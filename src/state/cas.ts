import crypto from 'node:crypto';
import { constants, promises as fs } from 'node:fs';
import type { Stats } from 'node:fs';
import path from 'node:path';

import type { ArtifactRef } from '../kernel/types.js';

export type { ArtifactRef } from '../kernel/types.js';

export type ArtifactStat = {
  ref: ArtifactRef;
  byteLength: number;
};

function digest(bytes: Uint8Array): ArtifactRef {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function assertArtifactRef(ref: string): asserts ref is ArtifactRef {
  if (!/^[0-9a-f]{64}$/.test(ref)) throw new Error(`invalid artifact ref: ${JSON.stringify(ref)}`);
}

async function fsyncDirectory(directory: string): Promise<void> {
  const handle = await fs.open(directory, constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function assertPublishedFile(ref: ArtifactRef, info: Stats): void {
  if (!info.isFile()) throw new Error(`artifact ${ref} is not a regular file`);
  if (info.nlink !== 1) throw new Error(`artifact ${ref} has invalid link count ${info.nlink}`);
  const mode = info.mode & 0o777;
  if (mode !== 0o400) throw new Error(`artifact ${ref} has invalid mode ${mode.toString(8)}; expected 400`);
}

async function openPublishedFile(root: string, ref: ArtifactRef) {
  const artifactPath = path.join(root, ref);
  const pathInfo = await fs.lstat(artifactPath);
  if (pathInfo.isSymbolicLink()) throw new Error(`artifact ${ref} is a symlink`);
  if (!pathInfo.isFile()) throw new Error(`artifact ${ref} is not a regular file`);

  let handle: Awaited<ReturnType<typeof fs.open>>;
  try {
    handle = await fs.open(artifactPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ELOOP') throw new Error(`artifact ${ref} is a symlink`);
    throw error;
  }
  try {
    const handleInfo = await handle.stat();
    assertPublishedFile(ref, handleInfo);
    if (pathInfo.dev !== handleInfo.dev || pathInfo.ino !== handleInfo.ino) {
      throw new Error(`artifact ${ref} changed while it was opened`);
    }
    return { handle, info: handleInfo };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

export class ContentAddressedStore {
  constructor(private readonly root: string) {}

  async publish(source: Uint8Array): Promise<ArtifactRef> {
    const bytes = Buffer.from(source);
    const ref = digest(bytes);
    await fs.mkdir(this.root, { recursive: true, mode: 0o700 });

    const temporaryPath = path.join(this.root, `.tmp-${crypto.randomBytes(16).toString('hex')}`);
    const finalPath = path.join(this.root, ref);
    let temporaryCreated = false;
    let publicationError: unknown;
    try {
      const handle = await fs.open(
        temporaryPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
        0o600
      );
      temporaryCreated = true;
      try {
        await handle.writeFile(bytes);
        await handle.chmod(0o400);
        await handle.sync();
      } finally {
        await handle.close();
      }

      try {
        await fs.link(temporaryPath, finalPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
    } catch (error) {
      publicationError = error;
    }

    let cleanupError: unknown;
    if (temporaryCreated) {
      try {
        await fs.unlink(temporaryPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') cleanupError = error;
      }
    }
    try {
      await fsyncDirectory(this.root);
    } catch (error) {
      cleanupError = cleanupError ?? error;
    }

    if (publicationError !== undefined && cleanupError !== undefined) {
      throw new AggregateError([publicationError, cleanupError], 'artifact publication and cleanup both failed');
    }
    if (publicationError !== undefined) throw publicationError;
    if (cleanupError !== undefined) throw cleanupError;

    const published = await this.verify(ref);
    if (published.byteLength !== bytes.byteLength) {
      throw new Error(`artifact ${ref} has unexpected size after publication`);
    }
    return ref;
  }

  async read(ref: ArtifactRef): Promise<Buffer> {
    assertArtifactRef(ref);
    const { handle, info } = await openPublishedFile(this.root, ref);
    let bytes: Buffer;
    try {
      bytes = await handle.readFile();
      const after = await handle.stat();
      assertPublishedFile(ref, after);
      if (info.dev !== after.dev || info.ino !== after.ino || info.size !== after.size) {
        throw new Error(`artifact ${ref} changed while it was read`);
      }
      if (bytes.byteLength !== after.size) throw new Error(`artifact ${ref} has an inconsistent size`);
    } finally {
      await handle.close();
    }
    if (digest(bytes) !== ref) throw new Error(`artifact ${ref} is corrupt`);
    return bytes;
  }

  async stat(ref: ArtifactRef): Promise<ArtifactStat> {
    assertArtifactRef(ref);
    const { handle, info } = await openPublishedFile(this.root, ref);
    try {
      return { ref, byteLength: info.size };
    } finally {
      await handle.close();
    }
  }

  async verify(ref: ArtifactRef): Promise<ArtifactStat> {
    assertArtifactRef(ref);
    const bytes = await this.read(ref);
    return { ref, byteLength: bytes.byteLength };
  }
}
