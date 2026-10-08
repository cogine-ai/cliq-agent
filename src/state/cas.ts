import crypto from 'node:crypto';
import { constants, promises as fs } from 'node:fs';
import type { Stats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';

import type { ArtifactRef } from '../kernel/types.js';
import { ResourceRetirementError } from './errors.js';

export type { ArtifactRef } from '../kernel/types.js';

export type ArtifactStat = {
  ref: ArtifactRef;
  byteLength: number;
};

type RootHandle = {
  handle: FileHandle;
  info: Stats;
};

type OpenedArtifact = {
  handle: FileHandle;
  info: Stats;
};

const FILE_MODE = 0o400;
const ROOT_MODE = 0o700;
const PERMISSION_AND_SPECIAL_BITS = 0o7777;
const TEMPORARY_SUFFIX_LENGTH = 32;
export const ARTIFACT_CHUNK_BYTES = 64 * 1024;

function digest(bytes: Uint8Array): ArtifactRef {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function assertArtifactRef(ref: string): asserts ref is ArtifactRef {
  if (!/^[0-9a-f]{64}$/.test(ref)) throw new Error(`invalid artifact ref: ${JSON.stringify(ref)}`);
}

function effectiveUid(): number {
  if (typeof process.geteuid !== 'function') {
    throw new Error('CAS requires an operating system with effective-user identity support');
  }
  return process.geteuid();
}

function visibleMode(info: Stats): number {
  return info.mode & PERMISSION_AND_SPECIAL_BITS;
}

function sameInode(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertRootMetadata(info: Stats): void {
  if (info.isSymbolicLink()) throw new Error('CAS root is a symlink');
  if (!info.isDirectory()) throw new Error('CAS root is not a directory');
  if (info.uid !== effectiveUid()) {
    throw new Error(`CAS root is owned by uid ${info.uid}; expected effective uid ${effectiveUid()}`);
  }
  const mode = visibleMode(info);
  if (mode !== ROOT_MODE) {
    throw new Error(`CAS root has invalid mode ${mode.toString(8)}; expected 700`);
  }
}

function assertOwnedImmutableFile(label: string, info: Stats): void {
  if (!info.isFile()) throw new Error(`${label} is not a regular file`);
  if (info.uid !== effectiveUid()) {
    throw new Error(`${label} is owned by uid ${info.uid}; expected effective uid ${effectiveUid()}`);
  }
  const mode = visibleMode(info);
  if (mode !== FILE_MODE) {
    throw new Error(`${label} has invalid mode ${mode.toString(8)}; expected 400`);
  }
}

function assertPublishedFile(ref: ArtifactRef, info: Stats): void {
  const label = `artifact ${ref}`;
  assertOwnedImmutableFile(label, info);
  if (info.nlink !== 1) throw new Error(`${label} has invalid link count ${info.nlink}`);
}

function temporaryName(ref: ArtifactRef): string {
  return `.tmp-${ref}-${crypto.randomBytes(TEMPORARY_SUFFIX_LENGTH / 2).toString('hex')}`;
}

function isRecoveryTemporaryName(name: string, ref: ArtifactRef): boolean {
  return new RegExp(`^\\.tmp-${ref}-[0-9a-f]{${TEMPORARY_SUFFIX_LENGTH}}$`).test(name);
}

function isErrno(error: unknown, code: string): boolean {
  return (error as NodeJS.ErrnoException).code === code;
}

async function closeCasHandle(handle: FileHandle): Promise<void> {
  try { await handle.close(); }
  catch (cause) { throw new ResourceRetirementError('CAS file descriptor retirement failed', cause); }
}

async function lstatRoot(root: string): Promise<Stats> {
  try {
    return await fs.lstat(root);
  } catch (error) {
    if (isErrno(error, 'ENOENT')) throw new Error(`CAS root does not exist: ${root}`, { cause: error });
    throw error;
  }
}

async function openRoot(root: string): Promise<RootHandle> {
  const pathInfo = await lstatRoot(root);
  assertRootMetadata(pathInfo);

  let handle: FileHandle;
  try {
    handle = await fs.open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  } catch (error) {
    if (isErrno(error, 'ELOOP')) throw new Error('CAS root is a symlink', { cause: error });
    throw error;
  }

  try {
    const handleInfo = await handle.stat();
    assertRootMetadata(handleInfo);
    if (!sameInode(pathInfo, handleInfo)) throw new Error('CAS root changed while it was opened');
    return { handle, info: handleInfo };
  } catch (error) {
    await closeCasHandle(handle);
    throw error;
  }
}

async function assertRootPathStable(root: string, opened: RootHandle): Promise<void> {
  const current = await lstatRoot(root);
  assertRootMetadata(current);
  if (!sameInode(current, opened.info)) throw new Error('CAS root changed during an operation');
}

async function syncRoot(root: string, opened: RootHandle): Promise<void> {
  await assertRootPathStable(root, opened);
  await opened.handle.sync();
  await assertRootPathStable(root, opened);
}

async function openOwnedImmutablePath(
  root: string,
  openedRoot: RootHandle,
  name: string,
  label: string
): Promise<OpenedArtifact> {
  await assertRootPathStable(root, openedRoot);
  const filePath = path.join(root, name);
  const pathInfo = await fs.lstat(filePath);
  if (pathInfo.isSymbolicLink()) throw new Error(`${label} is a symlink`);
  assertOwnedImmutableFile(label, pathInfo);

  let handle: FileHandle;
  try {
    handle = await fs.open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (isErrno(error, 'ELOOP')) throw new Error(`${label} is a symlink`, { cause: error });
    throw error;
  }
  try {
    const handleInfo = await handle.stat();
    assertOwnedImmutableFile(label, handleInfo);
    if (!sameInode(pathInfo, handleInfo)) throw new Error(`${label} changed while it was opened`);
    await assertRootPathStable(root, openedRoot);
    return { handle, info: handleInfo };
  } catch (error) {
    await closeCasHandle(handle);
    throw error;
  }
}

async function readAndVerifyOpened(
  ref: ArtifactRef,
  opened: OpenedArtifact,
  expectedLinkCount?: number
): Promise<Buffer> {
  if (expectedLinkCount !== undefined && opened.info.nlink !== expectedLinkCount) {
    throw new Error(`artifact ${ref} has invalid link count ${opened.info.nlink}`);
  }
  const bytes = await opened.handle.readFile();
  const after = await opened.handle.stat();
  assertOwnedImmutableFile(`artifact ${ref}`, after);
  if (!sameInode(opened.info, after) || opened.info.size !== after.size) {
    throw new Error(`artifact ${ref} changed while it was read`);
  }
  if (expectedLinkCount !== undefined && after.nlink !== expectedLinkCount) {
    throw new Error(`artifact ${ref} changed link count while it was read`);
  }
  if (bytes.byteLength !== after.size) throw new Error(`artifact ${ref} has an inconsistent size`);
  if (digest(bytes) !== ref) throw new Error(`artifact ${ref} is corrupt`);
  return bytes;
}

async function* verifiedChunks(ref: ArtifactRef, opened: OpenedArtifact, expectedByteLength: number,
  expectedLinkCount: number | null = 1): AsyncGenerator<Buffer> {
  assertOwnedImmutableFile(`artifact ${ref}`, opened.info);
  if (expectedLinkCount !== null && opened.info.nlink !== expectedLinkCount) throw new Error(`artifact ${ref} has an invalid link count`);
  if (opened.info.size !== expectedByteLength) throw new Error(`artifact ${ref} has an unexpected byte count`);
  const hash = crypto.createHash('sha256');
  let offset = 0;
  while (offset < expectedByteLength) {
    const chunk = Buffer.allocUnsafe(Math.min(ARTIFACT_CHUNK_BYTES, expectedByteLength - offset));
    const { bytesRead } = await opened.handle.read(chunk, 0, chunk.length, offset);
    if (bytesRead === 0) throw new Error(`artifact ${ref} ended before its declared byte count`);
    const bytes = chunk.subarray(0, bytesRead);
    hash.update(bytes);
    offset += bytesRead;
    yield bytes;
  }
  const after = await opened.handle.stat();
  assertOwnedImmutableFile(`artifact ${ref}`, after);
  if (expectedLinkCount !== null && after.nlink !== expectedLinkCount) throw new Error(`artifact ${ref} changed link count while it was streamed`);
  if (!sameInode(opened.info, after) || after.size !== expectedByteLength ||
      opened.info.mtimeMs !== after.mtimeMs || (expectedLinkCount !== null && opened.info.ctimeMs !== after.ctimeMs)) {
    throw new Error(`artifact ${ref} changed while it was streamed`);
  }
  if (hash.digest('hex') !== ref) throw new Error(`artifact ${ref} is corrupt`);
}

async function verifyOpened(ref: ArtifactRef, opened: OpenedArtifact): Promise<ArtifactStat> {
  for await (const _chunk of verifiedChunks(ref, opened, opened.info.size)) { /* Exhaustion verifies the whole digest. */ }
  return { ref, byteLength: opened.info.size };
}

async function openPublishedFile(
  root: string,
  openedRoot: RootHandle,
  ref: ArtifactRef
): Promise<OpenedArtifact> {
  const opened = await openOwnedImmutablePath(root, openedRoot, ref, `artifact ${ref}`);
  try {
    assertPublishedFile(ref, opened.info);
    return opened;
  } catch (error) {
    await closeCasHandle(opened.handle);
    throw error;
  }
}

async function matchingRootLinks(
  root: string,
  openedRoot: RootHandle,
  target: Stats
): Promise<Array<{ name: string; info: Stats }>> {
  await assertRootPathStable(root, openedRoot);
  const names = await fs.readdir(root);
  const links: Array<{ name: string; info: Stats }> = [];
  for (const name of names) {
    let info: Stats;
    try {
      info = await fs.lstat(path.join(root, name));
    } catch (error) {
      if (isErrno(error, 'ENOENT')) continue;
      throw error;
    }
    if (sameInode(info, target)) links.push({ name, info });
  }
  await assertRootPathStable(root, openedRoot);
  return links;
}

/**
 * Recover the one crash window created by link(temp, final) succeeding before
 * unlink(temp). This is path-based best-effort recovery: it deliberately fails
 * closed when every link cannot be accounted for inside the protected root. A
 * descriptor-relative native helper is still required to eliminate same-UID
 * path replacement races.
 */
async function recoverLinkedTemporary(
  root: string,
  openedRoot: RootHandle,
  ref: ArtifactRef
): Promise<'missing' | 'ready'> {
  const finalPath = path.join(root, ref);

  for (let attempt = 0; attempt < 8; attempt += 1) {
    let opened: OpenedArtifact;
    try {
      opened = await openOwnedImmutablePath(root, openedRoot, ref, `artifact ${ref}`);
    } catch (error) {
      if (isErrno(error, 'ENOENT')) return 'missing';
      throw error;
    }

    try {
      // Recovery may temporarily have multiple exact links; verify bytes without
      // demanding the final single-link state until residues have been removed.
      for await (const _chunk of verifiedChunks(ref, opened, opened.info.size, null)) { /* Rehash the held crash residue. */ }
      const before = await opened.handle.stat();
      if (before.nlink === 1) return 'ready';
      if (before.nlink < 1) throw new Error(`artifact ${ref} has invalid link count ${before.nlink}`);

      const links = await matchingRootLinks(root, openedRoot, before);
      const afterScan = await opened.handle.stat();
      if (!sameInode(before, afterScan)) throw new Error(`artifact ${ref} changed during recovery`);
      if (afterScan.nlink !== before.nlink) continue;
      if (links.length !== afterScan.nlink) {
        throw new Error(
          `cannot prove every link for artifact ${ref}: inode reports ${afterScan.nlink}, root contains ${links.length}`
        );
      }

      const final = links.find((entry) => entry.name === ref);
      if (final === undefined) throw new Error(`artifact ${ref} disappeared during recovery`);

      const residues = links.filter((entry) => entry.name !== ref);
      for (const residue of residues) {
        if (!isRecoveryTemporaryName(residue.name, ref)) {
          throw new Error(`unrecognized same-inode link ${JSON.stringify(residue.name)} for artifact ${ref}`);
        }
        assertOwnedImmutableFile(`artifact temporary ${residue.name}`, residue.info);
        if (residue.info.nlink !== afterScan.nlink) {
          throw new Error(`artifact temporary ${residue.name} changed link count during recovery`);
        }
      }

      for (const residue of residues) {
        const residuePath = path.join(root, residue.name);
        let current: Stats;
        try {
          current = await fs.lstat(residuePath);
        } catch (error) {
          if (isErrno(error, 'ENOENT')) break;
          throw error;
        }
        assertOwnedImmutableFile(`artifact temporary ${residue.name}`, current);
        if (!sameInode(current, afterScan)) {
          throw new Error(`artifact temporary ${residue.name} changed before cleanup`);
        }

        try {
          try { await fs.unlink(residuePath); }
          catch (error) { if (!isErrno(error, 'ENOENT')) throw error; }
          await syncRoot(root, openedRoot);
        } catch (cause) { throw new ResourceRetirementError('CAS crash temporary retirement failed', cause); }
      }

      const recovered = await opened.handle.stat();
      assertOwnedImmutableFile(`artifact ${ref}`, recovered);
      if (recovered.nlink === 1) return 'ready';
    } finally {
      await closeCasHandle(opened.handle);
    }
  }

  const finalInfo = await fs.lstat(finalPath);
  throw new Error(`artifact ${ref} did not reach a stable link count (currently ${finalInfo.nlink})`);
}

async function cleanupKnownTemporary(
  root: string,
  openedRoot: RootHandle,
  name: string,
  expected: Stats,
  allowAlreadyRemoved: boolean
): Promise<void> {
  const temporaryPath = path.join(root, name);
  let current: Stats;
  try {
    current = await fs.lstat(temporaryPath);
  } catch (error) {
    if (allowAlreadyRemoved && isErrno(error, 'ENOENT')) return;
    throw error;
  }
  assertOwnedImmutableFile(`artifact temporary ${name}`, current);
  if (!sameInode(current, expected)) throw new Error(`artifact temporary ${name} changed before cleanup`);
  try {
    await fs.unlink(temporaryPath);
  } catch (error) {
    // Another publisher may recover this linked temporary after our lstat.
    if (!allowAlreadyRemoved || !isErrno(error, 'ENOENT')) throw error;
  }
  await syncRoot(root, openedRoot);
}

export class ContentAddressedStore {
  private readonly root: string;

  constructor(root: string) {
    if (!path.isAbsolute(root) || path.resolve(root) !== root) {
      throw new Error(`CAS root must be a normalized absolute path: ${JSON.stringify(root)}`);
    }
    this.root = root;
  }

  private async withRoot<T>(operation: (opened: RootHandle) => Promise<T>): Promise<T> {
    const opened = await openRoot(this.root);
    try {
      return await operation(opened);
    } finally {
      await closeCasHandle(opened.handle);
    }
  }

  async publish(source: Uint8Array): Promise<ArtifactRef> {
    const bytes = Buffer.from(source);
    const result = await this.publishChunks((async function* () {
      for (let offset = 0; offset < bytes.length; offset += ARTIFACT_CHUNK_BYTES) {
        yield bytes.subarray(offset, offset + ARTIFACT_CHUNK_BYTES);
      }
    })(), bytes.length);
    return result.ref;
  }

  /** The producer supplies observed chunks, not a caller-selected final digest.
   * Only a fully consumed, bounded, fsynced stream can publish an immutable ref. */
  async publishChunks(source: AsyncIterable<Uint8Array>, maxByteLength: number): Promise<ArtifactStat> {
    if (!Number.isSafeInteger(maxByteLength) || maxByteLength < 0) throw new TypeError('artifact stream requires a nonnegative safe byte ceiling');

    return this.withRoot(async (openedRoot) => {
      let name = `.tmp-stream-${crypto.randomBytes(TEMPORARY_SUFFIX_LENGTH / 2).toString('hex')}`;
      let temporaryPath = path.join(this.root, name);
      let temporaryInfo: Stats | undefined;
      let linked = false;
      let publicationError: unknown;
      let ref!: ArtifactRef;
      let byteLength = 0;
      const hash = crypto.createHash('sha256');

      try {
        await assertRootPathStable(this.root, openedRoot);
        const handle = await fs.open(
          temporaryPath,
          constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
          0o600
        );
        try {
          for await (const chunk of source) {
            if (!(chunk instanceof Uint8Array) || chunk.byteLength > ARTIFACT_CHUNK_BYTES ||
                chunk.byteLength > maxByteLength - byteLength) {
              throw new Error('artifact stream exceeds its chunk or total byte ceiling');
            }
            const bytes = Buffer.from(chunk);
            hash.update(bytes);
            await handle.writeFile(bytes);
            byteLength += bytes.length;
            await assertRootPathStable(this.root, openedRoot);
          }
          ref = hash.digest('hex');
          await handle.chmod(FILE_MODE);
          await handle.sync();
          temporaryInfo = await handle.stat();
          assertOwnedImmutableFile(`artifact temporary ${name}`, temporaryInfo);
          if (temporaryInfo.nlink !== 1) {
            throw new Error(`artifact temporary ${name} has invalid link count ${temporaryInfo.nlink}`);
          }
          if (temporaryInfo.size !== byteLength) throw new Error('artifact temporary has an inconsistent streamed size');
        } finally {
          // Even an interrupted stream owns this one exact temporary. Give cleanup
          // its immutable metadata, never unlink a replaced path or unknown inode.
          try {
            if (temporaryInfo === undefined) {
              await handle.chmod(FILE_MODE);
              temporaryInfo = await handle.stat();
            }
          } catch (cause) {
            throw new ResourceRetirementError('CAS interrupted temporary retirement could not establish its exact metadata', cause);
          } finally { await closeCasHandle(handle); }
        }
        await syncRoot(this.root, openedRoot);

        await recoverLinkedTemporary(this.root, openedRoot, ref);
        const finalName = temporaryName(ref);
        await fs.rename(temporaryPath, path.join(this.root, finalName));
        name = finalName;
        temporaryPath = path.join(this.root, name);
        await syncRoot(this.root, openedRoot);

        try {
          await fs.link(temporaryPath, path.join(this.root, ref));
          linked = true;
          await syncRoot(this.root, openedRoot);
        } catch (error) {
          if (!isErrno(error, 'EEXIST')) throw error;
          await recoverLinkedTemporary(this.root, openedRoot, ref);
        }
      } catch (error) {
        publicationError = error;
      }

      let cleanupError: unknown;
      if (temporaryInfo !== undefined) {
        try {
          await cleanupKnownTemporary(this.root, openedRoot, name, temporaryInfo, linked);
        } catch (error) {
          cleanupError = error;
        }
      }

      if (publicationError !== undefined && cleanupError !== undefined) {
        throw new ResourceRetirementError('CAS publication and temporary retirement both failed',
          new AggregateError([publicationError, cleanupError], 'artifact publication and cleanup both failed'));
      }
      if (publicationError !== undefined) throw publicationError;
      if (cleanupError !== undefined) throw new ResourceRetirementError('CAS temporary retirement failed', cleanupError);

      const published = await openPublishedFile(this.root, openedRoot, ref);
      try {
        const verified = await verifyOpened(ref, published);
        if (verified.byteLength !== byteLength) {
          throw new Error(`artifact ${ref} has unexpected size after publication`);
        }
      } finally {
        await closeCasHandle(published.handle);
      }
      return { ref, byteLength };
    });
  }

  /** Chunks are staging bytes until the iterator is exhausted and its hash,
   * byte count and held-file metadata pass. Early return closes both handles. */
  async *readChunks(ref: ArtifactRef, expectedByteLength: number): AsyncGenerator<Buffer> {
    assertArtifactRef(ref);
    if (!Number.isSafeInteger(expectedByteLength) || expectedByteLength < 0) throw new TypeError('artifact stream requires an exact nonnegative safe byte count');
    const root = await openRoot(this.root);
    try {
      const opened = await openPublishedFile(this.root, root, ref);
      try {
        for await (const chunk of verifiedChunks(ref, opened, expectedByteLength)) {
          await assertRootPathStable(this.root, root);
          yield chunk;
        }
        await assertRootPathStable(this.root, root);
      } finally { await closeCasHandle(opened.handle); }
    } finally { await closeCasHandle(root.handle); }
  }

  async read(ref: ArtifactRef): Promise<Buffer> {
    assertArtifactRef(ref);
    return this.withRoot(async (openedRoot) => {
      const opened = await openPublishedFile(this.root, openedRoot, ref);
      try {
        return await readAndVerifyOpened(ref, opened, 1);
      } finally {
        await closeCasHandle(opened.handle);
      }
    });
  }

  async stat(ref: ArtifactRef): Promise<ArtifactStat> {
    assertArtifactRef(ref);
    return this.withRoot(async (openedRoot) => {
      const opened = await openPublishedFile(this.root, openedRoot, ref);
      try {
        return { ref, byteLength: opened.info.size };
      } finally {
        await closeCasHandle(opened.handle);
      }
    });
  }

  async verify(ref: ArtifactRef): Promise<ArtifactStat> {
    assertArtifactRef(ref);
    return this.withRoot(async root => {
      const opened = await openPublishedFile(this.root, root, ref);
      try { return await verifyOpened(ref, opened); }
      finally { await closeCasHandle(opened.handle); }
    });
  }
}
