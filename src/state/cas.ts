import crypto from 'node:crypto';
import { constants, promises as fs } from 'node:fs';
import type { Stats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';

import type { ArtifactRef } from '../kernel/types.js';

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
    await handle.close();
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
    await handle.close();
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

/** Verify a potentially large blob without materializing it in one Buffer. */
async function verifyOpened(ref: ArtifactRef, opened: OpenedArtifact): Promise<ArtifactStat> {
  const expected = opened.info;
  if (!Number.isSafeInteger(expected.size) || expected.size < 0) {
    throw new Error(`artifact ${ref} has an invalid byte length`);
  }
  const chunk = Buffer.allocUnsafe(Math.min(expected.size || 1, 1024 * 1024));
  const hash = crypto.createHash('sha256');
  let offset = 0;
  while (offset < expected.size) {
    const { bytesRead } = await opened.handle.read(chunk, 0,
      Math.min(chunk.byteLength, expected.size - offset), offset);
    if (bytesRead === 0) throw new Error(`artifact ${ref} has an inconsistent size`);
    hash.update(chunk.subarray(0, bytesRead));
    offset += bytesRead;
  }
  const after = await opened.handle.stat();
  assertPublishedFile(ref, after);
  if (!sameInode(expected, after) || expected.size !== after.size || offset !== after.size) {
    throw new Error(`artifact ${ref} changed while it was verified`);
  }
  if (hash.digest('hex') !== ref) throw new Error(`artifact ${ref} is corrupt`);
  return { ref, byteLength: offset };
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
    await opened.handle.close();
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
      await readAndVerifyOpened(ref, opened);
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
          await fs.unlink(residuePath);
        } catch (error) {
          if (!isErrno(error, 'ENOENT')) throw error;
        }
        await syncRoot(root, openedRoot);
      }

      const recovered = await opened.handle.stat();
      assertOwnedImmutableFile(`artifact ${ref}`, recovered);
      if (recovered.nlink === 1) return 'ready';
    } finally {
      await opened.handle.close();
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
      await opened.handle.close();
    }
  }

  async publish(source: Uint8Array): Promise<ArtifactRef> {
    const bytes = Buffer.from(source);
    const ref = digest(bytes);

    return this.withRoot(async (openedRoot) => {
      await recoverLinkedTemporary(this.root, openedRoot, ref);

      const name = temporaryName(ref);
      const temporaryPath = path.join(this.root, name);
      const finalPath = path.join(this.root, ref);
      let temporaryInfo: Stats | undefined;
      let linked = false;
      let publicationError: unknown;

      try {
        await assertRootPathStable(this.root, openedRoot);
        const handle = await fs.open(
          temporaryPath,
          constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
          0o600
        );
        try {
          await handle.writeFile(bytes);
          await handle.chmod(FILE_MODE);
          await handle.sync();
          temporaryInfo = await handle.stat();
          assertOwnedImmutableFile(`artifact temporary ${name}`, temporaryInfo);
          if (temporaryInfo.nlink !== 1) {
            throw new Error(`artifact temporary ${name} has invalid link count ${temporaryInfo.nlink}`);
          }
        } finally {
          await handle.close();
        }
        await syncRoot(this.root, openedRoot);

        try {
          await fs.link(temporaryPath, finalPath);
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
        throw new AggregateError([publicationError, cleanupError], 'artifact publication and cleanup both failed');
      }
      if (publicationError !== undefined) throw publicationError;
      if (cleanupError !== undefined) throw cleanupError;

      const published = await openPublishedFile(this.root, openedRoot, ref);
      try {
        const verified = await readAndVerifyOpened(ref, published, 1);
        if (verified.byteLength !== bytes.byteLength) {
          throw new Error(`artifact ${ref} has unexpected size after publication`);
        }
        await assertRootPathStable(this.root, openedRoot);
      } finally {
        await published.handle.close();
      }
      return ref;
    });
  }

  async read(ref: ArtifactRef): Promise<Buffer> {
    assertArtifactRef(ref);
    return this.withRoot(async (openedRoot) => {
      const opened = await openPublishedFile(this.root, openedRoot, ref);
      try {
        const bytes = await readAndVerifyOpened(ref, opened, 1);
        await assertRootPathStable(this.root, openedRoot);
        return bytes;
      } finally {
        await opened.handle.close();
      }
    });
  }

  async stat(ref: ArtifactRef): Promise<ArtifactStat> {
    assertArtifactRef(ref);
    return this.withRoot(async (openedRoot) => {
      const opened = await openPublishedFile(this.root, openedRoot, ref);
      try {
        await assertRootPathStable(this.root, openedRoot);
        return { ref, byteLength: opened.info.size };
      } finally {
        await opened.handle.close();
      }
    });
  }

  async verify(ref: ArtifactRef): Promise<ArtifactStat> {
    assertArtifactRef(ref);
    return this.withRoot(async (openedRoot) => {
      const opened = await openPublishedFile(this.root, openedRoot, ref);
      try {
        const verified = await verifyOpened(ref, opened);
        await assertRootPathStable(this.root, openedRoot);
        return verified;
      } finally {
        await opened.handle.close();
      }
    });
  }
}
