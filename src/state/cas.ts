import crypto from 'node:crypto';
import { constants, promises as fs } from 'node:fs';
import type { Stats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { beginInstalledAssemblyWork, noteInstalledAssemblyRead, settleInstalledAssemblyWork,
  type InstalledAssemblyWorkSpan } from './installed-work-diagnostics.js';
import path from 'node:path';

import type { ArtifactRef } from '../kernel/types.js';
import { joinResourceOperations, ResourceRetirementError } from './errors.js';

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

type Publication = {
  source: AsyncIterable<Uint8Array>;
  maxByteLength: number;
  name: string;
  renameTarget?: string;
  temporaryInfo?: Stats;
  linked: boolean;
  ref: ArtifactRef;
  byteLength: number;
  writeFailure?: Error;
};

const FILE_MODE = 0o400;
const ROOT_MODE = 0o700;
const PERMISSION_AND_SPECIAL_BITS = 0o7777;
const TEMPORARY_SUFFIX_LENGTH = 32;
export const ARTIFACT_CHUNK_BYTES = 64 * 1024;
const joinedCasPublicationFailures = new WeakSet<Error>();

/** Internal I/O classification only, not authority to retry an effect or
 * replace a native owner. The exact publication's resource joins mint it. */
export function isJoinedCasPublicationFailure(error: unknown): error is Error {
  return error instanceof Error && joinedCasPublicationFailures.has(error);
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
  const work = beginInstalledAssemblyWork('rootSync');
  try { await opened.handle.sync(); }
  finally { if (work) settleInstalledAssemblyWork(work); }
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
  expectedLinkCount = 1,
  signal?: AbortSignal,
  work?: InstalledAssemblyWorkSpan
): Promise<Buffer> {
  signal?.throwIfAborted();
  const bytes = Buffer.allocUnsafe(opened.info.size); let offset = 0;
  for await (const chunk of verifiedChunks(ref, opened, opened.info.size, expectedLinkCount, signal, work)) {
    chunk.copy(bytes, offset); offset += chunk.length;
  }
  signal?.throwIfAborted();
  return bytes;
}

async function* verifiedChunks(ref: ArtifactRef, opened: OpenedArtifact, expectedByteLength: number,
  expectedLinkCount: number | null = 1, signal?: AbortSignal, work?: InstalledAssemblyWorkSpan): AsyncGenerator<Buffer> {
  signal?.throwIfAborted();
  assertOwnedImmutableFile(`artifact ${ref}`, opened.info);
  if (expectedLinkCount !== null && opened.info.nlink !== expectedLinkCount) throw new Error(`artifact ${ref} has an invalid link count`);
  if (opened.info.size !== expectedByteLength) throw new Error(`artifact ${ref} has an unexpected byte count`);
  const hash = crypto.createHash('sha256');
  let offset = 0;
  while (offset < expectedByteLength) {
    signal?.throwIfAborted();
    const chunk = Buffer.allocUnsafe(Math.min(ARTIFACT_CHUNK_BYTES, expectedByteLength - offset));
    const { bytesRead } = await opened.handle.read(chunk, 0, chunk.length, offset);
    if (work) noteInstalledAssemblyRead(work, bytesRead);
    signal?.throwIfAborted();
    if (bytesRead === 0) throw new Error(`artifact ${ref} ended before its declared byte count`);
    const bytes = chunk.subarray(0, bytesRead);
    hash.update(bytes);
    offset += bytesRead;
    yield bytes;
  }
  signal?.throwIfAborted();
  const after = await opened.handle.stat();
  signal?.throwIfAborted();
  assertOwnedImmutableFile(`artifact ${ref}`, after);
  if (expectedLinkCount !== null && after.nlink !== expectedLinkCount) throw new Error(`artifact ${ref} changed link count while it was streamed`);
  if (!sameInode(opened.info, after) || after.size !== expectedByteLength ||
      opened.info.mtimeMs !== after.mtimeMs || (expectedLinkCount !== null && opened.info.ctimeMs !== after.ctimeMs)) {
    throw new Error(`artifact ${ref} changed while it was streamed`);
  }
  if (hash.digest('hex') !== ref) throw new Error(`artifact ${ref} is corrupt`);
}

async function verifyOpened(ref: ArtifactRef, opened: OpenedArtifact, signal?: AbortSignal,
  work?: InstalledAssemblyWorkSpan): Promise<ArtifactStat> {
  signal?.throwIfAborted();
  for await (const _chunk of verifiedChunks(ref, opened, opened.info.size, 1, signal, work)) { /* Exhaustion verifies the whole digest. */ }
  signal?.throwIfAborted();
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
}

function byteChunks(bytes: Buffer): AsyncIterable<Uint8Array> {
  return (async function* () {
    for (let offset = 0; offset < bytes.length; offset += ARTIFACT_CHUNK_BYTES)
      yield bytes.subarray(offset, offset + ARTIFACT_CHUNK_BYTES);
  })();
}

/** All actual mutations join before the common held-directory barrier, even
 * when one mutation failed after taking effect. Recovery keeps its own syncs. */
async function durableStage(root: string, openedRoot: RootHandle, operations: Promise<unknown>[]): Promise<void> {
  let failure: { error: unknown } | undefined;
  try { await joinResourceOperations(operations); }
  catch (error) { failure = { error }; }
  try { await syncRoot(root, openedRoot); }
  catch (cause) {
    throw new ResourceRetirementError('CAS namespace durability failed', failure
      ? new AggregateError([failure.error, cause], 'CAS mutation and durability failed') : cause);
  }
  if (failure) throw failure.error;
}

async function writeTemporary(root: string, openedRoot: RootHandle, publication: Publication): Promise<void> {
  const { source, maxByteLength, name } = publication;
  const hash = crypto.createHash('sha256');
  await assertRootPathStable(root, openedRoot);
  const handle = await fs.open(path.join(root, name),
    constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
  let streamFailure: { error: unknown } | undefined;
  try {
    for await (const chunk of source) {
      if (!(chunk instanceof Uint8Array) || chunk.byteLength > ARTIFACT_CHUNK_BYTES ||
          chunk.byteLength > maxByteLength - publication.byteLength)
        throw new Error('artifact stream exceeds its chunk or total byte ceiling');
      const bytes = Buffer.from(chunk);
      hash.update(bytes);
      try { await handle.writeFile(bytes); }
      catch (error) {
        if (error instanceof Error) joinedCasPublicationFailures.delete(error);
        if (error instanceof Error && !(error instanceof ResourceRetirementError) &&
            Object.getOwnPropertyDescriptor(error, 'code')?.value === 'ENOSPC') publication.writeFailure = error;
        throw error;
      }
      publication.byteLength += bytes.length;
      await assertRootPathStable(root, openedRoot);
    }
    publication.ref = hash.digest('hex');
    await handle.chmod(FILE_MODE);
    const work = beginInstalledAssemblyWork('fileSync');
    try { await handle.sync(); }
    finally { if (work) settleInstalledAssemblyWork(work); }
    publication.temporaryInfo = await handle.stat();
    assertOwnedImmutableFile(`artifact temporary ${name}`, publication.temporaryInfo);
    if (publication.temporaryInfo.nlink !== 1)
      throw new Error(`artifact temporary ${name} has invalid link count ${publication.temporaryInfo.nlink}`);
    if (publication.temporaryInfo.size !== publication.byteLength)
      throw new Error('artifact temporary has an inconsistent streamed size');
  } catch (error) {
    if (error instanceof Error) joinedCasPublicationFailures.delete(error);
    streamFailure = { error };
    throw error;
  } finally {
    const retirementFailures: unknown[] = [];
    try {
      if (publication.temporaryInfo === undefined) {
        await handle.chmod(FILE_MODE);
        publication.temporaryInfo = await handle.stat();
      }
    } catch (cause) {
      retirementFailures.push(new ResourceRetirementError('CAS interrupted temporary retirement could not establish its exact metadata', cause));
    }
    try { await closeCasHandle(handle); }
    catch (error) { retirementFailures.push(error); }
    if (retirementFailures.length !== 0) {
      if (!streamFailure && retirementFailures.length === 1) throw retirementFailures[0];
      throw new ResourceRetirementError('CAS streaming and descriptor retirement failed',
        new AggregateError([...(streamFailure ? [streamFailure.error] : []), ...retirementFailures],
          'artifact stream and retirement failures'));
    }
  }
}

async function renameTemporary(root: string, openedRoot: RootHandle, publication: Publication): Promise<void> {
  await recoverLinkedTemporary(root, openedRoot, publication.ref);
  // Retain both exact names if rename takes effect but reports failure. Cleanup
  // may recognize only the original dev/ino, never a path or equal bytes.
  publication.renameTarget = temporaryName(publication.ref);
  await fs.rename(path.join(root, publication.name), path.join(root, publication.renameTarget));
  publication.name = publication.renameTarget;
  publication.renameTarget = undefined;
}

async function linkTemporary(root: string, openedRoot: RootHandle, publication: Publication): Promise<void> {
  try {
    await fs.link(path.join(root, publication.name), path.join(root, publication.ref));
    publication.linked = true;
  } catch (error) {
    // A syscall wrapper may report failure after the actual link. Only the
    // original inode at the final name permits another publisher's cleanup.
    try {
      const final = await fs.lstat(path.join(root, publication.ref));
      publication.linked = sameInode(final, publication.temporaryInfo!);
    } catch (cause) {
      if (!isErrno(cause, 'ENOENT')) throw new ResourceRetirementError('CAS link outcome inspection failed', cause);
    }
    if (!isErrno(error, 'EEXIST')) throw error;
    await recoverLinkedTemporary(root, openedRoot, publication.ref);
  }
}

async function retireTemporary(root: string, openedRoot: RootHandle, publication: Publication): Promise<void> {
  if (publication.temporaryInfo === undefined) return;
  let name = publication.name;
  if (publication.renameTarget !== undefined) {
    const found: string[] = [];
    for (const candidate of [publication.name, publication.renameTarget]) {
      let info: Stats;
      try { info = await fs.lstat(path.join(root, candidate)); }
      catch (error) { if (isErrno(error, 'ENOENT')) continue; throw error; }
      assertOwnedImmutableFile(`artifact temporary ${candidate}`, info);
      if (!sameInode(info, publication.temporaryInfo)) throw new Error('CAS rename temporary changed before cleanup');
      found.push(candidate);
    }
    if (found.length !== 1) throw new Error('CAS rename did not retain exactly one original temporary');
    name = found[0]!;
  }
  await cleanupKnownTemporary(root, openedRoot, name, publication.temporaryInfo, publication.linked);
}

export class ContentAddressedStore {
  private readonly root: string;

  constructor(root: string) {
    // Trusted composition may borrow an already-held Linux directory. Keep
    // the final dot: O_NOFOLLOW then opens the directory, not its procfd link.
    // I/O still checks the actual root metadata and acquires its own handle.
    const heldDirectoryLocator = /^\/proc\/self\/fd\/(?:0|[1-9][0-9]*)\/\.$/.test(root);
    if (!path.isAbsolute(root) || (path.resolve(root) !== root && !heldDirectoryLocator)) {
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
    const result = await this.publishChunks(byteChunks(bytes), bytes.length);
    return result.ref;
  }

  /** Fixed admission data pairs retain the same four durable stages. */
  async publishPair(sources: readonly [Uint8Array, Uint8Array]): Promise<readonly [ArtifactStat, ArtifactStat]> {
    if (!Array.isArray(sources) || sources.length !== 2 ||
        [0, 1].some(index => !(sources[index] instanceof Uint8Array)))
      throw new TypeError('CAS requires exactly two byte objects');
    const inputs = sources.map(source => {
      const bytes = Buffer.from(source);
      return { source: byteChunks(bytes), maxByteLength: bytes.length };
    });
    const results = await this.publishSources(inputs);
    return [results[0]!, results[1]!];
  }

  /** Fixed admission data triples never expose one member before full join. */
  async publishTriple(sources: readonly [Uint8Array, Uint8Array, Uint8Array]): Promise<readonly [ArtifactStat, ArtifactStat, ArtifactStat]> {
    if (!Array.isArray(sources) || sources.length !== 3 ||
        [0, 1, 2].some(index => !(sources[index] instanceof Uint8Array)))
      throw new TypeError('CAS requires exactly three byte objects');
    const inputs = sources.map(source => {
      const bytes = Buffer.from(source);
      return { source: byteChunks(bytes), maxByteLength: bytes.length };
    });
    const results = await this.publishSources(inputs);
    return [results[0]!, results[1]!, results[2]!];
  }

  /** Exactly four immutable objects share each of the original four directory
   * barriers, not their file syncs or full verification. This is not an atomic
   * namespace transaction: failure may leave valid, unreferenced final objects. */
  async publishFour(sources: readonly [Uint8Array, Uint8Array, Uint8Array, Uint8Array]):
    Promise<readonly [ArtifactStat, ArtifactStat, ArtifactStat, ArtifactStat]> {
    const work = beginInstalledAssemblyWork('publishFour');
    try {
      if (!Array.isArray(sources) || sources.length !== 4 ||
          [0, 1, 2, 3].some(index => !(sources[index] instanceof Uint8Array)))
        throw new TypeError('CAS requires exactly four byte objects');
      const inputs = sources.map(source => {
        const bytes = Buffer.from(source);
        return { source: byteChunks(bytes), maxByteLength: bytes.length };
      });
      const results = await this.publishSources(inputs);
      return [results[0]!, results[1]!, results[2]!, results[3]!];
    } finally { if (work) settleInstalledAssemblyWork(work); }
  }

  /** The producer supplies observed chunks, not a caller-selected final digest.
   * Only a fully consumed, bounded, fsynced stream can publish an immutable ref. */
  async publishChunks(source: AsyncIterable<Uint8Array>, maxByteLength: number): Promise<ArtifactStat> {
    if (!Number.isSafeInteger(maxByteLength) || maxByteLength < 0) throw new TypeError('artifact stream requires a nonnegative safe byte ceiling');
    return (await this.publishSources([{ source, maxByteLength }]))[0]!;
  }

  private async publishSources(inputs: readonly { source: AsyncIterable<Uint8Array>; maxByteLength: number }[]): Promise<ArtifactStat[]> {
    const publications: Publication[] = inputs.map(input => ({ ...input,
      name: `.tmp-stream-${crypto.randomBytes(TEMPORARY_SUFFIX_LENGTH / 2).toString('hex')}`,
      linked: false, ref: '', byteLength: 0 }));
    let joinedFailure: Error | undefined;
    return this.withRoot(async (openedRoot) => {
      let publicationError: unknown;
      try {
        await durableStage(this.root, openedRoot, publications.map(publication => writeTemporary(this.root, openedRoot, publication)));
        await durableStage(this.root, openedRoot, publications.map(publication => renameTemporary(this.root, openedRoot, publication)));
        await durableStage(this.root, openedRoot, publications.map(publication => linkTemporary(this.root, openedRoot, publication)));
      } catch (error) {
        if (error instanceof Error) joinedCasPublicationFailures.delete(error);
        publicationError = error;
      }
      let cleanupError: unknown;
      try { await durableStage(this.root, openedRoot, publications.map(publication => retireTemporary(this.root, openedRoot, publication))); }
      catch (error) { cleanupError = error; }
      if (publicationError !== undefined && cleanupError !== undefined) {
        throw new ResourceRetirementError('CAS publication and temporary retirement both failed',
          new AggregateError([publicationError, cleanupError], 'artifact publication and cleanup both failed'));
      }
      if (publicationError !== undefined) {
        // This provenance belongs to one exact direct-write publication. The
        // fixed-four authentication group never lends a sibling's error a
        // business retry classification, even when Error objects are reused.
        if (publications.length === 1 && publicationError === publications[0]!.writeFailure) {
          try { await assertRootPathStable(this.root, openedRoot); joinedFailure = publicationError as Error; }
          catch { /* A failed identity recheck cannot classify the original error as joined. */ }
        }
        throw publicationError;
      }
      if (cleanupError !== undefined) throw new ResourceRetirementError('CAS temporary retirement failed', cleanupError);
      return joinResourceOperations(publications.map(async ({ ref, byteLength }) => {
        const published = await openPublishedFile(this.root, openedRoot, ref);
        try {
          const verified = await verifyOpened(ref, published);
          if (verified.byteLength !== byteLength) throw new Error(`artifact ${ref} has unexpected size after publication`);
        } finally { await closeCasHandle(published.handle); }
        return { ref, byteLength };
      }));
    }).catch(error => {
      if (error instanceof Error) {
        // An error reused by a source/other failing publication cannot borrow
        // an earlier publication's successful cleanup classification.
        joinedCasPublicationFailures.delete(error);
        if (error === joinedFailure && !(error instanceof ResourceRetirementError))
          joinedCasPublicationFailures.add(error);
      }
      // withRoot has now joined its original root FD too. Preserve the exact
      // original Error object; failed close/cleanup must never mint this fact.
      throw error;
    });
  }

  /** Chunks are staging bytes until the iterator is exhausted and its hash,
   * byte count and held-file metadata pass. Early return closes both handles. */
  async *readChunks(ref: ArtifactRef, expectedByteLength: number, signal?: AbortSignal): AsyncGenerator<Buffer> {
    const work = beginInstalledAssemblyWork('casRead');
    try {
      assertArtifactRef(ref);
      if (!Number.isSafeInteger(expectedByteLength) || expectedByteLength < 0) throw new TypeError('artifact stream requires an exact nonnegative safe byte count');
      signal?.throwIfAborted();
      const root = await openRoot(this.root);
      try {
        signal?.throwIfAborted();
        const opened = await openPublishedFile(this.root, root, ref);
        try {
          for await (const chunk of verifiedChunks(ref, opened, expectedByteLength, 1, signal, work)) {
            await assertRootPathStable(this.root, root);
            signal?.throwIfAborted();
            yield chunk;
          }
          await assertRootPathStable(this.root, root);
          signal?.throwIfAborted();
        } finally { await closeCasHandle(opened.handle); }
      } finally { await closeCasHandle(root.handle); }
      signal?.throwIfAborted();
    } finally { if (work) settleInstalledAssemblyWork(work); }
  }

  async read(ref: ArtifactRef, signal?: AbortSignal): Promise<Buffer> {
    const work = beginInstalledAssemblyWork('casRead');
    try {
      assertArtifactRef(ref);
      signal?.throwIfAborted();
      const bytes = await this.withRoot(async (openedRoot) => {
        signal?.throwIfAborted();
        const opened = await openPublishedFile(this.root, openedRoot, ref);
        try {
          const bytes = await readAndVerifyOpened(ref, opened, 1, signal, work);
          await assertRootPathStable(this.root, openedRoot); signal?.throwIfAborted();
          return bytes;
        } finally {
          await closeCasHandle(opened.handle);
        }
      });
      signal?.throwIfAborted(); return bytes;
    } finally { if (work) settleInstalledAssemblyWork(work); }
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

  async verify(ref: ArtifactRef, signal?: AbortSignal): Promise<ArtifactStat> {
    const work = beginInstalledAssemblyWork('casRead');
    try {
      assertArtifactRef(ref);
      signal?.throwIfAborted();
      const result = await this.withRoot(async root => {
        signal?.throwIfAborted();
        const opened = await openPublishedFile(this.root, root, ref);
        try {
          const result = await verifyOpened(ref, opened, signal, work);
          await assertRootPathStable(this.root, root); signal?.throwIfAborted();
          return result;
        } finally { await closeCasHandle(opened.handle); }
      });
      signal?.throwIfAborted(); return result;
    } finally { if (work) settleInstalledAssemblyWork(work); }
  }
}
