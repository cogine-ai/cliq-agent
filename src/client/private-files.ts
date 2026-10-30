import { randomBytes } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { link, lstat, mkdir, open, opendir, rename, rmdir, unlink, type FileHandle } from 'node:fs/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertRequestId, normalizeAbsolutePath } from '../kernel/identity.js';
import { ResourceRetirementError } from '../state/errors.js';

const FILE_BYTES = 1024 * 1024;
const DIRECTORY_ENTRIES = 4096;
export type PrivateClientDirectoryIdentity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;

/** Private client data only. These descriptors and copied identities confer no
 * installation, StateOwner, credential, permission or execution authority.
 * The root joins its whole family; a child can join and close its own branch. */
export type PrivateClientDirectory = Readonly<{
  identity: PrivateClientDirectoryIdentity;
  read(name: string, maxBytes: number): Promise<Buffer | undefined>;
  publish(name: string, bytes: Uint8Array): Promise<'created' | 'existing'>;
  replace(name: string, bytes: Uint8Array): Promise<void>;
  directory(name: string, create?: boolean): Promise<PrivateClientDirectory>;
  createDirectory(name: string): Promise<Readonly<{ directory: PrivateClientDirectory; created: boolean }>>;
  acknowledgeDirectory(name: string, identity: PrivateClientDirectoryIdentity,
    files: readonly Readonly<{ name: string; bytes: Uint8Array }>[]): Promise<void>;
  assertAcknowledgedDirectory(name: string): Promise<void>;
  names(): Promise<readonly string[]>;
  sync(): Promise<void>;
  assertCurrent(): Promise<void>;
  close(): Promise<void>;
}>;
type Directory = { handle: FileHandle; info: BigIntStats; parent?: Directory; name: string; private: boolean; closing?: Promise<void>; closed?: boolean };
const same = (a: BigIntStats, b: BigIntStats, file = false) =>
  ['dev', 'ino', 'uid', 'gid', 'mode', ...(file ? ['size', 'nlink', 'mtimeNs', 'ctimeNs'] : [])]
    .every(key => a[key as keyof BigIntStats] === b[key as keyof BigIntStats]);
const child = (parent: Directory, name: string) => `/proc/self/fd/${parent.handle.fd}/${name}`;
const missing = (error: unknown) => (error as NodeJS.ErrnoException)?.code === 'ENOENT';
const identity = (directory: Directory): PrivateClientDirectoryIdentity => Object.freeze({
  deviceId: String(directory.info.dev), fileId: String(directory.info.ino), ownerUid: Number(directory.info.uid) });
function acknowledgement(entry: string): RegExpExecArray {
  const value = /^\.ack-([0-9a-f-]{36})-([0-9a-f]{64})-([0-9a-f]{32})$/u.exec(entry);
  if (!value) throw new TypeError('private client acknowledgement name is invalid');
  assertRequestId(value[1]!); return value;
}
function name(value: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/u.test(value) || value === '.' || value === '..')
    throw new TypeError('private client data requires one bounded filename');
}
function limit(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > FILE_BYTES) throw new TypeError('private client file bound is invalid');
}

class PrivateFiles {
  readonly directories: Directory[] = [];
  readonly handles = new Set<FileHandle>();
  private tail: Promise<void> = Promise.resolve();
  private closing?: Promise<void>;
  private retirement?: ResourceRetirementError;
  constructor(readonly uid: bigint) {}
  own(handle: FileHandle) { this.handles.add(handle); return handle; }
  checkDirectory(info: BigIntStats, privateDirectory: boolean) {
    if (!info.isDirectory() || (privateDirectory ? info.uid !== this.uid || (info.mode & 0o7777n) !== 0o700n :
      (info.uid !== 0n && info.uid !== this.uid) || (info.mode & 0o022n) !== 0n && !(info.uid === 0n && (info.mode & 0o1000n) !== 0n)))
      throw new TypeError('private client directory has an invalid type, owner or mode');
  }
  checkFile(info: BigIntStats, maxBytes: number) {
    if (!info.isFile() || info.uid !== this.uid || info.nlink !== 1n || (info.mode & 0o7777n) !== 0o600n ||
        info.size < 0n || info.size > BigInt(maxBytes)) throw new TypeError('private client file has an invalid type, owner, links, mode or size');
  }
  async assertDirectories() {
    if (this.retirement) throw this.retirement;
    for (const directory of this.directories) {
      const held = await directory.handle.stat({ bigint: true });
      const named = await lstat(directory.parent ? child(directory.parent, directory.name) : '/', { bigint: true });
      this.checkDirectory(held, directory.private); this.checkDirectory(named, directory.private);
      if (!same(directory.info, held) || !same(held, named)) throw new TypeError('private client directory identity changed');
    }
  }
  run<T>(operation: () => Promise<T>, validate = true): Promise<T> {
    if (this.closing) return Promise.reject(new TypeError('private client directory is closed'));
    const pending = this.tail.then(async () => {
      if (validate) await this.assertDirectories();
      const result = await operation();
      if (validate) await this.assertDirectories();
      return result;
    });
    this.tail = pending.then(() => {}, () => {}); return pending;
  }
  at<T>(directory: Directory, operation: () => Promise<T>): Promise<T> {
    if (directory.closing || directory.closed) return Promise.reject(new TypeError('private client child directory is closed'));
    return this.run(async () => { if (directory.closed) throw new TypeError('private client child directory is closed'); return operation(); });
  }
  async retire(handle: FileHandle) {
    if (!this.handles.delete(handle)) return;
    try { await handle.close(); }
    catch (cause) { throw this.retirement ??= new ResourceRetirementError('private client descriptor did not close', cause); }
  }
  async directory(parent: Directory, entry: string, create: boolean): Promise<Directory> {
    const known = this.directories.find(value => value.parent === parent && value.name === entry);
    if (known) return known;
    const filename = child(parent, entry);
    if (create) try { await mkdir(filename, { mode: 0o700 }); await parent.handle.sync(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    const named = await lstat(filename, { bigint: true }); this.checkDirectory(named, true);
    const handle = this.own(await open(filename, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NONBLOCK));
    try {
      const info = await handle.stat({ bigint: true }); this.checkDirectory(info, true);
      if (!same(info, named)) throw new TypeError('private client directory changed while opening');
      const directory = { handle, info, parent, name: entry, private: true }; this.directories.push(directory); return directory;
    } catch (error) { await this.retire(handle); throw error; }
  }
  async read(directory: Directory, entry: string, maxBytes: number): Promise<Buffer | undefined> {
    const filename = child(directory, entry);
    let named: BigIntStats;
    try { named = await lstat(filename, { bigint: true }); } catch (error) { if (missing(error)) return undefined; throw error; }
    this.checkFile(named, maxBytes);
    const handle = this.own(await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK));
    try {
      const before = await handle.stat({ bigint: true }); this.checkFile(before, maxBytes);
      if (!same(named, before, true)) throw new TypeError('private client file changed while opening');
      const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
      while (offset < bytes.length) {
        const result = await handle.read(bytes, offset, bytes.length - offset, offset);
        if (!result.bytesRead) throw new TypeError('private client file ended before its declared size');
        offset += result.bytesRead;
      }
      if ((await handle.read(Buffer.alloc(1), 0, 1, offset)).bytesRead !== 0) throw new TypeError('private client file exceeds its declared size');
      const after = await handle.stat({ bigint: true }), current = await lstat(filename, { bigint: true });
      this.checkFile(after, maxBytes); this.checkFile(current, maxBytes);
      if (!same(before, after, true) || !same(after, current, true)) throw new TypeError('private client file changed while reading');
      return bytes;
    } finally { await this.retire(handle); }
  }
  async write(directory: Directory, entry: string, bytes: Buffer, replace: boolean): Promise<'created' | 'existing'> {
    const temporary = `.write-${randomBytes(16).toString('hex')}`, temporaryPath = child(directory, temporary);
    const handle = this.own(await open(temporaryPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600));
    let info: BigIntStats | undefined, named = true;
    try {
      try {
        info = await handle.stat({ bigint: true }); this.checkFile(info, FILE_BYTES);
        await handle.writeFile(bytes); await handle.sync();
        info = await handle.stat({ bigint: true }); this.checkFile(info, FILE_BYTES);
        if (info.size !== BigInt(bytes.length)) throw new TypeError('private client write has an incomplete size');
      } finally { await this.retire(handle); }
      if (!(await this.read(directory, temporary, FILE_BYTES))?.equals(bytes)) throw new TypeError('private client write differs from its complete original bytes');
      await this.assertDirectories();
      if (replace) {
        await this.read(directory, entry, FILE_BYTES); // Validate the original named object, if present.
        await rename(temporaryPath, child(directory, entry)); named = false;
      } else {
        try { await link(temporaryPath, child(directory, entry)); }
        catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
          if (await this.read(directory, entry, FILE_BYTES) === undefined) throw new TypeError('private client publication target disappeared');
          return 'existing';
        } throw error; }
        // The temporary alias is private and is joined before a single-link
        // final object can be returned or accepted by another reader.
        await unlink(temporaryPath); named = false;
      }
      await directory.handle.sync();
      const current = await lstat(child(directory, entry), { bigint: true }); this.checkFile(current, FILE_BYTES);
      if (!info || current.dev !== info.dev || current.ino !== info.ino || !(await this.read(directory, entry, FILE_BYTES))?.equals(bytes))
        throw new TypeError('private client publication changed its original bytes or identity');
      return 'created';
    } finally {
      if (named && !this.retirement) {
        const current = await lstat(temporaryPath, { bigint: true }); this.checkFile(current, FILE_BYTES);
        if (info && (current.dev !== info.dev || current.ino !== info.ino)) throw new TypeError('private client temporary identity changed');
        await unlink(temporaryPath); await directory.handle.sync();
      }
      if (this.retirement) throw this.retirement;
    }
  }
  async retireBranch(directory: Directory): Promise<void> {
    const branch = this.directories.filter(value => {
      for (let current: Directory | undefined = value; current; current = current.parent) if (current === directory) return true;
      return false;
    });
    for (const value of branch) { value.closed = true; this.directories.splice(this.directories.indexOf(value), 1); }
    const results = await Promise.allSettled(branch.reverse().map(value => this.retire(value.handle)));
    if (this.retirement) throw this.retirement;
    const failure = results.find(result => result.status === 'rejected'); if (failure?.status === 'rejected') throw failure.reason;
  }
  closeDirectory(directory: Directory): Promise<void> {
    if (this.closing) return this.closing;
    return directory.closing ??= this.run(() => this.retireBranch(directory), false);
  }
  async names(directory: Directory): Promise<readonly string[]> {
    const entries: string[] = [], stream = await opendir(`/proc/self/fd/${directory.handle.fd}`);
    try { for (;;) { const entry = await stream.read(); if (!entry) break;
      if (entries.length === DIRECTORY_ENTRIES) throw new TypeError('private client directory listing exceeds its bound'); entries.push(entry.name); } }
    finally { try { await stream.close(); } catch (cause) { throw this.retirement ??= new ResourceRetirementError('private client directory stream did not close', cause); } }
    return Object.freeze(entries.sort());
  }
  view(directory: Directory, root = false): PrivateClientDirectory {
    return Object.freeze({ identity: identity(directory),
      read: (entry: string, maxBytes: number) => { name(entry); limit(maxBytes); return this.at(directory, () => this.read(directory, entry, maxBytes)); },
      publish: (entry: string, supplied: Uint8Array) => {
        name(entry); if (!(supplied instanceof Uint8Array) || supplied.byteLength > FILE_BYTES) throw new TypeError('private client write exceeds its bound');
        const bytes = Buffer.from(supplied); return this.at(directory, () => this.write(directory, entry, bytes, false));
      },
      replace: (entry: string, supplied: Uint8Array) => {
        name(entry); if (!(supplied instanceof Uint8Array) || supplied.byteLength > FILE_BYTES) throw new TypeError('private client write exceeds its bound');
        const bytes = Buffer.from(supplied); return this.at(directory, async () => { await this.write(directory, entry, bytes, true); });
      },
      directory: (entry: string, create = false) => { name(entry); return this.at(directory, async () => this.view(await this.directory(directory, entry, create))); },
      createDirectory: (entry: string) => { name(entry); return this.at(directory, async () => {
        let created = false;
        try { await mkdir(child(directory, entry), { mode: 0o700 }); created = true; await directory.handle.sync(); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
        return Object.freeze({ directory: this.view(await this.directory(directory, entry, false)), created });
      }); },
      acknowledgeDirectory: (entry: string, expected: PrivateClientDirectoryIdentity,
        supplied: readonly Readonly<{ name: string; bytes: Uint8Array }>[]) => {
        assertRequestId(entry);
        const files = supplied.map(file => ({ name: file.name, bytes: Buffer.from(file.bytes) }));
        if (files.length !== 3 || !['metadata.json', 'request.json', 'response.json'].every(value => files.some(file => file.name === value)) ||
            files.some(file => file.bytes.length > FILE_BYTES)) throw new TypeError('acknowledgement requires the three complete known request files');
        const expectedDigest = canonicalSha256(expected);
        return this.at(directory, async () => {
          const group = await this.directory(directory, entry, false);
          try {
            const check = async () => {
              if (canonicalSha256(identity(group)) !== expectedDigest ||
                  (await this.names(group)).join('\0') !== files.map(file => file.name).sort().join('\0'))
                throw new TypeError('acknowledgement group changed its original physical identity or files');
              for (const file of files) if (!(await this.read(group, file.name, FILE_BYTES))?.equals(file.bytes))
                throw new TypeError('acknowledgement changed its complete known original bytes');
            };
            await check(); await this.assertDirectories();
            const retired = `.ack-${entry}-${expectedDigest}-${randomBytes(16).toString('hex')}`;
            await rename(child(directory, entry), child(directory, retired)); group.name = retired;
            await this.assertDirectories(); await directory.handle.sync(); await check();
            for (const file of files) await unlink(child(group, file.name));
            await group.handle.sync(); await this.retireBranch(group);
            const named = await lstat(child(directory, retired), { bigint: true }); this.checkDirectory(named, true);
            if (!same(group.info, named)) throw new TypeError('acknowledgement cleanup changed its original directory');
            await rmdir(child(directory, retired)); await directory.handle.sync();
          } finally { if (!group.closed) await this.retireBranch(group); }
        });
      },
      assertAcknowledgedDirectory: (entry: string) => {
        const parsed = acknowledgement(entry);
        return this.at(directory, async () => {
          const group = await this.directory(directory, entry, false);
          try { if (canonicalSha256(identity(group)) !== parsed[2]) throw new TypeError('acknowledgement residue substitutes another original directory'); }
          finally { await this.retireBranch(group); }
        });
      },
      names: () => this.at(directory, () => this.names(directory)),
      sync: () => this.at(directory, () => directory.handle.sync()),
      assertCurrent: () => this.at(directory, async () => {}), close: () => root ? this.close() : this.closeDirectory(directory) });
  }
  close(): Promise<void> {
    return this.closing ??= (async () => {
      await this.tail;
      const results = await Promise.allSettled([...this.handles].reverse().map(handle => this.retire(handle)));
      if (this.retirement) throw this.retirement;
      const failure = results.find(result => result.status === 'rejected'); if (failure?.status === 'rejected') throw failure.reason;
    })();
  }
}

/** Internal data path, chosen by the installed host from the actual account.
 * There is intentionally no environment override or non-Linux path fallback. */
export async function openPrivateClientDirectory(filename: string, options: Readonly<{ create?: boolean }> = {}): Promise<PrivateClientDirectory> {
  if (process.platform !== 'linux' || typeof process.geteuid !== 'function') throw new TypeError('private installed client data requires Linux descriptor-relative files');
  if (normalizeAbsolutePath(filename) !== filename || filename === '/') throw new TypeError('private client directory requires its canonical absolute path');
  const scope = new PrivateFiles(BigInt(process.geteuid()));
  try {
    const handle = scope.own(await open('/', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
    let directory: Directory = { handle, info: await handle.stat({ bigint: true }), name: '/', private: false };
    scope.checkDirectory(directory.info, false); scope.directories.push(directory);
    const parts = filename.split('/').slice(1);
    for (const [index, part] of parts.entries()) {
      if (!part || part === '.' || part === '..' || part.includes('\0') || Buffer.byteLength(part) > 255)
        throw new TypeError('private client ancestor is invalid');
      await scope.assertDirectories(); const location = child(directory, part), last = index === parts.length - 1;
      let named: BigIntStats;
      try { named = await lstat(location, { bigint: true }); }
      catch (error) {
        if (!options.create || !missing(error) || directory.info.uid !== scope.uid) throw error;
        try { await mkdir(location, { mode: 0o700 }); await directory.handle.sync(); }
        catch (cause) { if ((cause as NodeJS.ErrnoException).code !== 'EEXIST') throw cause; }
        named = await lstat(location, { bigint: true });
      }
      scope.checkDirectory(named, last);
      const held = scope.own(await open(location, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NONBLOCK));
      const info = await held.stat({ bigint: true }); scope.checkDirectory(info, last);
      if (!same(named, info)) throw new TypeError('private client ancestor changed while opening');
      directory = { handle: held, info, parent: directory, name: part, private: last }; scope.directories.push(directory);
    }
    await scope.assertDirectories(); return scope.view(directory, true);
  } catch (error) { await scope.close(); throw error; }
}
