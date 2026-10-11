// SEA-only mechanism experiment. Its VFS always refuses file opens; no storage authority.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readSync,
  writeSync, type BigIntStats } from 'node:fs';
import path from 'node:path';
import { getAsset, isSea } from 'node:sea';
import { DatabaseSync } from 'node:sqlite';

const protocol = 'cliq-sqlite-vfs-mechanism-v1';
const vfs = 'cliq-sqlite-vfs-mechanism-v1';
const modes = ['unregistered', 'scoped', 'permanent', 'dual', 'tampered'] as const;
type Mode = typeof modes[number];
type Snapshot = { initialized: boolean; mainOpens: number; totalOpens: number;
  privateRegistered: boolean; defaultUnchanged: boolean; sourceId: string | null };
function identity(info: BigIntStats) {
  return { dev: String(info.dev), ino: String(info.ino), size: String(info.size), uid: String(info.uid),
    gid: String(info.gid), mode: String(info.mode), nlink: String(info.nlink),
    mtimeNs: String(info.mtimeNs), ctimeNs: String(info.ctimeNs) };
}
function output(phase: string, facts: Record<string, unknown> = {}) {
  writeSync(1, JSON.stringify({ protocol, diagnosticOnly: true, phase, ...facts }) + '\n');
}
function barrier(phase: string, facts: Record<string, unknown>) {
  output(phase, facts);
  let token = '';
  const byte = Buffer.alloc(1);
  while (!token.endsWith('\n') && token.length < 16) {
    assert.equal(readSync(0, byte, 0, 1, null), 1); token += byte.toString('ascii');
  }
  assert.equal(token, 'continue\n');
}
function refuse(uri: string, expected: 'unregistered' | 'callback') {
  let unexpected: DatabaseSync | undefined;
  let error: unknown;
  try { unexpected = new DatabaseSync(uri, { allowExtension: false }); }
  catch (caught) { error = caught; }
  finally { unexpected?.close(); }
  assert(error instanceof Error, 'diagnostic VFS must not open a database');
  const actual = error as Error & { code: string; errcode: number };
  assert.equal(actual.code, 'ERR_SQLITE_ERROR');
  assert.equal(actual.errcode, expected === 'unregistered' ? 1 : 14);
  assert.match(actual.message, expected === 'unregistered' ? /no such vfs/ : /unable to open database/);
  return { code: actual.code, errcode: actual.errcode, message: actual.message };
}
function ordinary() {
  const db = new DatabaseSync(':memory:', { allowExtension: false });
  try {
    const facts = db.prepare('SELECT 17 AS value, sqlite_source_id() AS sourceId').get()!;
    assert.equal(facts.value, 17);
    assert.throws(() => db.enableLoadExtension(true), /disabled at database creation/);
    assert.throws(() => db.exec("SELECT load_extension('forbidden')"), /not authorized/);
    return facts;
  } finally { db.close(); }
}

let held: number | undefined;
let bootstrap: DatabaseSync | undefined;
try {
  assert(isSea()); assert.equal(process.platform, 'linux'); assert.equal(process.version, 'v24.21.0');
  assert(process.geteuid!() > 0); assert.equal(process.getuid!(), process.geteuid!());
  assert.equal(process.getgid!(), process.getegid!()); assert.deepEqual(process.getgroups!(), [process.getegid!()]);
  assert.equal(process.argv.length, 3);
  const mode = process.argv[2] as Mode; assert(modes.includes(mode));
  const startTicks = readFileSync('/proc/self/stat', 'utf8').split(') ').slice(1).join(') ').trim().split(/\s+/u)[19];
  assert.match(startTicks!, /^[1-9][0-9]*$/u);
  const lifetime = { pid: process.pid, startTicks, uid: process.getuid!(), euid: process.geteuid!(),
    gid: process.getgid!(), egid: process.getegid!(), groups: process.getgroups!(), nodeVersion: process.version, mode };
  const caseDirectory = path.join(process.env.HOME!, 'probe/sqlite-path-cases', `vfs-${mode}`);
  assert.match(caseDirectory, /^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+\/home\/probe\/sqlite-path-cases\/vfs-/u);
  const directory = lstatSync(caseDirectory, { bigint: true });
  assert(directory.isDirectory() && !directory.isSymbolicLink()); assert.equal(directory.uid, BigInt(process.geteuid!()));
  assert.equal(directory.gid, BigInt(process.getegid!())); assert.equal(directory.mode & 0o7777n, 0o700n);
  const uri = `file:${caseDirectory}/never-created.sqlite?vfs=${vfs}`;
  const before = refuse(uri, 'unregistered');
  const ordinaryBefore = ordinary();
  if (mode === 'unregistered') {
    barrier('unregistered', { ...lifetime, before, ordinaryBefore });
  } else {
    const claim = JSON.parse(Buffer.from(getAsset('cliq-vfs-mechanism-claim')).toString('utf8')) as {
      leaf: string; byteCount: number; sha256: string };
    assert.equal(claim.leaf, 'sqlite-vfs-mechanism.node');
    const leaf = mode === 'tampered' ? 'sqlite-vfs-mechanism-corrupt.node' : claim.leaf;
    const filename = path.join(path.dirname(process.execPath), leaf);
    held = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = fstatSync(held, { bigint: true });
    assert(info.isFile()); assert.equal(info.uid, 0n); assert.equal(info.gid, 0n);
    assert.equal(info.nlink, 1n); assert.equal(info.mode & 0o7777n, 0o555n);
    assert.equal(info.size, BigInt(claim.byteCount));
    const observedDigest = createHash('sha256').update(readFileSync(held)).digest('hex');
    assert.deepEqual(identity(fstatSync(held, { bigint: true })), identity(info));
    assert.deepEqual(identity(lstatSync(filename, { bigint: true })), identity(info));
    if (mode === 'tampered') {
      assert.notEqual(observedDigest, claim.sha256);
      barrier('signature_bound_digest_refused', { ...lifetime, helperFd: held, helperIdentity: identity(info), observedDigest });
      const consumed = held; held = undefined; closeSync(consumed);
    } else {
      assert.equal(observedDigest, claim.sha256, 'helper differs from the signed SEA claim');
      let native: { observe(): Snapshot } | undefined;
      const fdPath = `/proc/self/fd/${held}`;
      let beforeNative: Snapshot | undefined;
      if (mode === 'dual') {
        const module = { exports: {} };
        process.dlopen(module, fdPath);
        native = module.exports as typeof native;
        beforeNative = native!.observe(); assert.equal(beforeNative.initialized, false);
        assert.equal(beforeNative.sourceId, null); assert.equal(beforeNative.totalOpens, 0);
      }
      bootstrap = new DatabaseSync(':memory:', { allowExtension: true });
      const entry = mode === 'scoped' ? 'sqlite3_cliqvfsscopemechanism_init' : 'sqlite3_cliqvfsmechanism_init';
      bootstrap.loadExtension(fdPath, entry);
      bootstrap.enableLoadExtension(false);
      assert.throws(() => bootstrap!.loadExtension(fdPath, entry), /extension loading is not allowed/);
      const loadedNative = native?.observe();
      if (loadedNative) {
        assert.equal(loadedNative.initialized, true); assert.equal(loadedNative.privateRegistered, true);
        assert.equal(loadedNative.defaultUnchanged, true); assert.equal(loadedNative.totalOpens, 0);
        assert.equal(loadedNative.sourceId, ordinaryBefore.sourceId);
      }
      barrier('loaded', { ...lifetime, helperFd: held, helperIdentity: identity(info), observedDigest, beforeNative, loadedNative, before });
      const consumedBootstrap = bootstrap; bootstrap = undefined; consumedBootstrap.close();
      const consumed = held; held = undefined; closeSync(consumed);
      barrier('bootstrap_and_image_fd_closed', { ...lifetime, helperFd: consumed, napiLoaded: mode === 'dual' });
      const routed = [refuse(uri, mode === 'scoped' ? 'unregistered' : 'callback'),
        refuse(uri, mode === 'scoped' ? 'unregistered' : 'callback')];
      const ordinaryAfter = ordinary();
      const afterNative = native?.observe();
      if (afterNative) {
        assert.equal(afterNative.mainOpens, 2); assert.equal(afterNative.totalOpens, 2);
        assert.equal(afterNative.defaultUnchanged, true); assert.equal(afterNative.sourceId, ordinaryAfter.sourceId);
      }
      barrier(mode === 'scoped' ? 'unregistered_after_unload' : 'callback_refused',
        { ...lifetime, napiLoaded: mode === 'dual', routed, ordinaryAfter, afterNative });
    }
  }
  output('completed', { ...lifetime, physicalBindingQualified: false, productionCredentialAuthorityQualified: false, installedI1Qualified: false });
} catch (error) { output('fatal', { error: String((error as Error).stack ?? error) }); process.exitCode = 1; }
finally {
  if (bootstrap) { const consumed = bootstrap; bootstrap = undefined; consumed.close(); }
  if (held !== undefined) { const consumed = held; held = undefined; closeSync(consumed); }
}
