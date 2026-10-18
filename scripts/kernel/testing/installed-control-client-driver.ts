// Qualification-only consumer of the production installed client. The root-
// owned disposable fixture ledger is trusted test composition, not a public
// release-key/path override or a source of StateOwner/Run/native authority.
import assert from 'node:assert/strict';
import { constants, writeSync, type BigIntStats } from 'node:fs';
import { lstat, open, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { CONTROL_FRAME_BYTES as bound, decodeControlFrame, decodeInstalledControlRequest, INSTALLED_CONTROL_FEATURES,
  type InstalledControlFeature } from '../../../src/kernel/control-wire.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { ReleaseTrustKey } from '../../../src/policy/runtime-authority.js';
import { ResourceRetirementError } from '../../../src/state/errors.js';
import { createInstalledRuntime, type HeldInstalledRuntime } from '../../../src/state/installed-runtime.js';
import { openInstalledSupervisorClient, type InstalledSupervisorClient } from '../../../src/state/installed-control-client.js';
import type { InstalledClientDriverStage } from './installed-client-consumer.js';

let phase: InstalledClientDriverStage = 'platform';
let failedPhase: InstalledClientDriverStage | undefined;
const observedPhases = new Set<InstalledClientDriverStage>();
function writeMarker(kind: 'progress' | 'failed', stage: InstalledClientDriverStage): void {
  try { writeSync(2, `installed control client driver ${kind} phase=${stage}\n`); }
  catch { /* Optional diagnosis must never alter original execution or join. */ }
}
function setPhase(next: InstalledClientDriverStage): void {
  phase = next;
  // Startup diagnosis only. Repeated request/output entries do not spend the
  // original 64 KiB stderr budget or change the 1024-frame limit.
  if (!observedPhases.has(next)) {
    observedPhases.add(next);
    writeMarker('progress', next);
  }
}

const sameFile = (left: BigIntStats, right: BigIntStats) =>
  (['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs'] as const).every(key => left[key] === right[key]);
function rootDirectory(info: BigIntStats): void {
  assert(info.isDirectory() && !info.isSymbolicLink() && info.uid === 0n && info.gid === 0n && (info.mode & 0o7777n) === 0o755n);
}
async function retire(handle: FileHandle): Promise<void> {
  try { await handle.close(); }
  catch (cause) { throw new ResourceRetirementError('installed client fixture descriptor did not retire', cause); }
}
async function publicRootData(filename: string): Promise<Buffer> {
  const before = await lstat(filename, { bigint: true });
  assert(before.isFile() && !before.isSymbolicLink() && before.uid === 0n && before.gid === 0n && before.nlink === 1n &&
    (before.mode & 0o7777n) === 0o444n && before.size > 0n && before.size <= 65536n);
  const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    assert(sameFile(before, await held.stat({ bigint: true })));
    const bytes = Buffer.alloc(Number(before.size) + 1); let count = 0;
    for (;;) {
      const read = await held.read(bytes, count, bytes.length - count, null); count += read.bytesRead;
      assert(count < bytes.length);
      if (read.bytesRead === 0) break;
    }
    assert.equal(count, Number(before.size));
    assert(sameFile(before, await held.stat({ bigint: true })) && sameFile(before, await lstat(filename, { bigint: true })));
    return bytes.subarray(0, count);
  } finally { await retire(held); }
}
async function fixtureComposition(filename: string): Promise<{ stateRoot: string; releaseKeys: ReleaseTrustKey[] }> {
  assert(path.isAbsolute(filename) && path.basename(filename) === 'ownership-ledger.json');
  const fixture = path.dirname(filename);
  assert.match(fixture, /^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+$/u);
  const named = await lstat(fixture, { bigint: true }); rootDirectory(named);
  const directory = await open(fixture, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const info = await directory.stat({ bigint: true }); rootDirectory(info);
    assert(info.dev === named.dev && info.ino === named.ino);
    const ledger = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(
      await publicRootData(`/proc/self/fd/${directory.fd}/ownership-ledger.json`))) as Record<string, any>;
    assert.equal(ledger.diagnosticOnly, true); assert.equal(ledger.fixture, fixture);
    assert.equal(ledger.fixtureIdentity, `${info.dev}:${info.ino}:${info.uid}`);
    assert(Number.isSafeInteger(ledger.uid) && ledger.uid > 0 && ledger.uid === ledger.gid);
    assert.equal(process.geteuid!(), ledger.uid); assert.equal(process.getegid!(), ledger.gid);
    assert.equal(ledger.home, path.join(fixture, 'home'));
    const stateRoot = path.join(ledger.home, '.cliq/kernel-v1');
    assert.equal(ledger.runJourney.stateRoot, stateRoot);
    assert.equal(ledger.runJourney.releaseKeysFile, path.join(fixture, 'run-release-keys.json'));
    const bytes = await publicRootData(`/proc/self/fd/${directory.fd}/run-release-keys.json`);
    const releaseKeys = decodeControlFrame(bytes) as ReleaseTrustKey[];
    const after = await lstat(fixture, { bigint: true }); rootDirectory(after);
    assert(after.dev === info.dev && after.ino === info.ino);
    return { stateRoot, releaseKeys };
  } finally { await retire(directory); }
}
async function* requests(): AsyncGenerator<Buffer> {
  // Preserve the original harness budget: its automatic real hello is the
  // first of 1024 frames, leaving at most 1023 business requests. This is not
  // a production protocol or transport connection limit.
  let pending = Buffer.alloc(0), count = 1;
  for await (const chunk of process.stdin) {
    assert(Buffer.isBuffer(chunk)); let offset = 0;
    while (offset < chunk.length) {
      const newline = chunk.indexOf(10, offset), end = newline < 0 ? chunk.length : newline;
      const piece = chunk.subarray(offset, end);
      assert(pending.length + piece.length <= bound);
      pending = pending.length ? Buffer.concat([pending, piece]) : Buffer.from(piece);
      offset = end + (newline < 0 ? 0 : 1);
      if (newline >= 0) {
        assert(++count <= 1024 && pending.length > 0);
        const complete = pending; pending = Buffer.alloc(0); yield complete;
      }
    }
  }
  assert.equal(pending.length, 0, 'truncated installed client JSONL input');
}
async function output(value: unknown): Promise<void> {
  const bytes = Buffer.concat([canonicalJsonBytes(value), Buffer.from('\n')]);
  assert(bytes.length <= bound + 1);
  await new Promise<void>((resolve, reject) => process.stdout.write(bytes, error => error ? reject(new Error('installed client output failed')) : resolve()));
}
async function main(): Promise<void> {
  setPhase('platform');
  assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
  assert(process.geteuid!() > 0 && process.getegid!() > 0);
  const [filename, ...extra] = process.argv.slice(2); assert(filename && extra.length === 0);
  setPhase('composition');
  const composition = await fixtureComposition(filename);
  let selected: HeldInstalledRuntime | undefined, client: InstalledSupervisorClient | undefined, failure: unknown;
  let stopping: Promise<void> | undefined, stopRequested = false;
  const stop = () => {
    stopRequested = true;
    process.stdin.destroy();
    if (client) { stopping ??= client.close(); void stopping.catch(() => {}); }
  };
  process.once('SIGTERM', stop); process.once('SIGINT', stop); process.stdout.on('error', stop);
  try {
    setPhase('selection');
    selected = await createInstalledRuntime({ releaseKeys: composition.releaseKeys }).openSelected(composition.stateRoot);
    assert(!stopRequested, 'installed client driver is stopping');
    setPhase('authentication');
    client = await openInstalledSupervisorClient(selected);
    assert(!stopRequested, 'installed client driver is stopping');
    setPhase('output');
    await output({ protocolVersion: 1, ok: true, result: client.hello });
    setPhase('request');
    for await (const bytes of requests()) {
      setPhase('request');
      const request = decodeInstalledControlRequest(decodeControlFrame(bytes));
      assert(INSTALLED_CONTROL_FEATURES.includes(request.method as InstalledControlFeature), 'only connected installed methods may be sent');
      // The canonical table supplies the dynamic JSONL adapter; each generated
      // method and the common transport independently enforce its exact method.
      const response = await Reflect.apply(client[request.method as InstalledControlFeature], client, [request]);
      setPhase('output'); await output(response); setPhase('request');
    }
    assert(!stopRequested, 'installed client driver stopped before EOF');
  } catch (error) { failure = error; failedPhase = phase; }
  finally {
    setPhase('retirement');
    try {
      // Never close the selected original images under an uncertain native
      // client. The nonzero process exit, not a claimed join, is the fallback.
      if (failure instanceof ResourceRetirementError) throw failure;
      if (client) await client.close();
      if (selected) await selected.close();
    } catch (error) {
      failedPhase = phase; throw error;
    } finally {
      process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop); process.stdout.removeListener('error', stop);
    }
  }
  if (failure !== undefined) throw failure;
  assert(!stopRequested, 'installed client driver stopped before process join');
}
try { await main(); }
catch {
  // No user input, provider bytes, remote diagnostic, key or arbitrary cause.
  writeMarker('failed', failedPhase ?? phase); process.exitCode = 1;
}
