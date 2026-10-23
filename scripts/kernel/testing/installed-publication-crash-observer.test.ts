// Pure closed-output tests only; these literals are not process/death evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { decodePublicationCrashObserverOutput, decodePublicationRetirementStopObserverOutput } from './installed-publication-crash-observer.js';
import * as observer from './installed-publication-crash-observer.js';
import type { PublicationArenaBirthV1 } from '../../../src/kernel/publication.js';

test('the fixed retirement-stop consumer refuses invalid original identities before spawning', () => {
  assert.equal(typeof observer.startPublicationRetirementStopObserver, 'function');
  const input = { executable: '/not-used', prefix: [], cwd: '/not-used', env: {}, stateRoot: '/not-used',
    pid: 1, uid: 1, startTicks: '1', imageDigest: 'a'.repeat(64), imageDevice: '1', imageInode: '2', imageSize: '3', scan: () => undefined };
  for (const changed of [{ ...input, pid: 0 }, { ...input, uid: 0 }, { ...input, startTicks: '01' }, { ...input, imageDigest: 'private text' }])
    assert.throws(() => observer.startPublicationRetirementStopObserver(changed));
});

test('both fixed consumers join real spawn failure and all original pipes without a fabricated transcript', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-observer-spawn-failure-'));
  try {
    for (const start of [observer.startPublicationCrashObserver, observer.startPublicationRetirementStopObserver]) {
      const actor = start({ executable: '/not-an-observer', prefix: [], cwd: path.join(fixture, 'absent'), env: {}, stateRoot: fixture,
        pid: 1, uid: 1, startTicks: '1', imageDigest: 'a'.repeat(64), imageDevice: '1', imageInode: '2', imageSize: '3', scan: () => undefined });
      const settled = await Promise.allSettled([actor.ready, actor.joined, actor.close()]);
      assert(settled.every(result => result.status === 'rejected'));
      assert.throws(() => actor.arm({ arenaId: 'A'.repeat(43), arenaIdentity: { ownerUid: 1, mode: 0o700, deviceId: '1', fileId: '2' },
        parentIdentity: { ownerUid: 1, mode: 0o700, deviceId: '1', fileId: '3' } } as PublicationArenaBirthV1));
    }
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

test('only a complete joined one-shot observer transcript reports the requested signal', () => {
  assert.deepEqual(decodePublicationCrashObserverOutput(Buffer.from('publication_parent_watch_ready\npublication_original_birth_armed\npublication_original_supervisor_killed\n'), 0, null),
    { watchReady: true, originalBirthArmed: true, uniqueSignalSent: true, processAndPipesJoined: true });
});

test('missing, duplicated, reordered, extra, non-ASCII or unjoined output cannot report a crash cut', () => {
  const ready = 'publication_parent_watch_ready\n', armed = 'publication_original_birth_armed\n', killed = 'publication_original_supervisor_killed\n';
  for (const output of ['', ready, ready + armed, ready + killed + armed, ready + armed + killed + killed,
    ready + armed + killed + 'arbitrary\n', ready + armed + killed + '\0', ready + armed + 'publication_original_supervisor_killéd\n'])
    assert.throws(() => decodePublicationCrashObserverOutput(Buffer.from(output), 0, null));
  assert.throws(() => decodePublicationCrashObserverOutput(Buffer.from(ready + armed + killed), 98, null));
  assert.throws(() => decodePublicationCrashObserverOutput(Buffer.from(ready + armed + killed), null, 'SIGKILL'));
});

test('a joined retirement-stop transcript keeps the original signal interval and its at-most-two-second joined observation', () => {
  const output = 'publication_retirement_watch_ready\npublication_retirement_original_birth_armed\n' +
    'publication_retirement_signal_v1 1000000000 1000000000000 1000000100 1000000000100\n' +
    'publication_retirement_joined_v1 3000000000 1002000000000\npublication_retirement_original_supervisor_stopped_joined\n';
  const result = decodePublicationRetirementStopObserverOutput(Buffer.from(output), 0, null);
  assert.deepEqual(result, {
    watchReady: true, originalBirthArmed: true, uniqueSignalSent: true, processAndPipesJoined: true,
    signal: { monotonicEnterNs: '1000000000', realtimeEnterNs: '1000000000000', monotonicReturnNs: '1000000100', realtimeReturnNs: '1000000000100' },
    joined: { monotonicNs: '3000000000', realtimeNs: '1002000000000' },
  });
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.signal)); assert(Object.isFrozen(result.joined));
  assert.throws(() => decodePublicationCrashObserverOutput(Buffer.from(output), 0, null));
});

test('a partial, reinterpreted, noncanonical, regressing or over-two-second stop transcript never qualifies a joined stop', () => {
  const ready = 'publication_retirement_watch_ready\n', armed = 'publication_retirement_original_birth_armed\n';
  const signal = 'publication_retirement_signal_v1 1000000000 1000000000000 1000000100 1000000000100\n';
  const joined = 'publication_retirement_joined_v1 3000000000 1002000000000\n';
  const complete = 'publication_retirement_original_supervisor_stopped_joined\n';
  const valid = ready + armed + signal + joined + complete;
  for (const output of ['', ready, ready + armed, ready + armed + signal, ready + signal + armed + joined + complete,
    valid + complete, valid + '\0', valid + 'extra\n', valid.replace('joined_v1', 'joinéd_v1'),
    valid.replace('1000000000 ', '01000000000 '), valid.replace('1000000000 ', '-1000000000 '),
    valid.replace('1000000000 ', '18446744073709551616 '), valid.replace('1000000100 ', '999999999 '),
    valid.replace('1000000000100\n', '999999999999\n'), valid.replace('3000000000 ', '3000000001 '),
    valid.replace('3000000000 ', '999999999 '), valid.replace('1002000000000\n', '1000000000099\n'),
    valid.replace(signal, signal + signal), valid.replace('1000000100 ', '1000000100 extra '),
    'publication_parent_watch_ready\npublication_original_birth_armed\npublication_original_supervisor_killed\n'])
    assert.throws(() => decodePublicationRetirementStopObserverOutput(Buffer.from(output), 0, null));
  assert.throws(() => decodePublicationRetirementStopObserverOutput(Buffer.alloc(513, 65), 0, null));
  assert.throws(() => decodePublicationRetirementStopObserverOutput(Buffer.from(valid), 98, null));
  assert.throws(() => decodePublicationRetirementStopObserverOutput(Buffer.from(valid), null, 'SIGKILL'));
  assert.throws(() => decodePublicationRetirementStopObserverOutput(Buffer.from(valid), 0, 'SIGTERM'));
});

// Actual child/process/pipe lifecycle only, using inert protocol literals.
// No C observer body, real birth/death or native retirement is substituted.
// macOS/non-root runs do not execute these Linux runuser fixture bodies.
if (process.platform === 'linux' && process.geteuid?.() === 0) {
  const SCRIPT = String.raw`
const fs = require('node:fs');
const stop = process.env.CLIQ_PROTOCOL_STOP === 'yes';
const mode = process.env.CLIQ_PROTOCOL_CASE;
if (process.argv.filter(value => value === '--retirement-stop').length !== (stop ? 1 : 0) ||
    stop && process.argv.at(-1) !== '--retirement-stop') process.exit(95);
const ready = stop ? 'publication_retirement_watch_ready\n' : 'publication_parent_watch_ready\n';
const armed = stop ? 'publication_retirement_original_birth_armed\n' : 'publication_original_birth_armed\n';
const complete = stop ? 'publication_retirement_signal_v1 1000000000 1000000000000 1000000100 1000000000100\n' +
  'publication_retirement_joined_v1 3000000000 1002000000000\npublication_retirement_original_supervisor_stopped_joined\n' : 'publication_original_supervisor_killed\n';
const barrier = () => { try { return fs.readFileSync(process.env.CLIQ_PROTOCOL_BARRIER, 'utf8'); } catch { return ''; } };
process.stdin.on('end', () => process.exit(97));
if (mode === 'before-arm') { process.stdout.write(ready + armed); process.stdin.resume(); }
else {
  const split = Math.floor(ready.length / 2);
  process.stdout.write(ready.slice(0, split));
  const releaseReady = setInterval(() => { if (barrier() === 'ready') { clearInterval(releaseReady); process.stdout.write(ready.slice(split)); } }, 5);
  process.stdin.once('data', bytes => {
    if (bytes.toString() !== 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1 2 1 3\n') process.exit(94);
    if (mode === 'overflow') process.stdout.write(Buffer.alloc(513, 65));
    else { if (mode === 'stderr') process.stderr.write('inert-protocol-stderr'); process.stdout.write(armed + complete); }
    const releaseExit = setInterval(() => { if (barrier() === 'exit') { clearInterval(releaseExit); process.exit(mode === 'nonzero' ? 1 : 0); } }, 5);
  });
}
`;
  async function protocolFixture(stop: boolean, mode = 'complete', throwScan = false) {
    const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-protocol-'));
    await chmod(fixture, 0o755);
    const script = path.join(fixture, 'observer.cjs'), barrier = path.join(fixture, 'barrier');
    await writeFile(script, SCRIPT, { flag: 'wx', mode: 0o444 });
    const account = spawnSync('/usr/bin/id', ['-u', 'nobody'], { encoding: 'utf8' });
    assert.equal(account.error, undefined); assert.equal(account.status, 0);
    const uid = Number(account.stdout.trim()); assert(Number.isSafeInteger(uid) && uid > 0);
    let partialResolve!: () => void, completeResolve!: () => void, scanned = Buffer.alloc(0);
    const partialSeen = new Promise<void>(resolve => { partialResolve = resolve; }), completeSeen = new Promise<void>(resolve => { completeResolve = resolve; });
    const start = stop ? observer.startPublicationRetirementStopObserver : observer.startPublicationCrashObserver;
    const actor = start({ executable: process.execPath, prefix: ['-u', 'nobody', '--'], cwd: fixture,
      env: { CLIQ_PROTOCOL_STOP: stop ? 'yes' : 'no', CLIQ_PROTOCOL_CASE: mode, CLIQ_PROTOCOL_BARRIER: barrier }, stateRoot: script,
      pid: 1, uid, startTicks: '1', imageDigest: 'a'.repeat(64), imageDevice: '1', imageInode: '2', imageSize: '3',
      scan(bytes) {
        if (throwScan) throw undefined;
        scanned = Buffer.concat([scanned, bytes]); partialResolve();
        if (scanned.includes(Buffer.from(stop ? 'publication_retirement_original_supervisor_stopped_joined\n' : 'publication_original_supervisor_killed\n'))) completeResolve();
      } });
    const birth = { arenaId: 'A'.repeat(43), arenaIdentity: { ownerUid: uid, mode: 0o700, deviceId: '1', fileId: '2' },
      parentIdentity: { ownerUid: uid, mode: 0o700, deviceId: '1', fileId: '3' } } as PublicationArenaBirthV1;
    const observe = (marker: Promise<void>) => Promise.race([marker, actor.joined.then(() => { throw new Error('owned protocol fixture closed before its required marker'); })]);
    return { actor, birth, waitPartial: () => observe(partialSeen), waitComplete: () => observe(completeSeen),
      async release(value: string) { await writeFile(barrier, value, { mode: 0o444 }); },
      async dispose() { try { await actor.close(); } catch { /* Expected refusal still joins the original child and pipes. */ }
        await rm(fixture, { recursive: true, force: true }); } };
  }

  test('real Linux protocol children require complete ready, one original arm and actual close before either fixed consumer joins', async () => {
    for (const stop of [false, true]) {
      const fixture = await protocolFixture(stop), { actor } = fixture;
      try {
        let ready = false, joined = false;
        void actor.ready.then(() => { ready = true; }, () => undefined); void actor.joined.then(() => { joined = true; }, () => undefined);
        await fixture.waitPartial(); assert.equal(ready, false); assert.equal(joined, false);
        await fixture.release('ready'); await actor.ready;
        assert.throws(() => actor.arm({ ...fixture.birth, arenaIdentity: { ...fixture.birth.arenaIdentity, ownerUid: 0 } }));
        actor.arm(fixture.birth); assert.throws(() => actor.arm(fixture.birth));
        await fixture.waitComplete(); assert.equal(joined, false);
        await fixture.release('exit'); const result = await actor.joined;
        assert.equal(result.processAndPipesJoined, true); assert.equal(result.originalBirthArmed, true);
        if (stop) assert.equal((result as ReturnType<typeof decodePublicationRetirementStopObserverOutput>).signal.monotonicEnterNs, '1000000000');
        else assert.equal('signal' in result, false);
      } finally { await fixture.dispose(); }
    }
  });

  test('real Linux protocol refusal joins early output, scan failure, no arm, stderr, overflow and nonzero child exit', async () => {
    for (const mode of ['before-arm', 'scan-failure', 'no-arm', 'stderr', 'overflow', 'nonzero']) {
      const fixture = await protocolFixture(true, mode, mode === 'scan-failure'), { actor } = fixture;
      try {
        if (mode === 'before-arm' || mode === 'scan-failure') {
          const results = await Promise.allSettled([actor.ready, actor.joined]);
          assert(results.every(result => result.status === 'rejected'));
        } else {
          await fixture.waitPartial(); await fixture.release('ready'); await actor.ready;
          if (mode === 'no-arm') await assert.rejects(actor.close());
          else {
            actor.arm(fixture.birth);
            if (mode !== 'overflow') { await fixture.waitComplete(); await fixture.release('exit'); }
            await assert.rejects(actor.joined);
          }
        }
      } finally { await fixture.dispose(); }
    }
  });
}
