// Test actor only. No production authority, pause, ptrace, SQL write or retry.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import type { PublicationArenaBirthV1 } from '../../../src/kernel/publication.js';

const READY = 'publication_parent_watch_ready\n';
const ARMED = 'publication_original_birth_armed\n';
const KILLED = 'publication_original_supervisor_killed\n';
const COMPLETE = READY + ARMED + KILLED;

export function decodePublicationCrashObserverOutput(bytes: Buffer, code: number | null, signal: NodeJS.Signals | null) {
  assert.equal(code, 0); assert.equal(signal, null); assert(bytes.equals(Buffer.from(COMPLETE)));
  return Object.freeze({ watchReady: true, originalBirthArmed: true, uniqueSignalSent: true, processAndPipesJoined: true });
}

/** Pure closed data only. The actual actor/process and same native task/key
 * interval are verified independently; a transcript is not an in-flight proof. */
export function decodePublicationRetirementStopObserverOutput(bytes: Buffer, code: number | null, signal: NodeJS.Signals | null) {
  assert.equal(code, 0); assert.equal(signal, null); assert(bytes.length <= 512);
  const text = bytes.toString('ascii'); assert(bytes.equals(Buffer.from(text, 'ascii')));
  const lines = text.split('\n'); assert.equal(lines.length, 6);
  assert.equal(lines[0], 'publication_retirement_watch_ready');
  assert.equal(lines[1], 'publication_retirement_original_birth_armed');
  assert.equal(lines[4], 'publication_retirement_original_supervisor_stopped_joined'); assert.equal(lines[5], '');
  const signalFields = lines[2]!.split(' '), joinedFields = lines[3]!.split(' ');
  assert.equal(signalFields.length, 5); assert.equal(signalFields[0], 'publication_retirement_signal_v1');
  assert.equal(joinedFields.length, 3); assert.equal(joinedFields[0], 'publication_retirement_joined_v1');
  const values = [...signalFields.slice(1), ...joinedFields.slice(1)];
  for (const value of values) { assert.match(value, /^(0|[1-9][0-9]{0,19})$/u); assert(BigInt(value) <= 18446744073709551615n); }
  const [enterM, enterR, returnM, returnR, joinedM, joinedR] = values.map(value => BigInt(value));
  assert(returnM! >= enterM! && returnR! >= enterR! && joinedM! >= returnM! && joinedR! >= returnR!);
  assert(joinedM! - enterM! <= 2000000000n);
  return Object.freeze({ watchReady: true, originalBirthArmed: true, uniqueSignalSent: true, processAndPipesJoined: true,
    signal: Object.freeze({ monotonicEnterNs: values[0]!, realtimeEnterNs: values[1]!, monotonicReturnNs: values[2]!, realtimeReturnNs: values[3]! }),
    joined: Object.freeze({ monotonicNs: values[4]!, realtimeNs: values[5]! }) });
}

type ObserverInput = {
  executable: string; prefix: readonly string[]; cwd: string; env: NodeJS.ProcessEnv;
  stateRoot: string; pid: number; startTicks: string; uid: number;
  imageDigest: string; imageDevice: string; imageInode: string; imageSize: string;
  scan(bytes: Buffer): void;
};
type ObserverMode<Result> = { ready: string; outputLimit: number; retirementStop: boolean;
  decode(bytes: Buffer, code: number | null, signal: NodeJS.Signals | null): Result };

export function startPublicationCrashObserver(input: ObserverInput) {
  return startObserver(input, { ready: READY, outputLimit: COMPLETE.length, retirementStop: false, decode: decodePublicationCrashObserverOutput });
}
export function startPublicationRetirementStopObserver(input: ObserverInput) {
  return startObserver(input, { ready: 'publication_retirement_watch_ready\n', outputLimit: 512,
    retirementStop: true, decode: decodePublicationRetirementStopObserverOutput });
}

// Both fixed actors share one actual process/pipe lifetime. A failed scan or
// write closes only original stdin; no invented timeout, signal or retry joins.
function startObserver<Result>(input: ObserverInput, mode: ObserverMode<Result>) {
  for (const value of [input.pid, input.uid]) assert(Number.isSafeInteger(value) && value > 0);
  for (const value of [input.startTicks, input.imageDevice, input.imageInode, input.imageSize]) assert.match(value, /^(0|[1-9][0-9]{0,19})$/u);
  assert.match(input.imageDigest, /^[0-9a-f]{64}$/u);
  const child = spawn('/usr/sbin/runuser', [...input.prefix, input.executable, input.stateRoot, String(input.pid), input.startTicks,
    String(input.uid), input.imageDigest, input.imageDevice, input.imageInode, input.imageSize, ...(mode.retirementStop ? ['--retirement-stop'] : [])],
  { cwd: input.cwd, env: input.env, stdio: ['pipe', 'pipe', 'pipe'] });
  const readyBytes = Buffer.from(mode.ready), completeBytes = Buffer.from(COMPLETE), writes: Promise<void>[] = [];
  const pipesJoined = [child.stdin, child.stdout, child.stderr].map(pipe => new Promise<void>(resolve => pipe.once('close', resolve)));
  let output = Buffer.alloc(0), errorBytes = 0, failure: unknown, failed = false, armed = false, closed = false;
  let readyResolve!: () => void, readyReject!: (error: unknown) => void;
  const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const endInput = () => { if (!child.stdin.destroyed && !child.stdin.writableEnded) child.stdin.end(); };
  const refuse = (error: unknown) => {
    if (!failed) { failed = true; failure = error; }
    readyReject(error);
    try { endInput(); } catch { /* Preserve the first failure; close and every original pipe still join below. */ }
  };
  child.stdout.on('data', (chunk: Buffer) => {
    try {
      input.scan(chunk); assert(output.length + chunk.length <= mode.outputLimit);
      output = Buffer.concat([output, chunk]);
      if (mode.retirementStop) assert(readyBytes.subarray(0, Math.min(output.length, readyBytes.length)).equals(output.subarray(0, readyBytes.length)));
      else assert(completeBytes.subarray(0, output.length).equals(output));
      assert(armed || output.length <= readyBytes.length);
      if (output.length >= readyBytes.length) readyResolve();
    } catch (error) { refuse(error); }
  });
  child.stderr.on('data', (chunk: Buffer) => {
    try { input.scan(chunk); errorBytes += chunk.length; assert(errorBytes <= 256); }
    catch (error) { refuse(error); }
  });
  for (const pipe of [child.stdin, child.stdout, child.stderr]) pipe.on('error', refuse);
  child.on('error', refuse);
  const joined = new Promise<Result>((resolve, reject) => {
    child.once('close', async (code, signal) => {
      closed = true;
      try {
        await Promise.all([...pipesJoined, ...writes]);
        if (failed) throw failure;
        assert.equal(errorBytes, 0); resolve(mode.decode(output, code, signal));
      }
      catch (error) { readyReject(error); reject(error); }
    });
  });
  // The root fixture owns ready/join failures; do not produce unhandled rejection
  // before it reaches the corresponding awaited lifetime checkpoint.
  void joined.catch(() => undefined); void ready.catch(() => undefined);
  return Object.freeze({ ready, joined,
    arm(birth: PublicationArenaBirthV1) {
      assert(!armed && !failed && !closed && !child.stdin.destroyed && !child.stdin.writableEnded);
      assert.match(birth.arenaId, /^[A-Za-z0-9_-]{43}$/u);
      for (const identity of [birth.arenaIdentity, birth.parentIdentity]) {
        assert.equal(identity.ownerUid, input.uid); assert.equal(identity.mode, 0o700);
        for (const value of [identity.deviceId, identity.fileId]) assert.match(value, /^(0|[1-9][0-9]{0,19})$/u);
      }
      armed = true;
      writes.push(new Promise<void>(resolve => {
        try {
          child.stdin.write(`${birth.arenaId} ${birth.arenaIdentity.deviceId} ${birth.arenaIdentity.fileId} ${birth.parentIdentity.deviceId} ${birth.parentIdentity.fileId}\n`,
            error => { if (error) refuse(error); resolve(); });
        } catch (error) { refuse(error); resolve(); }
      }));
    },
    async close() { try { endInput(); } catch (error) { refuse(error); } try { await joined; } finally { output.fill(0); } },
  });
}
