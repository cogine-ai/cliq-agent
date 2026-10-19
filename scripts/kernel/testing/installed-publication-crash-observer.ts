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

export function startPublicationCrashObserver(input: {
  executable: string; prefix: readonly string[]; cwd: string; env: NodeJS.ProcessEnv;
  stateRoot: string; pid: number; startTicks: string; uid: number;
  imageDigest: string; imageDevice: string; imageInode: string; imageSize: string;
  scan(bytes: Buffer): void;
}) {
  for (const value of [input.pid, input.uid]) assert(Number.isSafeInteger(value) && value > 0);
  for (const value of [input.startTicks, input.imageDevice, input.imageInode, input.imageSize]) assert.match(value, /^(0|[1-9][0-9]{0,19})$/u);
  assert.match(input.imageDigest, /^[0-9a-f]{64}$/u);
  const child = spawn('/usr/sbin/runuser', [...input.prefix, input.executable, input.stateRoot, String(input.pid), input.startTicks,
    String(input.uid), input.imageDigest, input.imageDevice, input.imageInode, input.imageSize],
  { cwd: input.cwd, env: input.env, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = Buffer.alloc(0), errorBytes = 0, failure: unknown, armed = false;
  let readyResolve!: () => void, readyReject!: (error: unknown) => void;
  const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const refuse = (error: unknown) => { failure ??= error; readyReject(error); child.stdin.end(); };
  child.stdout.on('data', (chunk: Buffer) => {
    try {
      input.scan(chunk); assert(output.length + chunk.length <= COMPLETE.length);
      output = Buffer.concat([output, chunk]); assert(Buffer.from(COMPLETE).subarray(0, output.length).equals(output));
      assert(armed || output.length <= READY.length);
      if (output.length >= READY.length) readyResolve();
    } catch (error) { refuse(error); }
  });
  child.stderr.on('data', (chunk: Buffer) => {
    try { input.scan(chunk); errorBytes += chunk.length; assert(errorBytes <= 256); }
    catch (error) { refuse(error); }
  });
  child.stdin.on('error', refuse); child.on('error', refuse);
  const joined = new Promise<ReturnType<typeof decodePublicationCrashObserverOutput>>((resolve, reject) => {
    child.once('close', (code, signal) => {
      try { if (failure) throw failure; assert.equal(errorBytes, 0); const result = decodePublicationCrashObserverOutput(output, code, signal); resolve(result); }
      catch (error) { readyReject(error); reject(error); }
    });
  });
  // The root fixture owns ready/join failures; do not produce unhandled rejection
  // before it reaches the corresponding awaited lifetime checkpoint.
  void joined.catch(() => undefined); void ready.catch(() => undefined);
  return Object.freeze({ ready, joined,
    arm(birth: PublicationArenaBirthV1) {
      assert(!armed); assert.match(birth.arenaId, /^[A-Za-z0-9_-]{43}$/u);
      for (const identity of [birth.arenaIdentity, birth.parentIdentity]) {
        assert.equal(identity.ownerUid, input.uid); assert.equal(identity.mode, 0o700);
        for (const value of [identity.deviceId, identity.fileId]) assert.match(value, /^(0|[1-9][0-9]{0,19})$/u);
      }
      armed = true;
      child.stdin.write(`${birth.arenaId} ${birth.arenaIdentity.deviceId} ${birth.arenaIdentity.fileId} ${birth.parentIdentity.deviceId} ${birth.parentIdentity.fileId}\n`);
    },
    async close() { child.stdin.end(); try { await joined; } finally { output.fill(0); } },
  });
}
