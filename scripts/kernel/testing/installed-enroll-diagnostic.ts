// Test-only observations of a real owned enroll command. Neither counters nor
// retained phases are process-death, credential, installation or Run authority.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import type { CredentialSecretScanner } from './credential-secret-scan.js';
import { INSTALLED_CREDENTIAL_PHASES, type InstalledCredentialPhase } from '../../../src/state/installed-diagnostics.js';

const phaseMarkers = INSTALLED_CREDENTIAL_PHASES.map(phase => ({ phase, bytes: Buffer.from(`CLIQ_CREDENTIAL_PHASE_V1:${phase}\n`) }));
/** Closed data only: unknown/partial bytes are never copied into a report. */
export function decodeEnrollCredentialPhase(input: unknown): InstalledCredentialPhase | undefined {
  if (!Buffer.isBuffer(input)) return undefined;
  return phaseMarkers.find(marker => marker.bytes.equals(input))?.phase;
}

export type EnrollProcessCounters = Readonly<{ pid: number; parent: number; group: number; session: number;
  startTicks: string; userTicks: string; systemTicks: string; rchar: string; syscr: string; readBytes: string }>;

export function decodeEnrollProcessCounters(pid: number, stat: string, io: string): EnrollProcessCounters {
  try {
    if (!Number.isSafeInteger(pid) || pid < 1 || stat.length > 8192 || io.length > 4096 || !stat.startsWith(`${pid} (`)) throw 0;
    const at = stat.lastIndexOf(') '), fields = stat.slice(at + 2).trim().split(/\s+/u);
    if (at < 0 || fields.length < 20 || !/^[A-Za-z]$/u.test(fields[0]!)) throw 0;
    const decimal = (value: string | undefined) => { if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/u.test(value)) throw 0; return value; };
    const integer = (value: string | undefined) => { const result = Number(decimal(value)); if (!Number.isSafeInteger(result)) throw 0; return result; };
    const numbers = new Map<string, string>();
    for (const line of io.trim().split('\n')) {
      const match = /^(rchar|syscr|read_bytes): (.*)$/u.exec(line);
      if (match) { if (numbers.has(match[1]!)) throw 0; numbers.set(match[1]!, decimal(match[2])); }
    }
    return Object.freeze({ pid, parent: integer(fields[1]), group: integer(fields[2]), session: integer(fields[3]),
      startTicks: decimal(fields[19]), userTicks: decimal(fields[11]), systemTicks: decimal(fields[12]),
      rchar: decimal(numbers.get('rchar')), syscr: decimal(numbers.get('syscr')), readBytes: decimal(numbers.get('read_bytes')) });
  } catch { throw new TypeError('enroll process counters are invalid'); }
}

export type EnrollOwnerStage = Readonly<{ kind: 'absent' | 'busy' | 'unavailable' } |
  { kind: 'active' | 'terminal'; epoch: number }>;
type EnrollProcessSample = Readonly<{ kind: 'not_observed' | 'exited' | 'unavailable' } | {
  kind: 'observed'; pid: number; startTicks: string; role: 'bootstrap' | 'credential';
  userTicks: string; systemTicks: string; rchar: string; syscr: string; readBytes: string }>;
export type InstalledEnrollDiagnostic = {
  diagnosticOnly: true; originalDeadlineMs: number; elapsedMs: number;
  outcome: 'completed' | 'timeout' | 'spawn_failed' | 'output_limit' | 'observation_failed';
  launcherObserved: boolean; authObserved: boolean; launcherJoined: boolean; authJoined: boolean; processAndPipesJoined: boolean;
  completeInputWriteJoined: boolean;
  samples: Array<{ elapsedMs: number; process: EnrollProcessSample; owner: EnrollOwnerStage }>;
  /** First 32 complete markers observed on this original child's scanned
   * stderr; not a realtime state, full trace or credential/effect authority. */
  phases: Array<{ elapsedMs: number; phase: InstalledCredentialPhase }>;
};
type Fact = { pid: number; parent: number; group: number; session: number; start: string; uids: number[]; raw: string };
async function processFact(pid: number): Promise<Fact | undefined> {
  try {
    const raw = await readFile(`/proc/${pid}/stat`, 'utf8');
    assert(raw.startsWith(`${pid} (`) && raw.length <= 8192);
    const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u);
    assert(fields.length > 19 && /^[1-9][0-9]*$/u.test(fields[19]!));
    const status = await readFile(`/proc/${pid}/status`, 'utf8'); assert(status.length <= 65536);
    const uid = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu.exec(status); assert(uid);
    const confirmed = await readFile(`/proc/${pid}/stat`, 'utf8'); assert(confirmed.startsWith(`${pid} (`));
    assert.equal(confirmed.slice(confirmed.lastIndexOf(')') + 2).trim().split(/\s+/u)[19], fields[19]);
    return { pid, parent: Number(fields[1]), group: Number(fields[2]), session: Number(fields[3]), start: fields[19]!,
      uids: uid.slice(1).map(Number), raw };
  } catch (error) {
    if (['ENOENT', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) return undefined;
    throw new Error('owned enroll process identity is unavailable');
  }
}
async function waitGone(original: Fact): Promise<void> {
  const by = performance.now() + 5000;
  for (;;) {
    const current = await processFact(original.pid);
    if (!current || current.start !== original.start) return;
    assert(performance.now() < by, 'original owned enroll process did not retire'); await delay(20);
  }
}
async function within<T>(pending: Promise<T>, milliseconds: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([pending, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('owned enroll resources did not join')), milliseconds);
  })]); } finally { clearTimeout(timer); }
}

/** One real child lifetime; the caller supplies only its trusted disposable
 * fixture composition. The production caller fixes the original 60s budget.
 * No observation can extend it, make a timeout successful or authorize work. */
export async function runOwnedEnrollDiagnostic(input: Readonly<{
  command: { executable: string; args: readonly string[]; cwd: string; env: NodeJS.ProcessEnv };
  input: Buffer; uid: number; bootstrapImage: string; installedImage: string; originalDeadlineMs: number;
  scanner: CredentialSecretScanner; diagnostic: InstalledEnrollDiagnostic; observeOwner?: () => EnrollOwnerStage;
}>) {
  assert.equal(process.platform, 'linux');
  assert(Number.isSafeInteger(input.uid) && input.uid >= 0);
  assert(input.input.length > 0 && input.input.length <= 65536);
  assert(Number.isSafeInteger(input.originalDeadlineMs) && input.originalDeadlineMs > 0 && input.originalDeadlineMs <= 60000);
  const started = performance.now(), by = started + input.originalDeadlineMs, diagnostic = input.diagnostic;
  Object.assign(diagnostic, { diagnosticOnly: true, originalDeadlineMs: input.originalDeadlineMs, elapsedMs: 0, outcome: 'observation_failed',
    launcherObserved: false, authObserved: false, launcherJoined: false, authJoined: false, processAndPipesJoined: false,
    completeInputWriteJoined: false, samples: [], phases: [] });
  const images = await Promise.all([stat(input.bootstrapImage, { bigint: true }), stat(input.installedImage, { bigint: true })]);
  assert(images.every(image => image.isFile()));
  const scans: ReturnType<CredentialSecretScanner['openStream']>[] = [];
  try { scans.push(input.scanner.openStream()); scans.push(input.scanner.openStream()); }
  catch (error) { for (const scan of scans) scan.close(); throw error; }
  const child = (() => {
    try { return spawn(input.command.executable, [...input.command.args], { cwd: input.command.cwd, env: input.command.env,
      detached: true, stdio: ['pipe', 'pipe', 'pipe'] }); }
    catch {
      diagnostic.outcome = 'spawn_failed'; diagnostic.elapsedMs = Math.floor(performance.now() - started);
      for (const scan of scans) scan.close(); throw new Error('owned enroll launcher did not spawn');
    }
  })();
  diagnostic.outcome = 'completed';
  const streams = [child.stdin, child.stdout, child.stderr];
  const streamsClosed = Promise.all(streams.map(stream => new Promise<void>(resolve => stream.once('close', resolve))));
  let finished = false, launcher: Fact | undefined, auth: Fact | undefined;
  let failure: unknown, error: (Error & { code: string }) | undefined, stopping: Promise<void> | undefined;
  const stdout: Buffer[] = [], stderr: Buffer[] = []; let captured = 0, inputJoined = false, inputStarted = false, monitorDone = false;
  let phaseTail = Buffer.alloc(0), discardPhaseLine = false;
  const observePhases = (bytes: Buffer) => {
    // Preserve the original raw output/scanner budget independently. Only a
    // small complete source-owned marker can become retained diagnostic data.
    for (let offset = 0; offset < bytes.length;) {
      const newline = bytes.indexOf(10, offset), end = newline < 0 ? bytes.length : newline + 1;
      if (!discardPhaseLine) {
        const part = bytes.subarray(offset, end);
        if (phaseTail.length + part.length > 96) { phaseTail = Buffer.alloc(0); discardPhaseLine = true; }
        else phaseTail = Buffer.concat([phaseTail, part]);
      }
      if (newline >= 0) {
        const phase = discardPhaseLine ? undefined : decodeEnrollCredentialPhase(phaseTail);
        if (phase !== undefined && diagnostic.phases.length < 32)
          diagnostic.phases.push({ elapsedMs: Math.floor(performance.now() - started), phase });
        phaseTail.fill(0); phaseTail = Buffer.alloc(0); discardPhaseLine = false;
      }
      offset = end;
    }
  };
  let rejectRetirement!: (error: unknown) => void;
  const retirementFailed = new Promise<never>((_, reject) => { rejectRetirement = reject; });
  void retirementFailed.catch(() => {});
  const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => {
    child.once('close', (code, signal) => { finished = true; resolve({ code, signal }); });
  });
  const fail = (outcome: InstalledEnrollDiagnostic['outcome'], code: string) => {
    if (!error) { diagnostic.outcome = outcome; error = Object.assign(new Error('owned enroll command failed'), { code }); }
  };
  const retire = (): Promise<void> => stopping ??= (async () => {
    let signaled = false; const failures: unknown[] = [];
    if (auth) {
      try {
        const current = await processFact(auth.pid);
        if (current?.start === auth.start) {
          assert.deepEqual(current.uids, auth.uids); process.kill(auth.pid, 'SIGKILL'); signaled = true;
        }
      } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') failures.push(error); }
    }
    // First let the original trusted runuser reap its genuine auth child.
    if (signaled) { try { await within(joined, 5000); } catch { /* The original group fallback below still has to join. */ } }
    if (!finished && child.pid !== undefined) {
      const current = await processFact(child.pid);
      if (!launcher && current?.parent === process.pid && current.group === child.pid && current.session === child.pid) launcher = current;
      if (current) {
        assert(launcher && current.start === launcher.start && current.group === launcher.pid && current.session === launcher.pid,
          'original owned enroll launcher is unavailable for group retirement');
        try { process.kill(-launcher.pid, 'SIGKILL'); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
      }
    }
    await within(joined, 5000);
    if (failures.length) throw new AggregateError(failures, 'original owned auth retirement was uncertain');
  })();
  const stop = () => { void retire().catch(error => { failure ??= error; rejectRetirement(error); }); };
  child.once('error', () => { fail('spawn_failed', 'ESPAWN'); stop(); });
  child.stdin.on('error', () => {});
  for (const stream of [child.stdout, child.stderr]) stream.on('error', () => {
    failure ??= new Error('owned enroll output pipe failed'); fail('observation_failed', 'EPIPE'); stop();
  });
  const capture = (chunks: Buffer[], bytes: Buffer, index: number) => {
    try { scans[index]!.scan(bytes); }
    catch (error) { failure ??= error; fail('observation_failed', 'ESCAN'); stop(); return; }
    if (captured + bytes.length > 2 * 1024 * 1024) { fail('output_limit', 'ENOBUFS'); stop(); return; }
    captured += bytes.length; chunks.push(Buffer.from(bytes));
    if (index === 1) observePhases(bytes);
  };
  child.stdout.on('data', (bytes: Buffer) => capture(stdout, bytes, 0));
  child.stderr.on('data', (bytes: Buffer) => capture(stderr, bytes, 1));
  let resolveInput!: () => void;
  const inputWritten = new Promise<void>(resolve => { resolveInput = resolve; child.stdin.once('close', resolve); });
  const timer = setTimeout(() => { fail('timeout', 'ETIMEDOUT'); stop(); }, Math.max(0, by - performance.now()));
  const monitor = (async () => {
    let nextSample = started;
    while (!finished && !monitorDone) {
      let firstAuth = false;
      if (child.pid !== undefined) {
        const current = await processFact(child.pid);
        if (!launcher && current?.parent === process.pid && current.group === child.pid && current.session === child.pid) {
          launcher = current; diagnostic.launcherObserved = true;
        }
        if (current && launcher?.start === current.start) {
          let candidate: Fact | undefined = current;
          const actualImage = await stat(`/proc/${current.pid}/exe`, { bigint: true }).catch((error: NodeJS.ErrnoException) => {
            if (error.code === 'ENOENT' || error.code === 'ESRCH') return undefined; throw error;
          });
          if (!images.some(image => actualImage && image.dev === actualImage.dev && image.ino === actualImage.ino)) {
            const children = await readFile(`/proc/${current.pid}/task/${current.pid}/children`, 'utf8').catch((error: NodeJS.ErrnoException) => {
              if (error.code === 'ENOENT' || error.code === 'ESRCH') return ''; throw error;
            });
            assert(children.length <= 1024); const pids = children.trim() ? children.trim().split(/\s+/u).map(Number) : [];
            assert(pids.length <= 1, 'trusted enroll launcher must own at most its one auth child');
            candidate = pids[0] === undefined ? undefined : await processFact(pids[0]);
            if (candidate) assert.equal(candidate.parent, current.pid);
          }
          if (candidate && candidate.uids.every(uid => uid === input.uid)) {
            assert(candidate.group === launcher.pid && candidate.session === launcher.pid, 'owned auth escaped its original launcher session');
            const image = await stat(`/proc/${candidate.pid}/exe`, { bigint: true }).catch((error: NodeJS.ErrnoException) => {
              if (error.code === 'ENOENT' || error.code === 'ESRCH') return undefined; throw error;
            });
            const selectedImage = images.some(expected => image && expected.dev === image.dev && expected.ino === image.ino);
            const confirmed = await processFact(candidate.pid);
            if (confirmed) {
              assert.equal(confirmed.start, candidate.start); assert.equal(confirmed.parent, candidate.parent);
              assert.equal(confirmed.group, candidate.group); assert.equal(confirmed.session, candidate.session);
              assert.deepEqual(confirmed.uids, candidate.uids);
            }
            // runuser's fixed /usr/bin/env transition is not the signed auth.
            // Wait without writing secret input until the original real image
            // and complete current child identity have both been observed.
            if (!selectedImage || !confirmed) {
              assert(!auth || !confirmed, 'original owned auth executable image changed');
              candidate = undefined;
            }
          } else candidate = undefined;
          if (candidate) {
            if (auth) assert(candidate.pid === auth.pid && candidate.start === auth.start, 'original owned auth identity changed');
            else { auth = candidate; firstAuth = true; diagnostic.authObserved = true; }
            if (!inputStarted && !error && performance.now() < by) {
              inputStarted = true;
              child.stdin.end(input.input, (error?: Error | null) => {
                inputJoined = !error; resolveInput();
                if (error) { fail('observation_failed', 'EINPUT'); stop(); }
              });
            }
          }
        }
      }
      if (diagnostic.samples.length < 20 && (firstAuth || performance.now() >= nextSample)) {
        let observation: EnrollProcessSample = { kind: 'not_observed' };
        if (auth) {
          const current = await processFact(auth.pid);
          if (!current || current.start !== auth.start) observation = { kind: 'exited' };
          else {
            assert.deepEqual(current.uids, auth.uids);
            try {
              const actual = await stat(`/proc/${auth.pid}/exe`, { bigint: true });
              const index = images.findIndex(image => image.dev === actual.dev && image.ino === actual.ino);
              if (index >= 0) {
                const counters = decodeEnrollProcessCounters(auth.pid, current.raw, await readFile(`/proc/${auth.pid}/io`, 'utf8'));
                assert.equal((await processFact(auth.pid))?.start, auth.start);
                const { pid, startTicks, userTicks, systemTicks, rchar, syscr, readBytes } = counters;
                observation = { kind: 'observed', pid, startTicks, role: index === 0 ? 'bootstrap' : 'credential', userTicks, systemTicks, rchar, syscr, readBytes };
              } else observation = { kind: 'unavailable' };
            } catch { observation = { kind: 'unavailable' }; }
          }
        }
        let owner: EnrollOwnerStage = { kind: 'unavailable' };
        try { owner = input.observeOwner?.() ?? owner; } catch { /* Read-only diagnostic refusal is not missing authority. */ }
        diagnostic.samples.push({ elapsedMs: Math.floor(performance.now() - started), process: observation, owner });
        nextSample = started + diagnostic.samples.length * 3000;
      }
      await Promise.race([joined, delay(20)]);
    }
  })();
  void monitor.catch(error => { failure ??= error; fail('observation_failed', 'EOBSERVE'); stop(); });
  let exit: Awaited<typeof joined> | undefined;
  const cleanup: unknown[] = [];
  try {
    exit = await Promise.race([joined, retirementFailed]);
    // A late event-loop callback cannot win against the original deadline.
    if (performance.now() >= by) fail('timeout', 'ETIMEDOUT');
  } finally {
    clearTimeout(timer); monitorDone = true;
    if (!finished) { try { await retire(); } catch (error) { cleanup.push(error); } }
    try { await stopping; } catch (error) { cleanup.push(error); }
    try { await monitor; } catch (error) { cleanup.push(error); }
    if (auth) { try { await waitGone(auth); diagnostic.authJoined = true; } catch (error) { cleanup.push(error); } }
    if (launcher) { try { await waitGone(launcher); diagnostic.launcherJoined = true; } catch (error) { cleanup.push(error); } }
    for (const stream of streams) stream.destroy();
    try { await within(streamsClosed, 5000); await within(inputWritten, 5000); diagnostic.processAndPipesJoined = finished; }
    catch (error) { cleanup.push(error); }
    for (const scan of scans) scan.close();
    phaseTail.fill(0); phaseTail = Buffer.alloc(0);
    diagnostic.completeInputWriteJoined = inputJoined;
    diagnostic.elapsedMs = Math.floor(performance.now() - started);
  }
  if (failure || cleanup.length) throw new AggregateError([failure, ...cleanup].filter(Boolean), 'owned enroll command did not complete its observations and join');
  assert(exit);
  return { status: exit.code, signal: exit.signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8'), error };
}
