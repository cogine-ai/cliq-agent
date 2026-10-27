// Qualification-only parent for the production installed-client driver. This
// owns its original JSONL child and scanned pipes, never Run/native authority.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { types } from 'node:util';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeHeadlessControlRequest, decodeHeadlessControlRecord, decodeInstalledControlResponse, headlessRunEvent,
  CONTROL_METHODS_V1, INSTALLED_CONTROL_FEATURES, type InstalledControlRequestV1, type HeadlessRunEventV3 } from '../../../src/control/v1.js';
import { INSTALLED_CLIENT_PHASES, type InstalledClientPhase } from '../../../src/state/installed-diagnostics.js';
import type { InstalledWorkSnapshot } from '../../../src/state/installed-work-diagnostics.js';
import { writeSync } from 'node:fs';
import { decodeInstalledRequestFailureMarker, installedRequestFailureMarker,
  INSTALLED_REQUEST_FAILURE_PREFIX } from './installed-client-request-failure.js';

export type InstalledClientAuthenticationObservation = Readonly<{ stage: InstalledClientPhase; elapsedMs: number;
  observedElapsedMs: number; work?: InstalledWorkSnapshot; process?: InstalledClientAuthenticationProcess }>;
/** Node resourceUsage() cumulative values for this entire process, including
 * threads. CPU times are microseconds; fsRead/fsWrite are getrusage counters,
 * never bytes, per-hash timings, per-thread usage or execution evidence. */
export type InstalledClientAuthenticationProcess = Readonly<{
  userCPUTime: number; systemCPUTime: number; fsRead: number; fsWrite: number;
}>;
const authPrefix = 'CLIQ_INSTALLED_CLIENT_AUTH_V1:';
const authProcessPrefix = 'CLIQ_INSTALLED_CLIENT_AUTH_V2:self_whole_process_cumulative:';
/** Fixed diagnostic only: never serialize a request, identifier, path or error. */
export function installedClientRequestFailureMarker(method: unknown): string {
  const name = typeof method === 'string' && (CONTROL_METHODS_V1 as readonly string[]).includes(method) ? method : 'unknown';
  return 'CLIQ_INSTALLED_REQUEST_FAILED_V1:' + name;
}
const counterKeys = ['started', 'completed', 'bytesRead', 'spanElapsedMs'] as const;
const workKeys = ['package', 'revalidate', 'createCompare'] as const;
const processKeys = ['userCPUTime', 'systemCPUTime', 'fsRead', 'fsWrite'] as const;
function fields(value: unknown, keys: readonly string[]): Record<string, PropertyDescriptor> {
  assert(typeof value === 'object' && value !== null && !Array.isArray(value) && !types.isProxy(value));
  assert([Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const descriptors = Object.getOwnPropertyDescriptors(value);
  assert.deepEqual(Reflect.ownKeys(descriptors).sort(), [...keys].sort());
  assert(Object.values(descriptors).every(field => 'value' in field && field.enumerable)); return descriptors;
}
function integer(value: unknown): number { assert(typeof value === 'number' && Number.isSafeInteger(value) && value >= 0); return value; }
export function copyInstalledClientAuthenticationProcess(value: unknown): InstalledClientAuthenticationProcess {
  const row = fields(value, processKeys);
  const [userCPUTime, systemCPUTime, fsRead, fsWrite] = processKeys.map(key => integer(row[key]!.value));
  return Object.freeze({ userCPUTime: userCPUTime!, systemCPUTime: systemCPUTime!, fsRead: fsRead!, fsWrite: fsWrite! });
}
export function copyInstalledClientAuthenticationWork(value: unknown): InstalledWorkSnapshot {
  const outer = fields(value, workKeys);
  const rows = workKeys.map(key => {
    const row = fields(outer[key]!.value, counterKeys);
    const [started, completed, bytesRead, spanElapsedMs] = counterKeys.map(field => integer(row[field]!.value));
    assert(completed! <= started! && (key !== 'createCompare' || bytesRead === 0));
    return Object.freeze({ started: started!, completed: completed!, bytesRead: bytesRead!, spanElapsedMs: spanElapsedMs! });
  });
  return Object.freeze({ package: rows[0]!, revalidate: rows[1]!, createCompare: rows[2]! });
}
/** Closed ASCII data only. No source input, request, peer text or authority. */
export function installedClientAuthenticationMarker(stage: InstalledClientPhase, elapsedMs: number, work?: InstalledWorkSnapshot,
  process?: InstalledClientAuthenticationProcess): Buffer {
  assert(typeof stage === 'string' && INSTALLED_CLIENT_PHASES.includes(stage)); integer(elapsedMs);
  const snapshot = work === undefined ? undefined : copyInstalledClientAuthenticationWork(work);
  const self = process === undefined ? undefined : copyInstalledClientAuthenticationProcess(process);
  const suffix = snapshot ? workKeys.flatMap(key => counterKeys.map(field => snapshot[key][field])).join(':') : 'none';
  const prefix = self ? authProcessPrefix : authPrefix;
  const usage = self ? ':' + processKeys.map(key => self[key]).join(':') : '';
  const bytes = Buffer.from(`${prefix}${stage}:${elapsedMs}:${suffix}${usage}\n`); assert(bytes.length <= 512); return bytes;
}
export function authMarker(bytes: Buffer): Omit<InstalledClientAuthenticationObservation, 'observedElapsedMs'> {
  assert(bytes.length <= 512 && bytes.every(byte => byte < 128));
  const text = bytes.toString('ascii'), prefix = text.startsWith(authProcessPrefix) ? authProcessPrefix : authPrefix;
  assert(text.startsWith(prefix) && text.endsWith('\n'));
  const parts = text.slice(prefix.length, -1).split(':');
  const stage = INSTALLED_CLIENT_PHASES.find(value => value === parts[0]); assert(stage);
  const number = (text: string | undefined) => { assert(text !== undefined && /^(0|[1-9][0-9]{0,15})$/u.test(text)); return integer(Number(text)); };
  const elapsedMs = number(parts[1]);
  let process: InstalledClientAuthenticationProcess | undefined;
  if (prefix === authProcessPrefix) {
    assert(parts.length === 7 && parts[2] === 'none' || parts.length === 18);
    process = copyInstalledClientAuthenticationProcess(Object.fromEntries(processKeys.map((key, index) => [key, number(parts[parts.length - 4 + index])])));
    parts.splice(-4);
  }
  const usage = process ? { process } : {};
  if (parts.length === 3 && parts[2] === 'none') return Object.freeze({ stage, elapsedMs, ...usage });
  assert.equal(parts.length, 14); const numbers = parts.slice(2).map(number);
  const row = (offset: number) => Object.fromEntries(counterKeys.map((key, index) => [key, numbers[offset + index]]));
  return Object.freeze({ stage, elapsedMs, work: copyInstalledClientAuthenticationWork({ package: row(0), revalidate: row(4), createCompare: row(8) }), ...usage });
}
function copyAuthentication(value: readonly InstalledClientAuthenticationObservation[]): readonly InstalledClientAuthenticationObservation[] {
  assert(Array.isArray(value) && !types.isProxy(value) && value.length <= INSTALLED_CLIENT_PHASES.length);
  assert(Reflect.ownKeys(value).length === value.length + 1, 'authentication array must have only its original entries');
  let previous = -1, elapsed = -1, observed = -1;
  let previousWork: InstalledWorkSnapshot | undefined;
  let previousProcess: InstalledClientAuthenticationProcess | undefined;
  const result: InstalledClientAuthenticationObservation[] = [];
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index)); assert(descriptor && descriptor.enumerable && 'value' in descriptor);
    assert(descriptor.value && typeof descriptor.value === 'object' && !types.isProxy(descriptor.value));
    const keys = Reflect.ownKeys(descriptor.value as object); assert(keys.every(key => typeof key === 'string'));
    const row = fields(descriptor.value, ['stage', 'elapsedMs', 'observedElapsedMs', ...(keys.includes('work') ? ['work'] : []),
      ...(keys.includes('process') ? ['process'] : [])]);
    const stage = row.stage!.value; assert(typeof stage === 'string');
    const order = INSTALLED_CLIENT_PHASES.findIndex(phase => phase === stage); assert(order > previous); previous = order;
    const elapsedMs = integer(row.elapsedMs!.value), observedElapsedMs = integer(row.observedElapsedMs!.value);
    assert(elapsedMs >= elapsed && observedElapsedMs >= observed); elapsed = elapsedMs; observed = observedElapsedMs;
    const work = row.work ? copyInstalledClientAuthenticationWork(row.work.value) : undefined;
    if (work && previousWork) assert(workKeys.every(key => counterKeys.every(field => work[key][field] >= previousWork![key][field])));
    if (work) previousWork = work;
    const process = row.process ? copyInstalledClientAuthenticationProcess(row.process.value) : undefined;
    if (process && previousProcess) assert(processKeys.every(key => process[key] >= previousProcess![key]));
    if (process) previousProcess = process;
    result.push(Object.freeze({ stage: INSTALLED_CLIENT_PHASES[order]!, elapsedMs, observedElapsedMs,
      ...(work ? { work } : {}), ...(process ? { process } : {}) }));
  }
  return Object.freeze(result);
}

type Scan = { scan(bytes: Uint8Array): void; close(): void };
type Response = { protocolVersion: 1; ok: boolean; method?: string;
  result?: Record<string, any>; error?: Record<string, unknown> };
type Input = { executable: string; args: readonly string[]; cwd: string; env: NodeJS.ProcessEnv;
  openScan(): Scan; onJoined(): void; timeout?: number; headlessSchemaVersion?: 3; headlessTransport?: 'rpc'; initialRequest?: InstalledControlRequestV1 };
export type InstalledClientDriverStage = 'platform' | 'composition' | 'selection' | 'authentication' | 'request' | 'output' | 'retirement';
const driverStages = ['platform', 'composition', 'selection', 'authentication', 'request', 'output', 'retirement'] as const;
const driverMarkers = driverStages.flatMap(stage => [
  { stage, failure: false, bytes: Buffer.from(`installed control client driver progress phase=${stage}\n`) },
  { stage, failure: true, bytes: Buffer.from(`installed control client driver failed phase=${stage}\n`) }
]);

export class InstalledClientDriverError extends Error {
  readonly diagnostic: Readonly<{ kind: 'installed_client_driver'; stage: InstalledClientDriverStage;
    authentication?: readonly InstalledClientAuthenticationObservation[] }>;
  constructor(stage: InstalledClientDriverStage, authentication: readonly InstalledClientAuthenticationObservation[] = []) {
    super('original installed client driver failed');
    assert(typeof stage === 'string' && driverStages.includes(stage));
    const observed = copyAuthentication(authentication);
    this.diagnostic = Object.freeze({ kind: 'installed_client_driver', stage,
      ...(observed.length ? { authentication: observed } : {}) });
  }
}

/** Source-owned bounded timing only; never input, peer diagnostics or authority. */
export class InstalledClientConsumerDeadlineError extends Error {
  readonly diagnostic: Readonly<{ kind: 'installed_client_deadline'; stage: 'ready' | 'request' | 'close';
    originalDeadlineMs: number; elapsedMs: number; frames: number;
    /** Last complete original-child marker received, not realtime state or authority. */
    lastObservedDriverStage?: InstalledClientDriverStage;
    authentication?: readonly InstalledClientAuthenticationObservation[] }>;
  constructor(stage: 'ready' | 'request' | 'close', originalDeadlineMs: number, started: number, frames: number,
    lastObservedDriverStage?: InstalledClientDriverStage, authentication: readonly InstalledClientAuthenticationObservation[] = []) {
    super('original installed client consumer deadline expired');
    assert(lastObservedDriverStage === undefined || typeof lastObservedDriverStage === 'string' &&
      driverStages.includes(lastObservedDriverStage));
    assert(Array.isArray(authentication));
    this.diagnostic = Object.freeze({ kind: 'installed_client_deadline', stage, originalDeadlineMs,
      elapsedMs: Math.floor(performance.now() - started), frames,
      ...(lastObservedDriverStage === undefined ? {} : { lastObservedDriverStage }),
      ...(authentication.length ? { authentication: copyAuthentication(authentication) } : {}) });
  }
}

async function bounded<T>(operation: Promise<T>, milliseconds: number,
  stage: 'ready' | 'request' | 'close', frames: () => number, lastObservedStage: () => InstalledClientDriverStage | undefined,
  originalDeadlineMs = milliseconds, started = performance.now(), authentication: () => readonly InstalledClientAuthenticationObservation[] = () => []): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([operation, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new InstalledClientConsumerDeadlineError(stage, originalDeadlineMs, started, frames(), lastObservedStage(), authentication())), milliseconds);
  })]); } finally { clearTimeout(timer); }
}

export async function openInstalledClientConsumer(input: Input) {
  assert(input.headlessSchemaVersion === undefined || input.headlessSchemaVersion === 3);
  assert(input.headlessTransport === undefined || input.headlessSchemaVersion === 3 && input.headlessTransport === 'rpc');
  assert(input.initialRequest === undefined || input.headlessSchemaVersion === 3 && input.headlessTransport === undefined &&
    ['run.get', 'session.get', 'run.list', 'authorization.list', 'run.submit'].includes(input.initialRequest.method));
  const timeout = input.timeout ?? 5000;
  assert(Number.isSafeInteger(timeout) && timeout > 0 && timeout <= 5000);
  const by = performance.now() + timeout;
  const outScan = input.openScan(); let errorScan: Scan;
  try { errorScan = input.openScan(); } catch (error) { outScan.close(); throw error; }
  let child;
  try { child = spawn(input.executable, [...input.args], { cwd: input.cwd, env: input.env, stdio: ['pipe', 'pipe', 'pipe'] }); }
  catch (error) { outScan.close(); errorScan.close(); throw error; }
  let output = Buffer.alloc(0), errorBytes = 0, failure: unknown, frames = 0;
  let errorTail = Buffer.alloc(0), markerBytes = 0, lastObservedDriverStage: InstalledClientDriverStage | undefined;
  const observedStages = new Set<InstalledClientDriverStage>(), lastObservedStage = () => lastObservedDriverStage;
  const authentication: InstalledClientAuthenticationObservation[] = [];
  let requestFailureObserved = false;
  let pending: { method: string; request?: InstalledControlRequestV1; page?: Response; events?: HeadlessRunEventV3[];
    attachTarget?: number; attachLimit?: number; rpcId?: number; rpcDrained?: boolean; rpcLast?: Response;
    resolve(value: Response): void; reject(error: unknown): void } | undefined;
  // Exactly one predetermined CLI invocation may finish before the parent
  // resumes from hello. Register its original closed request before any child
  // bytes are consumed; this never sends/replays a business request.
  const initialResponse = input.initialRequest === undefined ? undefined : new Promise<Response>((resolve, reject) => {
    const request = decodeHeadlessControlRequest({ schemaVersion: 3, request: input.initialRequest }).request;
    pending = { method: request.method, request, resolve, reject };
  });
  void initialResponse?.catch(() => {});
  let readyResolve!: (value: Response) => void, readyReject!: (error: unknown) => void;
  const ready = new Promise<Response>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const refuse = (error: unknown) => { failure ??= error; readyReject(error); pending?.reject(error); };
  const finishPage = () => {
    assert(pending?.page && !pending.events?.length);
    const response = pending.page, original = pending;
    if (pending.method === 'run.attach' && pending.request?.method === 'run.attach') {
      if (response.ok) {
        pending.attachTarget ??= response.result!.highWaterEventSeq;
        pending.attachLimit ??= pending.request.limit;
        assert(response.result!.nextEventSeq <= pending.attachTarget!);
        if (response.result!.nextEventSeq < pending.attachTarget!) {
          assert(response.result!.nextEventSeq > pending.request.afterEventSeq);
          pending.request = { ...pending.request, afterEventSeq: response.result!.nextEventSeq,
            limit: Math.min(pending.attachLimit!, pending.attachTarget! - response.result!.nextEventSeq) };
          pending.page = undefined; return;
        }
      }
    }
    if (input.headlessTransport === 'rpc') {
      pending.rpcLast = response; pending.rpcDrained = true; pending.page = undefined; return;
    }
    pending = undefined; original.resolve(response);
  };
  child.stdout.on('data', (bytes: Buffer) => {
    try {
      outScan.scan(bytes); output = Buffer.concat([output, bytes]); assert(output.length <= 2 * 1048580);
      for (;;) {
        const at = output.indexOf(10); if (at < 0) { assert(output.length <= 1048576); break; }
        assert(at > 0 && at <= 1048576); const line = output.subarray(0, at); output = output.subarray(at + 1);
        const decoded = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(line));
        assert(canonicalJsonBytes(decoded).equals(line)); assert(++frames <= 1024);
        let application = decoded, rpcFinal = false;
        if (input.headlessTransport === 'rpc') {
          const rpc = decoded as Record<string, any>; assert.equal(rpc?.jsonrpc, '2.0');
          if (rpc.method === 'control.record') {
            assert.deepEqual(Object.keys(rpc).sort(), ['jsonrpc', 'method', 'params']);
            assert.deepEqual(Object.keys(rpc.params).sort(), ['id', 'record']);
            assert(pending?.method === 'run.attach' && rpc.params.id === pending.rpcId && !pending.rpcDrained);
            application = rpc.params.record;
          } else {
            assert.deepEqual(Object.keys(rpc).sort(), ['id', 'jsonrpc', 'result']);
            assert.equal(rpc.id, frames === 1 ? 0 : pending?.rpcId); rpcFinal = true; application = rpc.result;
          }
        }
        let response: Response;
        if (input.headlessSchemaVersion === 3) {
          const record = decodeHeadlessControlRecord(application);
          if (record.type !== 'response') {
            assert(!rpcFinal, 'a final RPC result must contain its authoritative response');
            assert(pending?.method === 'run.attach' && pending.events?.length, 'unexpected schema3 display record');
            assert(canonicalJsonBytes(record).equals(canonicalJsonBytes(pending.events.shift())), 'display event differs from its original committed page');
            if (!pending.events.length) finishPage();
            continue;
          }
          // Validation copies/freezes data for production consumers. This
          // campaign must retain the original strict-parsed wire value so
          // raw v1 and schema3 replay comparisons see the same representation.
          response = (application as { response: Response }).response;
        } else response = decoded as Response;
        assert.equal(response.protocolVersion, 1); assert.equal(typeof response.ok, 'boolean');
        if (frames === 1) {
          assert.deepEqual(Object.keys(response).sort(), ['ok', 'protocolVersion', 'result']);
          assert.equal(response.ok, true); assert.equal(response.result?.method, 'control.hello');
          assert.equal(typeof response.result.supervisorInstanceId, 'string');
          if (input.headlessSchemaVersion === 3) assert(response.result.headlessSchemaRange.min <= 3 && response.result.headlessSchemaRange.max >= 3);
          readyResolve(response); continue;
        }
        assert(pending, 'installed client driver emitted an unsolicited response');
        if (rpcFinal && pending.rpcDrained) {
          assert(canonicalJsonBytes(response).equals(canonicalJsonBytes(pending.rpcLast)));
          const original = pending; pending = undefined; original.resolve(response); continue;
        }
        if (response.ok) assert.equal(response.result?.method, pending.method);
        else assert.equal(response.method, pending.method);
        if (input.headlessSchemaVersion === 3) {
          assert(pending.request && !pending.page && !pending.events?.length, 'overlapping schema3 pages');
          decodeInstalledControlResponse(response, pending.request);
          pending.page = response;
          pending.events = response.ok && response.result!.method === 'run.attach' ? response.result!.events.map(headlessRunEvent) : [];
          if (rpcFinal) {
            assert(pending.method !== 'run.attach', 'RPC attach must retain every page/display notification before its final result');
            const original = pending; pending = undefined; original.resolve(response);
          } else if (!pending.events!.length) finishPage();
        } else { const original = pending; pending = undefined; original.resolve(response); }
      }
    } catch (error) { refuse(error); }
  });
  child.stderr.on('data', (bytes: Buffer) => {
    try {
      errorScan.scan(bytes); errorBytes += bytes.length; assert(errorBytes <= 65536);
      // Scan every original byte before accepting only exact source-owned
      // marker lines. A split line must remain a prefix of that finite set.
      errorTail = Buffer.concat([errorTail, bytes]);
      for (;;) {
        const at = errorTail.indexOf(10);
        if (at < 0) {
          const authText = errorTail.toString('ascii');
          assert(driverMarkers.some(marker => errorTail.length < marker.bytes.length &&
            marker.bytes.subarray(0, errorTail.length).equals(errorTail)) || errorTail.length <= 512 &&
            errorTail.every(byte => byte < 128) && [authPrefix, authProcessPrefix, INSTALLED_REQUEST_FAILURE_PREFIX].some(prefix =>
              prefix.startsWith(authText) || authText.startsWith(prefix)), 'unknown installed client stderr');
          break;
        }
        const line = errorTail.subarray(0, at + 1), marker = driverMarkers.find(value => value.bytes.equals(line));
        errorTail = errorTail.subarray(at + 1);
        if (!marker) {
          if (line.subarray(0, INSTALLED_REQUEST_FAILURE_PREFIX.length).toString('ascii') === INSTALLED_REQUEST_FAILURE_PREFIX) {
            assert(!requestFailureObserved, 'duplicate fixed request failure');
            const observation = decodeInstalledRequestFailureMarker(line);
            requestFailureObserved = true; markerBytes += line.length;
            // errorScan already scanned every original byte above. Log only
            // the closed canonical projection; never the original exception.
            try { writeSync(2, installedRequestFailureMarker(observation)); } catch { /* Diagnosis cannot replace the original failure. */ }
            continue;
          }
          const auth = authMarker(line);
          const observation = { ...auth, observedElapsedMs: Math.floor(performance.now() - (by - timeout)) };
          copyAuthentication([...authentication, observation]); authentication.push(Object.freeze(observation)); markerBytes += line.length; continue;
        }
        markerBytes += line.length;
        if (marker.failure) {
          // The original bytes were scanned above. Retain only this exact
          // source-owned marker so a failed child keeps its fixed stage even
          // when the outer journey preserves only closed exception frames.
          try { writeSync(2, marker.bytes); } catch { /* Diagnosis cannot replace the original failure or join. */ }
          refuse(new InstalledClientDriverError(marker.stage, authentication));
        }
        else {
          assert(!observedStages.has(marker.stage), 'duplicate installed client progress');
          observedStages.add(marker.stage); lastObservedDriverStage = marker.stage;
        }
      }
    }
    catch (error) { errorTail = Buffer.alloc(0); refuse(error); }
  });
  child.once('error', refuse); child.stdin.on('error', refuse); child.stdout.on('error', refuse); child.stderr.on('error', refuse);
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => child.once('close', (code, signal) => {
    try { outScan.close(); } catch (error) { refuse(error); }
    try { errorScan.close(); } catch (error) { refuse(error); }
    if (errorTail.length) refuse(new Error('truncated installed client stderr'));
    errorTail = Buffer.alloc(0);
    if (frames === 0 || pending) refuse(new Error('original installed client driver closed before its response'));
    resolve({ code, signal });
  }));
  let closing: Promise<void> | undefined;
  const close = () => closing ??= (async () => {
    child.stdin.end(); let exit: Awaited<typeof closed>;
    try { exit = await bounded(closed, 10000, 'close', () => frames, lastObservedStage, 10000, performance.now(), () => authentication); }
    catch (error) {
      child.kill('SIGKILL');
      // The outer disposable-UID coordinator still owns uncertain descendants.
      // A wrapper exit without original inherited pipe join is never success.
      try { await bounded(closed, 10000, 'close', () => frames, lastObservedStage, 10000, performance.now(), () => authentication); }
      catch (joinError) { throw new AggregateError([error, joinError], 'installed client consumer did not retire'); }
      throw error;
    }
    assert.equal(exit.code, 0); assert.equal(exit.signal, null); assert.equal(failure, undefined);
    assert.equal(output.length, 0); assert.equal(errorBytes, markerBytes); input.onJoined();
  })();
  let correlation = 0;
  const send = async (value: Record<string, unknown>, milliseconds = 5000): Promise<Response> => {
    assert(input.initialRequest === undefined, 'a one-shot invocation never sends another command');
    assert(!pending && !failure && !closing && frames >= 1 && frames < 1024);
    assert(Number.isSafeInteger(milliseconds) && milliseconds > 0 && milliseconds <= 30000);
    const by = performance.now() + milliseconds;
    const method = value.method;
    assert.equal(typeof method, 'string'); assert.notEqual(method, 'control.hello');
    const wrapped = input.headlessSchemaVersion === 3 ? decodeHeadlessControlRequest({ schemaVersion: 3, request: value }) : undefined;
    const rpcId = input.headlessTransport === 'rpc' ? ++correlation : undefined;
    const bytes = canonicalJsonBytes(rpcId === undefined ? wrapped ?? value
      : { jsonrpc: '2.0', id: rpcId, method, params: wrapped });
    assert(bytes.length > 0 && bytes.length <= 1048576);
    const reply = new Promise<Response>((resolve, reject) => { pending = { method: method as string,
      ...(wrapped ? { request: wrapped.request } : {}), ...(rpcId === undefined ? {} : { rpcId }), resolve, reject }; });
    child.stdin.write(Buffer.concat([bytes, Buffer.from('\n')]));
    try { const response = await bounded(reply, milliseconds, 'request', () => frames, lastObservedStage, milliseconds, performance.now(), () => authentication); assert(performance.now() < by); return response; }
    catch (error) {
      try {
        const marker = installedClientRequestFailureMarker(method), scan = input.openScan();
        try { scan.scan(Buffer.from(marker + '\n')); } finally { scan.close(); }
        console.error(marker);
      } catch { /* Preserve the original failure and never emit an unscanned marker. */ }
      refuse(error); throw error;
    }
  };
  if (input.headlessTransport === 'rpc') {
    const params = decodeHeadlessControlRequest({ schemaVersion: 3, request: { protocolVersion: 1, method: 'control.hello',
      clientBuild: 'cliq-installed-rpc-v3', controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 3, max: 3 },
      requestedFeatureIds: [...INSTALLED_CONTROL_FEATURES] } });
    const bytes = canonicalJsonBytes({ jsonrpc: '2.0', id: 0, method: 'control.hello', params });
    assert(bytes.length > 0 && bytes.length <= 1048576); child.stdin.write(Buffer.concat([bytes, Buffer.from('\n')]));
  }
  try {
    const remaining = by - performance.now(); assert(remaining > 0);
    const greeting = await bounded(Promise.race([ready, closed.then(() => {
      throw new Error('original installed client driver closed before readiness');
    })]), Math.ceil(remaining), 'ready', () => frames, lastObservedStage, timeout, by - timeout, () => authentication);
    assert(performance.now() < by);
    const initialCompleted = initialResponse ? bounded(initialResponse, Math.ceil(by - performance.now()), 'request', () => frames,
      lastObservedStage, timeout, by - timeout, () => authentication).catch(error => { refuse(error); throw error; }) : undefined;
    void initialCompleted?.catch(() => {});
    return Object.freeze({ send, close, ...(initialCompleted ? { initialResponse: initialCompleted } : {}), hello: greeting.result!, supervisorInstanceId: greeting.result!.supervisorInstanceId as string });
  } catch (error) { refuse(error); try { await close(); } catch {} throw error; }
}
