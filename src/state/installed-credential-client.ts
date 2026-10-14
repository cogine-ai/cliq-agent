import { closeSync, constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { Socket } from 'node:net';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, normalizeCanonicalText } from '../kernel/canonical.js';
import { decodeCredentialAuthorityOperation, type CredentialAuthorityOperationV1 } from '../kernel/credential-authority.js';
import { assertRequestId } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { immutableSnapshot } from '../model/immutable.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { openInstalledControlClient, withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import type { HeldInstalledControlClient } from './native-owner.js';
import { observeInstalledCredentialSupervisor, type InstalledCredentialSupervisorObservation } from './installed-services.js';

/** Continuation of the original credential operation, not MutationBase or a
 * new control-request ledger. Every other producer/authority field is absent. */
export type CredentialFinalizeRequest = Readonly<{ protocolVersion: 1; method: 'credential.finalize';
  requestId: string; operationId: string; attempt: 1 | 2 | 3; commandDigest: string }>;
export type InstalledCredentialSupervisor = Readonly<{
  finalize(request: CredentialFinalizeRequest): Promise<CredentialAuthorityOperationV1>;
  close(): Promise<void>;
}>;
const FRAME_BYTES = 1024 * 1024;
let retirementFailure: ResourceRetirementError | undefined;
const retainedGuards = new Set<HeldInstalledControlClient>();
function refuse(message: string, cause?: unknown): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', message, cause === undefined ? undefined : { cause });
}
function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('invalid installed control record');
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !Object.hasOwn(fields, key) || !Object.hasOwn(fields[key]!, 'value') || !fields[key]!.enumerable))
    throw new TypeError('invalid installed control fields');
  return value as Record<string, unknown>;
}
function text(value: unknown): string {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 128 || normalizeCanonicalText(value) !== value)
    throw new TypeError('invalid installed control text');
  return value;
}
function finalizeRequest(value: CredentialFinalizeRequest): CredentialFinalizeRequest {
  const request = exact(value, ['protocolVersion', 'method', 'requestId', 'operationId', 'attempt', 'commandDigest']);
  if (request.protocolVersion !== 1 || request.method !== 'credential.finalize' || typeof request.requestId !== 'string' ||
      typeof request.operationId !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(request.operationId) ||
      ![1, 2, 3].includes(request.attempt as number) || typeof request.commandDigest !== 'string' || !/^[0-9a-f]{64}$/u.test(request.commandDigest))
    throw new TypeError('invalid original credential continuation');
  assertRequestId(request.requestId); return immutableSnapshot(request) as CredentialFinalizeRequest;
}
function same(left: unknown, right: unknown): boolean { return canonicalJsonBytes(left).equals(canonicalJsonBytes(right)); }
function invocation(observation: InstalledCredentialSupervisorObservation): void {
  for (const unit of [observation.keeper, observation.supervisor]) {
    if (unit.ActiveState !== 'active' || unit.SubState !== 'running' || unit.MainPID < 1 || unit.MainPID !== unit.ExecMainPID ||
        unit.ControlPID !== 0 || !/^[0-9a-f]{32}$/u.test(unit.InvocationID) || !unit.ControlGroup.startsWith('/') ||
        unit.ControlGroup.split('/').includes('..') || !unit.ControlGroup.endsWith(`/${unit.Id}`))
      refuse('installed credential services are not in a current running invocation');
  }
}
function stable(before: InstalledCredentialSupervisorObservation, after: InstalledCredentialSupervisorObservation): void {
  invocation(after);
  if (!same(before.bus, after.bus) || !same(before.manager, after.manager) || before.uid !== after.uid || before.gid !== after.gid ||
      before.stateRoot !== after.stateRoot || [before.keeper, before.supervisor].some((unit, index) => {
        const current = [after.keeper, after.supervisor][index]!;
        return unit.Id !== current.Id || unit.MainPID !== current.MainPID || unit.ExecMainPID !== current.ExecMainPID ||
          unit.InvocationID !== current.InvocationID || unit.ControlGroup !== current.ControlGroup;
      })) refuse('installed credential manager or service invocation changed');
}

/** Actual peer PID comes only from the held native socket. Its native check
 * fences lifetime and the selected original image before and after this read. */
async function peerBinding(native: HeldInstalledControlClient, observation: InstalledCredentialSupervisorObservation): Promise<void> {
  native.assertHeld(); invocation(observation);
  if (native.server.pid !== observation.supervisor.MainPID || native.server.uid !== observation.uid || native.server.gid !== observation.gid)
    refuse('connected installed Supervisor differs from its current manager invocation');
  const handle = await open(`/proc/${native.server.pid}/cgroup`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const bytes = Buffer.alloc(8193); let count = 0;
    for (;;) {
      const read = await handle.read(bytes, count, bytes.length - count, null); count += read.bytesRead;
      if (count === bytes.length) refuse('installed Supervisor cgroup observation exceeds its bound');
      if (!read.bytesRead) break;
    }
    const lines = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, count)).trim().split('\n').filter(line => line.startsWith('0::'));
    const group = observation.supervisor.ControlGroup;
    if (lines.length !== 1 || (lines[0] !== `0::${group}` && !lines[0]!.startsWith(`0::${group}/`)))
      refuse('connected installed Supervisor is outside its current manager cgroup');
    native.assertHeld();
  } finally {
    try { await handle.close(); }
    catch (error) { retirementFailure ??= new ResourceRetirementError('installed peer observation descriptor did not retire', error); throw retirementFailure; }
  }
}

/** Pure wire-data decoder; accepting data here confers no peer or authority. */
export function decodeInstalledCredentialControlResult(response: unknown, method: 'control.hello' | 'credential.finalize'): Record<string, unknown> {
  const value = response as Record<string, unknown>;
  if (value?.ok === false) {
    exact(value, ['protocolVersion', 'ok', 'method', 'error']);
    if (value.protocolVersion !== 1 || value.method !== method) throw new TypeError('unexpected installed control refusal');
    const error = value.error as Record<string, unknown>; const code = text(error?.code);
    const extra = code === 'INVALID_REQUEST' ? ['issues'] : code === 'INTERNAL' ? ['errorId'] :
      code === 'INCOMPATIBLE_PROTOCOL' ? ['supportedControlRange', 'supportedHeadlessRange', 'upgradeAction'] : [];
    exact(error, ['schemaVersion', 'code', 'retryable', 'messageCode', ...extra]);
    if (error.schemaVersion !== 1 || error.retryable !== false || !['INVALID_REQUEST', 'INTERNAL', 'INCOMPATIBLE_PROTOCOL',
      'NOT_FOUND', 'AUTHORIZATION_REQUIRED', 'ARTIFACT_MISMATCH', 'UNSUPPORTED_PLATFORM', 'REQUEST_ID_CONFLICT'].includes(code))
      throw new TypeError('invalid installed control refusal');
    const messageCode = text(error.messageCode);
    // A refusal never imports remote messages/payloads into diagnostics. No
    // false retry/ledger identity is synthesized from an INTERNAL response.
    if (method === 'credential.finalize' && code === 'AUTHORIZATION_REQUIRED') {
      if (messageCode === 'credential.finalize.noncausal_time')
        refuse('installed Supervisor refused credential finalization because its timestamps are not causal');
      if (messageCode === 'credential.finalize.expired')
        refuse('installed Supervisor refused expired credential finalization');
    }
    refuse('installed Supervisor refused the authenticated credential operation');
  }
  exact(value, ['protocolVersion', 'ok', 'result']);
  if (value.protocolVersion !== 1 || value.ok !== true || value.result === null || typeof value.result !== 'object' || Array.isArray(value.result))
    throw new TypeError('invalid installed control response');
  const answer = value.result as Record<string, unknown>;
  if (answer.method !== method) throw new TypeError('installed control response method differs'); return answer;
}

export async function ensureInstalledCredentialSupervisor(selected: HeldInstalledRuntime): Promise<InstalledCredentialSupervisor> {
  if (retirementFailure) throw retirementFailure;
  // The fixed friend authenticates the selection before any caller property.
  let observed = await observeInstalledCredentialSupervisor(selected, true);
  const deadline = performance.now() + 30000;
  for (;;) {
    const socket = await lstat(path.join(observed.stateRoot, 'runtime/control-v1.sock')).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return undefined; throw error;
    });
    if (socket?.isSocket() && observed.supervisor.ActiveState === 'active' && observed.keeper.ActiveState === 'active') break;
    if (performance.now() >= deadline || [observed.supervisor, observed.keeper].some(unit => unit.ActiveState === 'failed'))
      refuse('installed Supervisor startup did not reach authenticated readiness');
    await delay(20); observed = await observeInstalledCredentialSupervisor(selected);
  }
  invocation(observed);
  const selection = await withHeldInstalledRuntime(selected, async installed => immutableSnapshot({
    bundleDigest: installed.bundleDigest, bundleVersion: installed.bundle.bundleVersion, headlessSchemaRange: installed.bundle.headlessSchemaRange }));
  const native = await openInstalledControlClient(selected);
  let socket: Socket;
  let fd: number | undefined;
  try {
    fd = native.takeSocketFd(); socket = new Socket({ fd, readable: true, writable: true }); fd = undefined;
  } catch (cause) {
    if (cause instanceof ResourceRetirementError) { retainedGuards.add(native); retirementFailure ??= cause; throw retirementFailure; }
    if (fd !== undefined) {
      try { closeSync(fd); }
      catch (error) { retainedGuards.add(native); retirementFailure ??= new ResourceRetirementError('installed control transferred descriptor did not retire', new AggregateError([cause, error])); throw retirementFailure; }
    }
    try { native.close(); } catch (error) { retainedGuards.add(native); retirementFailure ??= new ResourceRetirementError('installed native control acquisition did not retire', new AggregateError([cause, error])); throw retirementFailure; }
    throw cause;
  }
  const socketClosed = new Promise<void>(resolve => socket.once('close', () => resolve()));
  let failure: unknown; let stopped = false; let retiring: Promise<void> | undefined; let closing: Promise<void> | undefined;
  let running: Promise<CredentialAuthorityOperationV1> | undefined;
  let waiter: { resolve(value: unknown): void; reject(error: unknown): void } | undefined;
  const header = Buffer.alloc(4); let headerCount = 0; let body: Buffer | undefined; let bodyCount = 0;
  const fail = (error: unknown) => {
    if (error instanceof ResourceRetirementError) { retainedGuards.add(native); retirementFailure ??= error; failure = retirementFailure; }
    else failure ??= error;
    stopped = true; waiter?.reject(failure); waiter = undefined; body = undefined; socket.destroy();
  };
  socket.on('error', () => fail(new KernelStorageError('RECOVERY_REQUIRED', 'installed credential control socket failed')));
  socket.on('close', () => { if (!stopped) fail(new KernelStorageError('RECOVERY_REQUIRED', 'installed credential control peer closed')); });
  socket.on('data', (chunk: Buffer) => {
    if (stopped) return;
    try {
      let offset = 0;
      while (offset < chunk.length) {
        if (!waiter) throw new TypeError('unsolicited installed control response');
        if (!body) {
          const count = Math.min(4 - headerCount, chunk.length - offset); chunk.copy(header, headerCount, offset, offset + count);
          offset += count; headerCount += count; if (headerCount < 4) continue;
          const length = header.readUInt32BE(0); if (length < 1 || length > FRAME_BYTES) throw new TypeError('invalid installed response bound');
          body = Buffer.alloc(length); bodyCount = 0; headerCount = 0;
        }
        const count = Math.min(body.length - bodyCount, chunk.length - offset); chunk.copy(body, bodyCount, offset, offset + count);
        offset += count; bodyCount += count;
        if (bodyCount === body.length) {
          native.assertHeld();
          const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(body));
          if (!canonicalJsonBytes(value).equals(body)) throw new TypeError('noncanonical installed control response');
          const complete = waiter; waiter = undefined; body = undefined; complete.resolve(value);
        }
      }
    } catch (error) { fail(error instanceof ResourceRetirementError ? error : new KernelStorageError('RECOVERY_REQUIRED', 'installed credential response or native peer is invalid')); }
  });
  const retire = (): Promise<void> => retiring ??= (async () => {
    stopped = true; waiter?.reject(failure ?? new KernelStorageError('RECOVERY_REQUIRED', 'installed credential client is closing')); waiter = undefined;
    socket.destroy(); let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([socketClosed, new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('installed control socket did not join')), 5000);
      })]);
    } catch (error) { retainedGuards.add(native); retirementFailure ??= new ResourceRetirementError('installed control socket retirement is uncertain; native guards retained', error); throw retirementFailure; }
    finally { clearTimeout(timer); }
    if (retirementFailure) { retainedGuards.add(native); throw retirementFailure; }
    try { native.close(); }
    catch (error) { retainedGuards.add(native); retirementFailure ??= error instanceof ResourceRetirementError ? error : new ResourceRetirementError('installed native control descriptors did not retire', error); throw retirementFailure; }
  })();
  const exchange = async (request: object): Promise<unknown> => {
    if (stopped || waiter || retirementFailure) throw retirementFailure ?? failure ?? new KernelStorageError('RECOVERY_REQUIRED', 'installed credential connection is closed or busy');
    native.assertHeld();
    const bytes = canonicalJsonBytes(request); if (!bytes.length || bytes.length > 65536) throw new TypeError('installed credential request exceeds its bound');
    const frame = Buffer.alloc(4); frame.writeUInt32BE(bytes.length);
    const response = new Promise<unknown>((resolve, reject) => { waiter = { resolve, reject }; });
    const timer = setTimeout(() => fail(new KernelStorageError('RECOVERY_REQUIRED', 'installed credential response timed out')), 30000);
    try {
      const writes = [frame, bytes].map(value => new Promise<void>((resolve, reject) => {
        try { socket.write(value, error => error ? reject(new Error('installed control write failed')) : resolve()); }
        catch { reject(new Error('installed control write failed')); }
      }));
      const results = await Promise.all([response, ...writes]); native.assertHeld(); return results[0];
    } finally { clearTimeout(timer); }
  };
  const checkCurrent = async () => {
    if (stopped || retirementFailure) throw retirementFailure ?? failure ?? new KernelStorageError('RECOVERY_REQUIRED', 'installed credential client is closing');
    native.assertHeld(); const current = await observeInstalledCredentialSupervisor(selected); stable(observed, current);
    await peerBinding(native, current); return current;
  };
  const client: InstalledCredentialSupervisor = Object.freeze({
    finalize(request) {
      if (this !== client) return Promise.reject(new TypeError('invalid installed credential client'));
      if (running || closing || stopped) return Promise.reject(new KernelStorageError('RECOVERY_REQUIRED', 'installed credential client is closed or busy'));
      let candidate: CredentialFinalizeRequest;
      try { candidate = finalizeRequest(request); } catch (error) { return Promise.reject(new KernelStorageError('INVALID_REQUEST', 'invalid original credential continuation', { cause: error })); }
      running = (async () => {
        try {
          await checkCurrent(); const response = decodeInstalledCredentialControlResult(await exchange(candidate), 'credential.finalize');
          exact(response, ['method', 'operation']); const operation = decodeCredentialAuthorityOperation(response.operation);
          if (operation.phase !== 'committed' || operation.operationId !== candidate.operationId || operation.requestId !== candidate.requestId ||
              operation.attempt !== candidate.attempt || operation.requestDigest !== candidate.commandDigest)
            refuse('installed credential finalization did not return the original committed operation');
          await checkCurrent(); return immutableSnapshot(operation);
        } catch (error) {
          const failure = error instanceof KernelStorageError ? error : new KernelStorageError('RECOVERY_REQUIRED', 'installed credential finalization response is invalid');
          fail(failure); await retire(); throw failure;
        }
      })();
      const pending = running; void pending.finally(() => { running = undefined; }).catch(() => {}); return pending;
    },
    close() {
      if (this !== client) return Promise.reject(new TypeError('invalid installed credential client'));
      return closing ??= (async () => { fail(new KernelStorageError('RECOVERY_REQUIRED', 'installed credential client is closing'));
        await Promise.allSettled(running ? [running] : []); await retire(); })();
    }
  });
  try {
    await checkCurrent();
    const hello = decodeInstalledCredentialControlResult(await exchange({ protocolVersion: 1, method: 'control.hello', clientBuild: 'cliq-installed-credential-v1',
      controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 }, requestedFeatureIds: ['credential.finalize'] }), 'control.hello');
    exact(hello, ['method', 'protocolVersion', 'serverBuild', 'controlSchemaRange', 'enabledFeatureIds', 'supervisorInstanceId', 'activeRuntimeBundle', 'headlessSchemaRange']);
    const bundle = exact(hello.activeRuntimeBundle, ['schemaVersion', 'runtimeBundleRef', 'bundleDigest', 'bundleVersion']);
    if (hello.protocolVersion !== 1 || text(hello.serverBuild) !== 'cliq-installed-v1' || !same(hello.controlSchemaRange, { min: 1, max: 1 }) ||
        !same(hello.headlessSchemaRange, selection.headlessSchemaRange) || !same(hello.enabledFeatureIds, ['credential.finalize']) ||
        bundle.schemaVersion !== 1 || bundle.runtimeBundleRef !== selection.bundleDigest || bundle.bundleDigest !== selection.bundleDigest ||
        bundle.bundleVersion !== selection.bundleVersion) refuse('installed Supervisor hello is incompatible with credential finalization');
    text(hello.supervisorInstanceId); await checkCurrent(); return client;
  } catch (error) {
    const failure = error instanceof KernelStorageError ? error : new KernelStorageError('RECOVERY_REQUIRED', 'installed credential hello response is invalid');
    fail(failure); await retire(); throw failure;
  }
}
