import { closeSync, constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { Socket } from 'node:net';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { CONTROL_FRAME_BYTES as FRAME_BYTES, INSTALLED_CONTROL_FEATURES, decodeControlFrame, decodeInstalledControlRequest, decodeInstalledControlResponse,
  controlWireText, type InstalledControlMethod, type InstalledControlRequestV1, type InstalledControlResponseFor,
  type InstalledControlResultFor } from '../kernel/control-wire.js';
import { immutableSnapshot } from '../model/immutable.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { openInstalledControlClient, withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import type { HeldInstalledControlClient } from './native-owner.js';
import { observeInstalledCredentialSupervisor, type InstalledCredentialSupervisorObservation } from './installed-services.js';

/** Internal common transport: only genuine held installed selections can open
 * it. The fixed credential purpose is the existing explicit ensure-start path;
 * normal clients observe the installed service without starting it. */
export type InstalledControlTransport = Readonly<{
  hello: InstalledControlResultFor<'control.hello'>;
  request<M extends InstalledControlMethod>(request: Extract<InstalledControlRequestV1, { method: M }>): Promise<InstalledControlResponseFor<M>>;
  close(): Promise<void>;
}>;
let retirementFailure: ResourceRetirementError | undefined;
const retainedGuards = new Set<HeldInstalledControlClient>();
function refuse(message: string, cause?: unknown): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', message, cause === undefined ? undefined : { cause });
}
function same(left: unknown, right: unknown): boolean { return canonicalJsonBytes(left).equals(canonicalJsonBytes(right)); }
function invocation(observation: InstalledCredentialSupervisorObservation): void {
  for (const unit of [observation.keeper, observation.supervisor]) {
    if (unit.ActiveState !== 'active' || unit.SubState !== 'running' || unit.MainPID < 1 || unit.MainPID !== unit.ExecMainPID ||
        unit.ControlPID !== 0 || !/^[0-9a-f]{32}$/u.test(unit.InvocationID) || !unit.ControlGroup.startsWith('/') ||
        unit.ControlGroup.split('/').includes('..') || !unit.ControlGroup.endsWith(`/${unit.Id}`))
      refuse('installed services are not in a current running invocation');
  }
}
function stable(before: InstalledCredentialSupervisorObservation, after: InstalledCredentialSupervisorObservation): void {
  invocation(after);
  if (!same(before.bus, after.bus) || !same(before.manager, after.manager) || before.uid !== after.uid || before.gid !== after.gid ||
      before.stateRoot !== after.stateRoot || [before.keeper, before.supervisor].some((unit, index) => {
        const current = [after.keeper, after.supervisor][index]!;
        return unit.Id !== current.Id || unit.MainPID !== current.MainPID || unit.ExecMainPID !== current.ExecMainPID ||
          unit.InvocationID !== current.InvocationID || unit.ControlGroup !== current.ControlGroup;
      })) refuse('installed manager or service invocation changed');
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


export async function openInstalledControlTransport(selected: HeldInstalledRuntime,
  purpose: 'control' | 'credential'): Promise<InstalledControlTransport> {
  if (purpose !== 'control' && purpose !== 'credential') throw new TypeError('invalid installed control purpose');
  if (retirementFailure) throw retirementFailure;
  // The fixed friend authenticates the selection before any caller property.
  let observed = await observeInstalledCredentialSupervisor(selected, purpose === 'credential');
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
  let running: Promise<unknown> | undefined;
  let waiter: { resolve(value: unknown): void; reject(error: unknown): void } | undefined;
  const header = Buffer.alloc(4); let headerCount = 0; let body: Buffer | undefined; let bodyCount = 0;
  const fail = (error: unknown) => {
    if (error instanceof ResourceRetirementError) { retainedGuards.add(native); retirementFailure ??= error; failure = retirementFailure; }
    else failure ??= error;
    stopped = true; waiter?.reject(failure); waiter = undefined; body = undefined; socket.destroy();
  };
  socket.on('error', () => fail(new KernelStorageError('RECOVERY_REQUIRED', 'installed control socket failed')));
  socket.on('close', () => { if (!stopped) fail(new KernelStorageError('RECOVERY_REQUIRED', 'installed control peer closed')); });
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
          const value = decodeControlFrame(body);
          const complete = waiter; waiter = undefined; body = undefined; complete.resolve(value);
        }
      }
    } catch (error) { fail(error instanceof ResourceRetirementError ? error : new KernelStorageError('RECOVERY_REQUIRED', 'installed control response or native peer is invalid')); }
  });
  const retire = (): Promise<void> => retiring ??= (async () => {
    stopped = true; waiter?.reject(failure ?? new KernelStorageError('RECOVERY_REQUIRED', 'installed control client is closing')); waiter = undefined;
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
    if (stopped || waiter || retirementFailure) throw retirementFailure ?? failure ?? new KernelStorageError('RECOVERY_REQUIRED', 'installed control connection is closed or busy');
    native.assertHeld();
    const bytes = canonicalJsonBytes(request); if (!bytes.length || bytes.length > (purpose === 'credential' ? 65536 : FRAME_BYTES)) throw new TypeError('installed control request exceeds its bound');
    const frame = Buffer.alloc(4); frame.writeUInt32BE(bytes.length);
    const response = new Promise<unknown>((resolve, reject) => { waiter = { resolve, reject }; });
    const timer = setTimeout(() => fail(new KernelStorageError('RECOVERY_REQUIRED', 'installed control response timed out')), 30000);
    try {
      const writes = [frame, bytes].map(value => new Promise<void>((resolve, reject) => {
        try { socket.write(value, error => error ? reject(new Error('installed control write failed')) : resolve()); }
        catch { reject(new Error('installed control write failed')); }
      }));
      const results = await Promise.all([response, ...writes]); native.assertHeld(); return results[0];
    } finally { clearTimeout(timer); }
  };
  const checkCurrent = async () => {
    if (stopped || retirementFailure) throw retirementFailure ?? failure ?? new KernelStorageError('RECOVERY_REQUIRED', 'installed control client is closing');
    native.assertHeld(); const current = await observeInstalledCredentialSupervisor(selected); stable(observed, current);
    await peerBinding(native, current); return current;
  };
  let helloResult: InstalledControlResultFor<'control.hello'>;
  const client: InstalledControlTransport = Object.freeze({
    get hello() { return helloResult; },
    request<M extends InstalledControlMethod>(request: Extract<InstalledControlRequestV1, { method: M }>): Promise<InstalledControlResponseFor<M>> {
      if (this !== client) return Promise.reject(new TypeError('invalid installed control client'));
      if (running || closing || stopped) return Promise.reject(new KernelStorageError('RECOVERY_REQUIRED', 'installed control client is closed or busy'));
      let candidate: InstalledControlRequestV1;
      try {
        candidate = decodeInstalledControlRequest(request);
        if (candidate.method === 'control.hello' || !helloResult.enabledFeatureIds.includes(candidate.method))
          throw new TypeError('installed control method was not enabled by this hello');
        if (purpose === 'credential' && candidate.method !== 'credential.finalize') throw new TypeError('credential connection accepts only its original continuation');
      } catch (cause) { return Promise.reject(new KernelStorageError('INVALID_REQUEST', 'invalid installed control request', { cause })); }
      const pending = (async () => {
        try {
          await checkCurrent();
          const response = decodeInstalledControlResponse(await exchange(candidate), candidate);
          await checkCurrent(); return response as InstalledControlResponseFor<M>;
        } catch (error) {
          const reason = error instanceof KernelStorageError || error instanceof ResourceRetirementError ? error
            : new KernelStorageError('RECOVERY_REQUIRED', 'installed control response is invalid');
          fail(reason); await retire(); throw reason;
        }
      })();
      running = pending; void pending.finally(() => { running = undefined; }).catch(() => {}); return pending;
    },
    close() {
      if (this !== client) return Promise.reject(new TypeError('invalid installed control client'));
      return closing ??= (async () => { fail(new KernelStorageError('RECOVERY_REQUIRED', 'installed control client is closing'));
        await Promise.allSettled(running ? [running] : []); await retire(); })();
    }
  });
  try {
    await checkCurrent();
    const requestedFeatureIds = purpose === 'credential' ? ['credential.finalize'] : [...INSTALLED_CONTROL_FEATURES];
    const request = decodeInstalledControlRequest({ protocolVersion: 1, method: 'control.hello',
      clientBuild: purpose === 'credential' ? 'cliq-installed-credential-v1' : 'cliq-installed-client-v1',
      controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 }, requestedFeatureIds });
    const response = decodeInstalledControlResponse(await exchange(request), request) as InstalledControlResponseFor<'control.hello'>;
    if (!response.ok) refuse('installed Supervisor refused the authenticated control handshake');
    const hello = response.result, bundle = hello.activeRuntimeBundle;
    if (hello.serverBuild !== 'cliq-installed-v1' || !same(hello.controlSchemaRange, { min: 1, max: 1 }) ||
        !same(hello.headlessSchemaRange, selection.headlessSchemaRange) ||
        (purpose === 'credential' && !same(hello.enabledFeatureIds, ['credential.finalize'])) ||
        bundle.runtimeBundleRef !== selection.bundleDigest || bundle.bundleDigest !== selection.bundleDigest || bundle.bundleVersion !== selection.bundleVersion)
      refuse('installed Supervisor hello is incompatible with the selected installed runtime');
    controlWireText(hello.supervisorInstanceId); helloResult = immutableSnapshot(hello);
    await checkCurrent(); return client;
  } catch (error) {
    const reason = error instanceof KernelStorageError || error instanceof ResourceRetirementError ? error
      : new KernelStorageError('RECOVERY_REQUIRED', 'installed control hello response is invalid');
    fail(reason); await retire(); throw reason;
  }
}
