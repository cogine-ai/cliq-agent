import { randomUUID } from 'node:crypto';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { normalizeBoundedText, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { RunSnapshotV1, SessionSnapshotV1, ControlResultV1 } from '../kernel/types.js';
import type { LocalControlConnection } from './control-channel.js';
import { EventCursorExpiredError, type ReadControlRequest, type ReadControlResult } from './control-read.js';
import { CredentialFinalizationTimeError, InstalledModelAuthorizationError, KernelStorageError, ResourceRetirementError } from './errors.js';
import type { StateStore } from './store.js';
import type { CredentialAuthorityOperationV1 } from '../kernel/credential-authority.js';
import type { CredentialFinalizeRequest } from './installed-credential-client.js';
import { InstalledRunAuthorityError } from './installed-run.js';
import { InstalledRunCapacityError } from './installed-run-capacity.js';

export type RuntimeBundlePublicSummaryV1 = Readonly<{
  schemaVersion: 1;
  runtimeBundleRef: string;
  bundleDigest: string;
  bundleVersion: string;
}>;

export type SupervisorHelloV1 = Readonly<{
  supervisorInstanceId: string;
  activeRuntimeBundle: RuntimeBundlePublicSummaryV1;
  headlessSchemaRange: Readonly<{ min: number; max: number }>;
}>;

export type SupervisorStatusV1 = Readonly<{
  method: 'supervisor.status';
  health: 'starting' | 'ready' | 'draining' | 'degraded';
  supervisorInstanceId: string;
  queue: Readonly<{ queuedRuns: number; runningRuns: number; capacity: number }>;
  stateSchemaVersion: number;
  activeRuntimeBundle: RuntimeBundlePublicSummaryV1;
  installedRuntimeBundles: readonly RuntimeBundlePublicSummaryV1[];
  incompatiblePinnedRunCount: number;
}>;

export type InstalledControlService = Readonly<{ close(): Promise<void> }>;

const METHODS = ['control.hello', 'session.create', 'session.list', 'session.get', 'session.fork',
  'session.compact', 'session.handoff.create', 'run.submit', 'run.list', 'run.get', 'run.attach',
  'run.cancel', 'run.approve', 'run.input', 'run.reconcile', 'run.diff', 'run.result', 'run.apply',
  'authorization.create', 'authorization.list', 'authorization.revoke', 'mcp.register',
  'mcp.refresh', 'mcp.list', 'artifact.get', 'supervisor.status', 'credential.finalize'] as const;
export type ControlMethodV1 = typeof METHODS[number];
type Range = { min: number; max: number };
type HelloRequest = { protocolVersion: 1; method: 'control.hello'; clientBuild: string;
  controlSchemaRange: Range; headlessSchemaRange: Range; requestedFeatureIds: string[] };
export type InstalledControlResultV1 = ReadControlResult | Extract<ControlResultV1, { method: 'session.create' | 'run.submit' | 'run.cancel' }> |
  SupervisorStatusV1 | { method: 'credential.finalize'; operation: CredentialAuthorityOperationV1 } | (SupervisorHelloV1 & {
  method: 'control.hello'; protocolVersion: 1; serverBuild: string;
  controlSchemaRange: { min: 1; max: 1 }; enabledFeatureIds: string[];
});
type ErrorBase = { schemaVersion: 1; messageCode: string };
type InvalidError = ErrorBase & { code: 'INVALID_REQUEST'; retryable: false;
  issues: Array<{ path: string; issueCode: string }> };
export type InstalledControlErrorV1 = InvalidError
  | InstalledRunCapacityError['controlError']
  | (ErrorBase & { code: 'INCOMPATIBLE_PROTOCOL'; retryable: false;
      supportedControlRange: { min: 1; max: 1 }; supportedHeadlessRange: Range;
      upgradeAction: 'upgrade_client' | 'upgrade_supervisor' })
  | (ErrorBase & { code: 'EVENT_CURSOR_EXPIRED'; retryable: false;
      earliestEventSeq: number; latestEventSeq: number; snapshot: RunSnapshotV1 })
  | (ErrorBase & { code: 'INTERNAL'; retryable: false; errorId: string })
  | (ErrorBase & { code: 'REVISION_CONFLICT'; retryable: true; currentRevision: number;
      conflict: { resourceKind: 'session'; currentSnapshot: SessionSnapshotV1 } | { resourceKind: 'run'; currentSnapshot: RunSnapshotV1 } })
  | (ErrorBase & { code: 'NOT_FOUND' | 'AUTHORIZATION_REQUIRED' | 'ARTIFACT_MISMATCH' | 'UNSUPPORTED_PLATFORM' |
      'REQUEST_ID_CONFLICT' | 'ADMISSION_KEY_CONFLICT' | 'MODEL_COST_UNKNOWN' | 'BUDGET_EXHAUSTED' | 'CANCEL_REQUESTED'; retryable: false });
export type InstalledControlResponseV1 =
  | { protocolVersion: 1; ok: true; result: InstalledControlResultV1 }
  | { protocolVersion: 1; ok: false; method: ControlMethodV1; error: InstalledControlErrorV1 }
  | { protocolVersion: 1; ok: false; rejectedMethodDigest: string; error: InvalidError };

const FRAME_BYTES = 1024 * 1024;
const MAX_OUTSTANDING = 64;
// All owned partial/request/response bodies share this budget. Each connection
// has four-byte input/output headers; Store metadata is separately bounded.
const BUFFER_BYTES = (MAX_OUTSTANDING + 1) * FRAME_BYTES;
const FEATURES = ['session.get', 'run.get', 'run.attach', 'supervisor.status', 'credential.finalize', 'session.create', 'run.submit', 'run.cancel'];
const RUN_FEATURES = ['session.create', 'run.submit', 'run.cancel'];
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
function text(value: unknown): string {
  if (typeof value !== 'string' || normalizeBoundedText(value, 1, 128) !== value) throw new TypeError('invalid bounded text');
  return value;
}
function exact(value: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) throw new TypeError('unknown or missing field');
}
function range(value: unknown): Range {
  if (!record(value)) throw new TypeError('invalid schema range');
  exact(value, ['min', 'max']);
  if (!Number.isSafeInteger(value.min) || !Number.isSafeInteger(value.max) ||
      (value.min as number) < 1 || (value.max as number) < (value.min as number)) throw new TypeError('invalid schema range');
  return { min: value.min as number, max: value.max as number };
}
function hello(value: Record<string, unknown>): HelloRequest {
  exact(value, ['protocolVersion', 'method', 'clientBuild', 'controlSchemaRange', 'headlessSchemaRange', 'requestedFeatureIds']);
  if (value.protocolVersion !== 1 || !Array.isArray(value.requestedFeatureIds) || value.requestedFeatureIds.length > 64) {
    throw new TypeError('invalid hello');
  }
  const featureIds = value.requestedFeatureIds.map(text);
  if (new Set(featureIds).size !== featureIds.length) throw new TypeError('duplicate requested feature');
  return { protocolVersion: 1, method: 'control.hello', clientBuild: text(value.clientBuild),
    controlSchemaRange: range(value.controlSchemaRange), headlessSchemaRange: range(value.headlessSchemaRange), requestedFeatureIds: featureIds };
}
const invalid = (): InvalidError => ({ schemaVersion: 1, code: 'INVALID_REQUEST', retryable: false,
  messageCode: 'control.invalid_request', issues: [{ path: 'request', issueCode: 'invalid_request' }] });
const overlaps = (left: Range, right: Range) => left.min <= right.max && right.min <= left.max;
function incompatible(control: Range, headless: Range, supported: Range): InstalledControlErrorV1 {
  return { schemaVersion: 1, code: 'INCOMPATIBLE_PROTOCOL', retryable: false, messageCode: 'control.incompatible_protocol',
    supportedControlRange: { min: 1, max: 1 }, supportedHeadlessRange: supported,
    upgradeAction: control.max < 1 || headless.max < supported.min ? 'upgrade_client' : 'upgrade_supervisor' };
}

type Connection = { channel: LocalControlConnection; closed: boolean; handshaken: boolean;
  header: Buffer; headerCount: number; body?: Buffer; bodyCount: number;
  queued: Buffer[]; running?: Promise<void> };
type Pending = { connection: Connection; body: Buffer };
// A new server cannot turn uncertain native retirement into successful close.
let controlRetirementFailure: ResourceRetirementError | undefined;

/** Bounded v1 native UDS service. Installed composition alone advertises the
 * fixed Run recipe; authenticated channels never supply principal authority. */
export function openInstalledControl(store: StateStore,
  options: Readonly<{ serverBuild: string }>, onError: (error: Error) => void): InstalledControlService {
  if (controlRetirementFailure) throw controlRetirementFailure;
  const serverBuild = text(options.serverBuild);
  if (typeof onError !== 'function') throw new TypeError('control service requires an error reporter');
  const connections = new Set<Connection>();
  const active = new Set<Promise<void>>();
  let outstanding = 0;
  let reservedBytes = 0;
  let closing: Promise<void> | undefined;
  let stopped = false;
  let retirementFailure: ResourceRetirementError | undefined;
  const report = (error: unknown) => {
    try { onError(error instanceof Error ? error : new Error('control service failed', { cause: error })); }
    catch { /* A consumer reporter cannot escape a socket/native callback. */ }
  };
  const retire = (connection: Connection) => {
    if (connection.closed) return;
    connection.closed = true;
    if (connection.body) { reservedBytes -= connection.body.byteLength; connection.body = undefined; }
    for (const body of connection.queued) reservedBytes -= body.byteLength;
    outstanding -= connection.queued.length;
    connection.queued.length = 0;
    connections.delete(connection);
    try { connection.channel.close(); }
    catch (error) {
      retirementFailure ??= error instanceof ResourceRetirementError ? error
        : new ResourceRetirementError('control connection retirement is uncertain', error);
      controlRetirementFailure ??= retirementFailure;
      stopped = true;
      report(retirementFailure);
    } finally {
      // Native observation retirement can fail before channel.close reaches
      // the independently transferred Socket. Unblock its writes without
      // retrying consumed native descriptors or calling retirement successful.
      if (!connection.channel.socket.destroyed) connection.channel.socket.destroy();
    }
  };
  const errorResult = (error: unknown, credential = false): InstalledControlErrorV1 => {
    if (error instanceof ResourceRetirementError) {
      retirementFailure ??= error;
      controlRetirementFailure ??= error;
      stopped = true;
    }
    if (error instanceof EventCursorExpiredError) return { schemaVersion: 1, code: 'EVENT_CURSOR_EXPIRED', retryable: false,
      messageCode: 'control.event_cursor_expired', earliestEventSeq: error.earliestEventSeq,
      latestEventSeq: error.latestEventSeq, snapshot: error.snapshot };
    if (error instanceof InstalledModelAuthorizationError) return { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED',
      retryable: false, messageCode: 'run.model_authority_refused' };
    if (error instanceof InstalledRunAuthorityError) return { schemaVersion: 1,
      code: error.refusalCode === 'MODEL_COST_UNKNOWN' ? 'MODEL_COST_UNKNOWN' : error.refusalCode === 'MODEL_CAPABILITY_UNKNOWN'
        ? 'AUTHORIZATION_REQUIRED' : 'ARTIFACT_MISMATCH', retryable: false,
      messageCode: error.refusalCode === 'MODEL_COST_UNKNOWN' ? 'run.model_cost_unknown' : error.refusalCode === 'MODEL_CAPABILITY_UNKNOWN'
        ? 'run.model_capability_unknown' : 'run.assembly_invalid' };
    if (error instanceof InstalledRunCapacityError) return error.controlError;
    if (error instanceof TypeError || (error instanceof KernelStorageError && error.code === 'INVALID_REQUEST')) return invalid();
    if (error instanceof KernelStorageError && ['REQUEST_ID_CONFLICT', 'ADMISSION_KEY_CONFLICT', 'BUDGET_EXHAUSTED'].includes(error.code)) return {
      schemaVersion: 1, code: error.code as 'REQUEST_ID_CONFLICT' | 'ADMISSION_KEY_CONFLICT' | 'BUDGET_EXHAUSTED',
      retryable: false, messageCode: 'control.mutation_refused' };
    if (credential && error instanceof KernelStorageError && error.code === 'STATE_TRANSITION_INVALID') {
      const reason = error instanceof CredentialFinalizationTimeError ? error.reason : undefined;
      const messageCode = reason === 'noncausal_time' ? 'credential.finalize.noncausal_time' :
        reason === 'expired' ? 'credential.finalize.expired' : 'credential.finalize_refused';
      return { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode };
    }
    if (error instanceof KernelStorageError && (error.code === 'NOT_FOUND' || error.code === 'ARTIFACT_MISMATCH' || error.code === 'UNSUPPORTED_PLATFORM')) {
      return { schemaVersion: 1, code: error.code, retryable: false, messageCode: 'control.read_rejected' };
    }
    // Generic recovery failures lack the RFC's required exact recovery closure.
    // Never invent recoveryKind/detailRef or put an internal exception on wire.
    report(error);
    return { schemaVersion: 1, code: 'INTERNAL', retryable: false, messageCode: 'control.internal', errorId: randomUUID() };
  };
  const respond = async (pending: Pending): Promise<void> => {
    if (controlRetirementFailure) throw controlRetirementFailure;
    const connection = pending.connection;
    const source = new TextDecoder('utf-8', { fatal: true }).decode(pending.body);
    const request = parseJsonStrict(source);
    if (!record(request) || !pending.body.equals(canonicalJsonBytes(request))) throw new TypeError('noncanonical application frame');
    const method = text(request.method);
    const response = await connection.channel.dispatch(async identity => {
      if (!METHODS.includes(method as ControlMethodV1)) return { protocolVersion: 1, ok: false,
        rejectedMethodDigest: sha256Bytes(Buffer.from(method, 'utf8')), error: invalid() } satisfies InstalledControlResponseV1;
      const knownMethod = method as ControlMethodV1;
      try {
        if (method === 'control.hello') {
          const candidate = hello(request);
          const observed = await store.readSupervisorHello(identity);
          if (!overlaps(candidate.controlSchemaRange, { min: 1, max: 1 }) || !overlaps(candidate.headlessSchemaRange, observed.headlessSchemaRange)) {
            return { protocolVersion: 1, ok: false, method: knownMethod,
              error: incompatible(candidate.controlSchemaRange, candidate.headlessSchemaRange, observed.headlessSchemaRange) } satisfies InstalledControlResponseV1;
          }
          connection.handshaken = true;
          return { protocolVersion: 1, ok: true, result: { ...observed, method: 'control.hello', protocolVersion: 1,
            serverBuild, controlSchemaRange: { min: 1, max: 1 }, enabledFeatureIds: candidate.requestedFeatureIds.filter(feature =>
              FEATURES.includes(feature) && (feature !== 'credential.finalize' || store.supportsCredentialFinalization()) &&
              (!RUN_FEATURES.includes(feature) || store.supportsInstalledRuns())) }
          } satisfies InstalledControlResponseV1;
        }
        if (!connection.handshaken) return { protocolVersion: 1, ok: false, method: knownMethod,
          error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'control.hello_required' } } satisfies InstalledControlResponseV1;
        if (request.protocolVersion !== 1) throw new TypeError('protocol version must be 1');
        if (RUN_FEATURES.includes(method) && !store.supportsInstalledRuns()) return { protocolVersion: 1, ok: false, method: knownMethod,
          error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'control.method_not_enabled' } } satisfies InstalledControlResponseV1;
        if (method === 'session.create') return (await store.createInstalledSession(request, identity)).response;
        if (method === 'run.submit') return (await store.submitInstalledRun(request, identity)).response;
        if (method === 'run.cancel') return (await store.cancelInstalledRun(request, identity)).response;
        if (method === 'credential.finalize') return { protocolVersion: 1, ok: true,
          result: { method: 'credential.finalize', operation: await store.finalizeCredential(request as CredentialFinalizeRequest, identity) }
        } satisfies InstalledControlResponseV1;
        if (method === 'session.get' || method === 'run.get' || method === 'run.attach') {
          return { protocolVersion: 1, ok: true, result: await store.readControl(request as ReadControlRequest, identity) } satisfies InstalledControlResponseV1;
        }
        if (method === 'supervisor.status') {
          exact(request, ['protocolVersion', 'method']);
          return { protocolVersion: 1, ok: true, result: await store.readSupervisorStatus(identity) } satisfies InstalledControlResponseV1;
        }
        return { protocolVersion: 1, ok: false, method: knownMethod,
          error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'control.method_not_enabled' } } satisfies InstalledControlResponseV1;
      } catch (error) {
        if (error instanceof KernelStorageError && error.code === 'REVISION_CONFLICT') {
          // Read a fresh authenticated authoritative snapshot, not the stale
          // producer cut or a fabricated metadata-only conflict response.
          try {
            const observed = method === 'run.submit'
              ? await store.readControl({ protocolVersion: 1, method: 'session.get', sessionId: request.sessionId as string }, identity)
              : method === 'run.cancel'
                ? await store.readControl({ protocolVersion: 1, method: 'run.get', runId: request.runId as string }, identity) : undefined;
            if (observed?.method === 'session.get') return { protocolVersion: 1, ok: false, method: knownMethod,
              error: { schemaVersion: 1, code: 'REVISION_CONFLICT', retryable: true, messageCode: 'control.revision_conflict',
                currentRevision: observed.snapshot.session.contextRevision,
                conflict: { resourceKind: 'session', currentSnapshot: observed.snapshot } } } satisfies InstalledControlResponseV1;
            if (observed?.method === 'run.get') return { protocolVersion: 1, ok: false, method: knownMethod,
              error: { schemaVersion: 1, code: 'REVISION_CONFLICT', retryable: true, messageCode: 'control.revision_conflict',
                currentRevision: observed.snapshot.run.revision,
                conflict: { resourceKind: 'run', currentSnapshot: observed.snapshot } } } satisfies InstalledControlResponseV1;
          } catch (snapshotFailure) { return { protocolVersion: 1, ok: false, method: knownMethod, error: errorResult(snapshotFailure) } satisfies InstalledControlResponseV1; }
        }
        return { protocolVersion: 1, ok: false, method: knownMethod, error: errorResult(error, method === 'credential.finalize') } satisfies InstalledControlResponseV1;
      }
    });
    if (controlRetirementFailure) throw controlRetirementFailure;
    if (connection.closed || stopped) return;
    const body = canonicalJsonBytes(response);
    if (body.byteLength > FRAME_BYTES || reservedBytes + body.byteLength > BUFFER_BYTES) throw new Error('control response exceeds the wire bound');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(body.byteLength);
    reservedBytes += body.byteLength;
    try {
      await new Promise<void>((resolve, reject) => {
        let remaining = 2;
        let failure: unknown;
        const done = (error?: Error | null) => {
          failure ??= error ?? undefined;
          if (--remaining === 0) failure ? reject(failure) : resolve();
        };
        // Avoid an extra large concat allocation. Both writes are joined,
        // including when socket destruction rejects one before the other.
        for (const bytes of [header, body]) {
          try { connection.channel.socket.write(bytes, done); }
          catch (error) { done(error instanceof Error ? error : new Error('control write failed', { cause: error })); }
        }
      });
    } finally { reservedBytes -= body.byteLength; }
  };
  const work = (connection: Connection) => {
    if (connection.running || stopped || connection.closed) return;
    const running = (async () => {
      while (!stopped && !connection.closed && connection.queued.length > 0) {
        const body = connection.queued.shift()!;
        try { await respond({ connection, body }); }
        catch (error) { report(error); retire(connection); }
        finally { reservedBytes -= body.byteLength; outstanding--; }
      }
    })();
    connection.running = running;
    active.add(running);
    void running.finally(() => {
      active.delete(running); connection.running = undefined;
      if (connection.queued.length > 0) work(connection);
    }).catch(report);
  };
  const listener = store.openLocalControl(channel => {
    const connection: Connection = { channel, closed: false, handshaken: false,
      header: Buffer.alloc(4), headerCount: 0, bodyCount: 0, queued: [] };
    connections.add(connection);
    if (stopped || controlRetirementFailure) { retire(connection); return; }
    channel.socket.once('close', () => retire(connection));
    channel.socket.on('data', (chunk: Buffer) => {
      if (stopped || connection.closed) return;
      try {
        let offset = 0;
        while (offset < chunk.byteLength && !connection.closed) {
          if (!connection.body) {
            const count = Math.min(4 - connection.headerCount, chunk.byteLength - offset);
            chunk.copy(connection.header, connection.headerCount, offset, offset + count);
            offset += count; connection.headerCount += count;
            if (connection.headerCount < 4) continue;
            const length = connection.header.readUInt32BE(0);
            if (length < 1 || length > FRAME_BYTES || reservedBytes + length > BUFFER_BYTES) throw new TypeError('control frame bound exceeded');
            connection.body = Buffer.alloc(length); reservedBytes += length;
            connection.bodyCount = 0; connection.headerCount = 0;
          }
          const count = Math.min(connection.body.byteLength - connection.bodyCount, chunk.byteLength - offset);
          chunk.copy(connection.body, connection.bodyCount, offset, offset + count);
          offset += count; connection.bodyCount += count;
          if (connection.bodyCount === connection.body.byteLength) {
            if (outstanding >= MAX_OUTSTANDING) throw new TypeError('control FIFO bound exceeded');
            outstanding++;
            connection.queued.push(connection.body); connection.body = undefined;
            work(connection);
          }
        }
      } catch (error) { report(error); retire(connection); }
    });
  }, report);
  const service: InstalledControlService = Object.freeze({ close() {
    if (this !== service) return Promise.reject(new TypeError('invalid control service'));
    if (closing) return closing;
    stopped = true;
    for (const connection of connections) retire(connection);
    closing = (async () => {
      const results = await Promise.allSettled([...active, Promise.resolve().then(() => listener.close())]);
      if (retirementFailure) throw retirementFailure;
      const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
      const failure = failures.find(result => result.reason instanceof ResourceRetirementError) ?? failures[0];
      if (failure) {
        if (failure.reason instanceof ResourceRetirementError) controlRetirementFailure ??= failure.reason;
        throw failure.reason;
      }
    })();
    return closing;
  } });
  return service;
}
