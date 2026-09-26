import { randomBytes } from 'node:crypto';

import { canonicalSha256 } from '../kernel/canonical.js';
import { assertAdmissionKey, assertRequestId, digestOmitting, identityHash,
  normalizeAbsolutePath, normalizeBoundedText, sha256Bytes } from '../kernel/identity.js';
import type { LocalControlChannelIdentityV1, LocalPrincipalIdentityV1, LocalSocketPeerObservationV2 } from '../kernel/types.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readPersistedWorkspaceTrustByCanonicalPath } from '../session/trust.js';
import { sampleCanonicalNow } from '../state/canonical-time.js';
import { KernelStorageError } from '../state/errors.js';
import { EventCursorExpiredError } from '../state/queries/run-attach.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state/state-owner.js';
import type { SqliteDriver } from '../state/sqlite-driver.js';
import type { StateStore } from '../state/store.js';
import { runAuthenticatedControlRequest } from './request-authority.js';
import { NativeControlListener, type NativeControlConnection } from './native-listener.js';

type Channel = { connection: NativeControlConnection; closed: boolean; hello: boolean;
  principalId?: string; channelIdentityRef?: string; channelIdentityDigest?: string };

const fatalUtf8 = new TextDecoder('utf-8', { fatal: true });

function exactRecord(value: unknown, required: readonly string[], optional: readonly string[] = []): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => required.includes(key) || optional.includes(key));
}

function encode(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

function errorResult(id: string | number | null, code: string): Buffer {
  return encode({ jsonrpc: '2.0', id, error: { code: -32000, message: code } });
}

function isId(value: unknown): value is string | number {
  return (typeof value === 'string' && value.length > 0 && value.length <= 128) ||
    (typeof value === 'number' && Number.isSafeInteger(value));
}

function supportsVersion(value: unknown, version: number): boolean {
  return exactRecord(value, ['min', 'max']) &&
    Number.isSafeInteger(value.min) && Number.isSafeInteger(value.max) &&
    (value.min as number) >= 1 && (value.min as number) <= version &&
    (value.max as number) >= version && (value.max as number) <= 1000;
}

function channelObservation(store: StateStore, connection: NativeControlConnection,
                            at: string): LocalSocketPeerObservationV2 {
  const peer = connection.peer;
  const observation: LocalSocketPeerObservationV2 = {
    schemaVersion: 2,
    format: 'cliq-local-socket-peer-observation-v2',
    platform: peer.platform,
    stateRootIdentityRef: store.stateRootIdentity.ref,
    stateRootIdentityDigest: store.stateRootIdentity.digest,
    endpoint: {
      canonicalRootRelativePath: 'runtime/control-v1.sock', fileType: 'unix_stream_socket',
      deviceId: peer.endpoint.deviceId, fileId: peer.endpoint.fileId,
      ownerUid: peer.endpoint.ownerUid, mode: 384
    },
    listenerSocket: {
      socketFamily: 'AF_UNIX', socketType: 'SOCK_STREAM',
      deviceId: peer.listenerSocket.deviceId, fileId: peer.listenerSocket.fileId
    },
    acceptedSocket: {
      socketFamily: 'AF_UNIX', socketType: 'SOCK_STREAM',
      deviceId: peer.acceptedSocket.deviceId, fileId: peer.acceptedSocket.fileId
    },
    credentialApi: peer.credentialApi,
    peerUid: peer.peerUid,
    peerGid: peer.peerGid,
    observedAt: at,
    observationDigest: ''
  };
  observation.observationDigest = digestOmitting(observation, 'observationDigest');
  return observation;
}

/** Hidden Supervisor service. The public wire never accepts authority fields. */
export class LocalControlServer {
  private native?: NativeControlListener;
  private closing = false;
  private readonly channels = new Map<string, Channel>();
  private readonly inFlight = new Set<Promise<unknown>>();

  private constructor(private readonly store: StateStore,
                      private readonly driver: SqliteDriver,
                      private readonly owner: StateOwnerContext,
                      private readonly bundle: RuntimeBundleManifest) {}

  static async start(store: StateStore, driver: SqliteDriver, owner: StateOwnerContext,
                     bundle: RuntimeBundleManifest): Promise<LocalControlServer> {
    assertActiveStateOwner(driver, owner);
    const server = new LocalControlServer(store, driver, owner, bundle);
    server.native = await NativeControlListener.start(store.stateRoot, {
      root: owner.filesystem.root,
      runtime: owner.filesystem.runtime
    }, {
      onOpen: (connection) => server.track(server.open(connection)),
      onFrame: (connection, frame) => server.track(server.frame(connection, frame)),
      onClosed: (connection) => server.closed(connection)
    }, bundle);
    return server;
  }

  private track<T>(promise: Promise<T>): Promise<T> {
    this.inFlight.add(promise);
    void promise.finally(() => this.inFlight.delete(promise)).catch(() => {});
    return promise;
  }

  private async open(connection: NativeControlConnection): Promise<void> {
    if (this.closing) throw new KernelStorageError('RECOVERY_REQUIRED', 'control service is closing');
    assertActiveStateOwner(this.driver, this.owner);
    if (connection.peer.peerUid !== this.owner.filesystem.root.ownerUid ||
        connection.peer.endpoint.ownerUid !== this.owner.filesystem.root.ownerUid) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'native peer uid differs from StateRoot owner');
    }
    const channelState: Channel = { connection, closed: false, hello: false };
    this.channels.set(connection.id, channelState);
    const at = sampleCanonicalNow();
    const observation = channelObservation(this.store, connection, at);
    const observationArtifact = await this.store.artifacts.publishCanonical(observation, observation.format);
    const principalId = identityHash('cliq-local-principal-v1', this.owner.stateRootIdentityDigest,
      observation.platform, observation.peerUid);
    const principal: LocalPrincipalIdentityV1 = {
      schemaVersion: 1, format: 'cliq-local-principal-identity-v1',
      stateRootIdentityRef: this.owner.stateRootIdentityRef,
      stateRootIdentityDigest: this.owner.stateRootIdentityDigest,
      platform: observation.platform, effectiveUid: observation.peerUid,
      principalId, identityDigest: ''
    };
    principal.identityDigest = digestOmitting(principal, 'identityDigest');
    const principalArtifact = await this.store.artifacts.publishCanonical(principal, principal.format);
    const channel: LocalControlChannelIdentityV1 = {
      schemaVersion: 1, format: 'cliq-local-control-channel-identity-v1',
      principalIdentityRef: principalArtifact.ref,
      principalIdentityDigest: principal.identityDigest,
      principalId, client: 'rpc',
      transport: { kind: 'uds_peer', peerObservationRef: observationArtifact.ref,
        peerObservationDigest: observation.observationDigest },
      openedAt: at,
      channelNonceDigest: sha256Bytes(randomBytes(32)),
      channelIdentityDigest: ''
    };
    channel.channelIdentityDigest = digestOmitting(channel, 'channelIdentityDigest');
    const channelArtifact = await this.store.artifacts.publishCanonical(channel, channel.format);
    if (channelState.closed || this.closing) return;
    channelState.principalId = principalId;
    channelState.channelIdentityRef = channelArtifact.ref;
    channelState.channelIdentityDigest = channel.channelIdentityDigest;
  }

  private async frame(connection: NativeControlConnection, bytes: Buffer): Promise<Buffer> {
    const channel = this.channels.get(connection.id);
    if (!channel || channel.closed || this.closing) throw new Error('control connection is no longer live');
    assertActiveStateOwner(this.driver, this.owner);
    let request: unknown;
    try { request = JSON.parse(fatalUtf8.decode(bytes)); } catch { return errorResult(null, 'INVALID_REQUEST'); }
    if (!exactRecord(request, ['jsonrpc', 'id', 'method', 'params']) ||
        request.jsonrpc !== '2.0' || !isId(request.id) || typeof request.method !== 'string') {
      return errorResult(null, 'INVALID_REQUEST');
    }
    const id = request.id;
    if (!channel.hello) {
      if (request.method !== 'control.hello' || !exactRecord(request.params,
        ['protocolVersion', 'clientBuild', 'controlSchemaRange', 'headlessSchemaRange', 'requestedFeatureIds']) ||
          request.params.protocolVersion !== 1 ||
          typeof request.params.clientBuild !== 'string' || request.params.clientBuild.length < 1 ||
          request.params.clientBuild.length > 128 ||
          !supportsVersion(request.params.controlSchemaRange, 1) ||
          !supportsVersion(request.params.headlessSchemaRange, 1) ||
          !Array.isArray(request.params.requestedFeatureIds) ||
          request.params.requestedFeatureIds.length > 64 ||
          request.params.requestedFeatureIds.some((value) =>
            value !== 'session.create' && value !== 'session.get' &&
            value !== 'run.get' && value !== 'run.attach') ||
          new Set(request.params.requestedFeatureIds).size !== request.params.requestedFeatureIds.length) {
        return encode({ jsonrpc: '2.0', id, error: {
          code: -32000, message: 'INCOMPATIBLE_PROTOCOL',
          data: { controlSchemaRange: this.bundle.controlProtocolRange,
            headlessSchemaRange: this.bundle.headlessSchemaRange, action: 'upgrade_client' }
        } });
      }
      channel.hello = true;
      return encode({ jsonrpc: '2.0', id, result: {
        protocolVersion: 1,
        serverBuild: this.bundle.bundleVersion,
        controlSchemaRange: this.bundle.controlProtocolRange,
        headlessSchemaRange: this.bundle.headlessSchemaRange,
        capabilities: ['session.create', 'session.get', 'run.get', 'run.attach'],
        supervisorInstanceId: this.owner.supervisorInstanceId,
        runtimeBundleRef: canonicalSha256(this.bundle),
        runtimeBundleManifestDigest: this.bundle.manifestDigest
      } });
    }
    if (request.method === 'control.hello') return errorResult(id, 'INVALID_REQUEST');
    if (request.method === 'run.get') {
      const payload = request.params;
      if (!exactRecord(payload, ['protocolVersion', 'method', 'runId'], [
        'afterItemSeq', 'afterJournalSeq', 'checkpointCursor',
        'itemLimit', 'journalLimit', 'checkpointLimit'
      ]) || payload.protocolVersion !== 1 || payload.method !== 'run.get' ||
          typeof payload.runId !== 'string' ||
          (payload.checkpointCursor !== undefined && typeof payload.checkpointCursor !== 'string') ||
          ['afterItemSeq', 'afterJournalSeq'].some((field) => payload[field] !== undefined &&
            (!Number.isSafeInteger(payload[field]) || (payload[field] as number) < 0)) ||
          ['itemLimit', 'journalLimit', 'checkpointLimit'].some((field) => payload[field] !== undefined &&
            (!Number.isSafeInteger(payload[field]) || (payload[field] as number) < 1 ||
              (payload[field] as number) > 1000))) {
        return errorResult(id, 'INVALID_REQUEST');
      }
      if (!channel.principalId) throw new Error('control channel identity publication is incomplete');
      await this.native!.recheck(connection);
      if (channel.closed || this.closing) throw new Error('control connection closed before query cut');
      try {
        const result = await this.store.queryRun({
          principalId: channel.principalId, runId: payload.runId,
          ...(payload.afterItemSeq === undefined ? {} : { afterItemSeq: payload.afterItemSeq as number }),
          ...(payload.afterJournalSeq === undefined ? {} : { afterJournalSeq: payload.afterJournalSeq as number }),
          ...(payload.checkpointCursor === undefined ? {} : { checkpointCursor: payload.checkpointCursor as string }),
          ...(payload.itemLimit === undefined ? {} : { itemLimit: payload.itemLimit as number }),
          ...(payload.journalLimit === undefined ? {} : { journalLimit: payload.journalLimit as number }),
          ...(payload.checkpointLimit === undefined ? {} : { checkpointLimit: payload.checkpointLimit as number })
        });
        return encode({ jsonrpc: '2.0', id, result: { protocolVersion: 1, ok: true, result } });
      } catch (error) {
        const code = error instanceof KernelStorageError ? error.code : 'INVALID_REQUEST';
        const publicCode = ['INVALID_REQUEST', 'NOT_FOUND', 'RECOVERY_REQUIRED'].includes(code)
          ? code : 'INVALID_REQUEST';
        return encode({ jsonrpc: '2.0', id, result: {
          protocolVersion: 1, ok: false, method: 'run.get',
          error: { code: publicCode, retryable: false }
        } });
      }
    }
    if (request.method === 'run.attach') {
      const payload = request.params;
      if (!exactRecord(payload, ['protocolVersion', 'method', 'runId', 'afterEventSeq'], ['limit']) ||
          payload.protocolVersion !== 1 || payload.method !== 'run.attach' ||
          typeof payload.runId !== 'string' ||
          !Number.isSafeInteger(payload.afterEventSeq) || (payload.afterEventSeq as number) < 0 ||
          (payload.limit !== undefined &&
            (!Number.isSafeInteger(payload.limit) || (payload.limit as number) < 1 ||
              (payload.limit as number) > 1000))) {
        return errorResult(id, 'INVALID_REQUEST');
      }
      if (!channel.principalId) throw new Error('control channel identity publication is incomplete');
      await this.native!.recheck(connection);
      if (channel.closed || this.closing) throw new Error('control connection closed before attach cut');
      try {
        const result = await this.store.attachRun({
          principalId: channel.principalId,
          runId: payload.runId,
          afterEventSeq: payload.afterEventSeq as number,
          ...(payload.limit === undefined ? {} : { limit: payload.limit as number })
        });
        return encode({ jsonrpc: '2.0', id, result: { protocolVersion: 1, ok: true, result } });
      } catch (error) {
        if (error instanceof EventCursorExpiredError) {
          return encode({ jsonrpc: '2.0', id, result: {
            protocolVersion: 1, ok: false, method: 'run.attach', error: {
              schemaVersion: 1, code: 'EVENT_CURSOR_EXPIRED', messageCode: 'event_cursor_expired',
              retryable: false, earliestEventSeq: error.earliestEventSeq,
              latestEventSeq: error.latestEventSeq, snapshot: error.snapshot
            }
          } });
        }
        const code = error instanceof KernelStorageError ? error.code : 'INVALID_REQUEST';
        const publicCode = ['INVALID_REQUEST', 'NOT_FOUND', 'RECOVERY_REQUIRED'].includes(code)
          ? code : 'INVALID_REQUEST';
        return encode({ jsonrpc: '2.0', id, result: {
          protocolVersion: 1, ok: false, method: 'run.attach',
          error: { code: publicCode, retryable: false }
        } });
      }
    }
    if (request.method === 'session.get') {
      const payload = request.params;
      if (!exactRecord(payload, ['protocolVersion', 'method', 'sessionId'], ['afterItemSeq', 'limit']) ||
          payload.protocolVersion !== 1 || payload.method !== 'session.get' ||
          typeof payload.sessionId !== 'string' ||
          (payload.afterItemSeq !== undefined &&
            (!Number.isSafeInteger(payload.afterItemSeq) || (payload.afterItemSeq as number) < 0)) ||
          (payload.limit !== undefined &&
            (!Number.isSafeInteger(payload.limit) || (payload.limit as number) < 1 ||
              (payload.limit as number) > 1000))) {
        return errorResult(id, 'INVALID_REQUEST');
      }
      if (!channel.principalId) throw new Error('control channel identity publication is incomplete');
      await this.native!.recheck(connection);
      if (channel.closed || this.closing) throw new Error('control connection closed before query cut');
      try {
        const result = this.store.querySession({
          principalId: channel.principalId,
          sessionId: payload.sessionId,
          ...(payload.afterItemSeq === undefined ? {} : { afterItemSeq: payload.afterItemSeq as number }),
          ...(payload.limit === undefined ? {} : { limit: payload.limit as number })
        });
        return encode({ jsonrpc: '2.0', id, result: { protocolVersion: 1, ok: true, result } });
      } catch (error) {
        const code = error instanceof KernelStorageError ? error.code : 'INVALID_REQUEST';
        const publicCode = ['INVALID_REQUEST', 'NOT_FOUND', 'RECOVERY_REQUIRED'].includes(code)
          ? code : 'INVALID_REQUEST';
        return encode({ jsonrpc: '2.0', id, result: {
          protocolVersion: 1, ok: false, method: 'session.get',
          error: { code: publicCode, retryable: false }
        } });
      }
    }
    if (request.method !== 'session.create') return errorResult(id, 'METHOD_NOT_FOUND');
    const payload = request.params;
    if (!exactRecord(payload, ['protocolVersion', 'requestId', 'requestDigest', 'method',
      'admissionKey', 'workspacePath'], ['name']) || payload.protocolVersion !== 1 ||
        payload.method !== 'session.create' || typeof payload.requestId !== 'string' ||
        typeof payload.requestDigest !== 'string' || typeof payload.admissionKey !== 'string' ||
        typeof payload.workspacePath !== 'string' ||
        (payload.name !== undefined && typeof payload.name !== 'string')) {
      return errorResult(id, 'INVALID_REQUEST');
    }
    // The reducer hashes normalized fields. Reject alternate spellings before
    // comparing the wire digest so one requestId cannot replay different bytes.
    try {
      assertRequestId(payload.requestId as string);
      assertAdmissionKey(payload.admissionKey as string);
      if (normalizeAbsolutePath(payload.workspacePath as string) !== payload.workspacePath ||
          (payload.name !== undefined &&
            normalizeBoundedText(payload.name as string, 1, 256) !== payload.name)) {
        return errorResult(id, 'INVALID_REQUEST');
      }
    } catch {
      return errorResult(id, 'INVALID_REQUEST');
    }
    const { requestDigest, ...requestBody } = payload;
    try {
      if (canonicalSha256(requestBody) !== requestDigest) return errorResult(id, 'INVALID_REQUEST');
    } catch {
      return errorResult(id, 'INVALID_REQUEST');
    }
    // This read-only trust gate precedes any .git/config or workspace-context
    // capture. A service environment override cannot grant trust to requests.
    try {
      if (await readPersistedWorkspaceTrustByCanonicalPath(payload.workspacePath as string) !== 'trusted') {
        return errorResult(id, 'WORKSPACE_TRUST_REQUIRED');
      }
    } catch {
      return errorResult(id, 'WORKSPACE_TRUST_REQUIRED');
    }
    if (!channel.principalId || !channel.channelIdentityRef || !channel.channelIdentityDigest) {
      throw new Error('control channel artifact publication is incomplete');
    }
    // The child rechecks the held connection and endpoint after asynchronous
    // trust I/O. No historical artifact can substitute for this live cut.
    await this.native!.recheck(connection);
    if (channel.closed || this.closing) throw new Error('control connection closed before authentication cut');
    assertActiveStateOwner(this.driver, this.owner);
    const identity = {
      ownerEpoch: this.owner.ownerEpoch,
      principalId: channel.principalId,
      channelIdentityRef: channel.channelIdentityRef,
      channelIdentityDigest: channel.channelIdentityDigest
    };
    try {
      const committed = await runAuthenticatedControlRequest(identity, () => this.store.createSession({
        principalId: identity.principalId,
        channelIdentityRef: identity.channelIdentityRef,
        channelIdentityDigest: identity.channelIdentityDigest,
        requestId: payload.requestId as string,
        admissionKey: payload.admissionKey as string,
        workspacePath: payload.workspacePath as string,
        ...(payload.name === undefined ? {} : { name: payload.name as string })
      }));
      return encode({ jsonrpc: '2.0', id, result: committed.response });
    } catch (error) {
      const code = error instanceof KernelStorageError ? error.code : 'INVALID_REQUEST';
      const publicCode = ['ADMISSION_KEY_CONFLICT', 'REQUEST_ID_CONFLICT', 'ARTIFACT_MISMATCH',
        'INVALID_REQUEST', 'NOT_FOUND', 'RECOVERY_REQUIRED', 'UNSUPPORTED_PLATFORM'].includes(code)
        ? code : 'INVALID_REQUEST';
      return encode({ jsonrpc: '2.0', id, result: {
        protocolVersion: 1, ok: false, method: 'session.create',
        error: { code: publicCode, retryable: false }
      } });
    }
  }

  private closed(connection: NativeControlConnection): void {
    const channel = this.channels.get(connection.id);
    if (channel) channel.closed = true;
    this.channels.delete(connection.id);
  }

  async close(): Promise<void> {
    if (this.closing) return;
    this.closing = true;
    await this.native?.close();
    await Promise.allSettled([...this.inFlight]);
    this.channels.clear();
  }
}
