import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertArtifactRef, assertRequestId, normalizeAbsolutePath } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { immutableSnapshot } from '../model/immutable.js';
import { CONTROL_FRAME_BYTES, CONTROL_V1_SOURCE_DIGEST, decodeControlFrame, decodeInstalledControlRequest,
  decodeInstalledControlResponse, type InstalledControlResponseFor } from '../control/v1.js';
import { openPrivateClientDirectory, type PrivateClientDirectory, type PrivateClientDirectoryIdentity } from './private-files.js';
import type { PendingClientMutation, PendingRequestMetadata, PendingRequestRecord, PendingRequestSummary } from './request-data.js';
export type { PendingClientMutation, PendingRequestMetadata, PendingRequestRecord, PendingRequestSummary } from './request-data.js';

const METADATA_BYTES = 4096;
type MutationResponse = InstalledControlResponseFor<PendingClientMutation['method']>;
export type PendingRequestBinding = Readonly<{
  stateRoot: PrivateClientDirectoryIdentity & Readonly<{ canonicalPath: string }>; sourceBundleDigest: string;
}>;
const equal = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
const keys = (value: Record<string, unknown>, names: readonly string[]) =>
  Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
function rootIdentity(value: unknown): PrivateClientDirectoryIdentity {
  const root = value as Record<string, unknown>;
  if (!root || typeof root !== 'object' || Array.isArray(root) || !keys(root, ['deviceId', 'fileId', 'ownerUid']) ||
      typeof root.deviceId !== 'string' || !/^(0|[1-9][0-9]{0,31})$/u.test(root.deviceId) ||
      typeof root.fileId !== 'string' || !/^[1-9][0-9]{0,31}$/u.test(root.fileId) ||
      !Number.isSafeInteger(root.ownerUid) || (root.ownerUid as number) < 0 || (root.ownerUid as number) > 0xffffffff)
    throw new TypeError('pending request StateRoot identity is invalid');
  return immutableSnapshot(root) as PrivateClientDirectoryIdentity;
}
function mutation(value: unknown): PendingClientMutation {
  const request = decodeInstalledControlRequest(value);
  if (!('requestId' in request) || !('requestDigest' in request))
    throw new TypeError('only an original secret-free v1 mutation can be retained');
  return request as PendingClientMutation;
}

/** Closed, independent files: the original wire frame gets its original byte,
 * JSON-depth and aggregate-node limits, without a metadata wrapper. Data only;
 * a decoded disk response does not authenticate a peer or authorize an effect. */
export function decodePendingRequestFiles(metadataBytes: Uint8Array, requestBytes: Uint8Array,
  responseBytes?: Uint8Array): PendingRequestRecord {
  if (metadataBytes.byteLength < 1 || metadataBytes.byteLength > METADATA_BYTES) throw new TypeError('pending request metadata exceeds its bound');
  const metadata = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(metadataBytes)) as Record<string, unknown>;
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata) || !keys(metadata,
    ['schemaVersion', 'protocolVersion', 'method', 'requestId', 'requestDigest', 'stateRoot', 'sourceBundleDigest', 'controlSourceDigest']) ||
      metadata.schemaVersion !== 1 || metadata.protocolVersion !== 1 || typeof metadata.requestId !== 'string' ||
      typeof metadata.requestDigest !== 'string' || typeof metadata.sourceBundleDigest !== 'string' ||
      typeof metadata.controlSourceDigest !== 'string' || !/^[a-f0-9]{64}$/u.test(metadata.controlSourceDigest) ||
      !canonicalJsonBytes(metadata).equals(Buffer.from(metadataBytes))) throw new TypeError('pending request metadata is not its closed canonical contract');
  assertRequestId(metadata.requestId); assertArtifactRef(metadata.requestDigest); assertArtifactRef(metadata.sourceBundleDigest);
  rootIdentity(metadata.stateRoot);
  const request = mutation(decodeControlFrame(requestBytes));
  if (!canonicalJsonBytes(request).equals(Buffer.from(requestBytes)) || request.method !== metadata.method ||
      request.requestId !== metadata.requestId || request.requestDigest !== metadata.requestDigest)
    throw new TypeError('pending request bytes differ from their original metadata');
  let response: MutationResponse | undefined;
  if (responseBytes !== undefined) {
    response = decodeInstalledControlResponse(decodeControlFrame(responseBytes), request);
    if (!canonicalJsonBytes(response).equals(Buffer.from(responseBytes))) throw new TypeError('pending response is not its original canonical wire bytes');
  }
  return Object.freeze({ metadata: immutableSnapshot(metadata) as PendingRequestMetadata, request,
    bytes: Buffer.from(requestBytes), ...(response === undefined ? {} : { response }) });
}

/** Borrows the actual account's held private directory. This is a durable
 * copy of original requests/results, never an execution journal or permission
 * to resend. Unknown records are neither replaced, retried nor evicted. */
export async function openPendingRequests(directory: PrivateClientDirectory, supplied: PendingRequestBinding) {
  const binding = immutableSnapshot(supplied);
  const expected = rootIdentity({ deviceId: binding.stateRoot.deviceId, fileId: binding.stateRoot.fileId, ownerUid: binding.stateRoot.ownerUid });
  assertArtifactRef(binding.sourceBundleDigest);
  if (normalizeAbsolutePath(binding.stateRoot.canonicalPath) !== binding.stateRoot.canonicalPath)
    throw new TypeError('pending requests require their original canonical StateRoot locator');
  async function assertBinding() {
    const current = await openPrivateClientDirectory(binding.stateRoot.canonicalPath);
    try { if (!equal(current.identity, expected)) throw new TypeError('pending requests belong to another physical StateRoot'); }
    finally { await current.close(); }
    await directory.assertCurrent();
  }
  await assertBinding();
  const requests = await directory.directory('requests-v1', true);
  let closed = false, tail: Promise<void> = Promise.resolve();
  const acknowledging = new Map<string, Promise<void>>();
  function serial<T>(operation: () => Promise<T>): Promise<T> {
    if (closed) return Promise.reject(new TypeError('pending request data is closed'));
    const result = tail.then(async () => { await assertBinding(); const value = await operation(); await assertBinding(); return value; });
    tail = result.then(() => {}, () => {}); return result;
  }
  async function read(group: PrivateClientDirectory): Promise<PendingRequestRecord> {
    const entries = await group.names();
    if (entries.some(entry => !['metadata.json', 'request.json', 'response.json'].includes(entry)))
      throw new TypeError('pending request group contains an unrecognized or incomplete publication');
    const metadata = await group.read('metadata.json', METADATA_BYTES), original = await group.read('request.json', CONTROL_FRAME_BYTES);
    if (!metadata || !original) throw new TypeError('pending request group is incomplete; its original request must be retained');
    const response = await group.read('response.json', CONTROL_FRAME_BYTES);
    const value = decodePendingRequestFiles(metadata, original, response);
    if (!equal(value.metadata.stateRoot, expected)) throw new TypeError('pending request belongs to another physical StateRoot');
    return value;
  }
  async function load(requestId: string) {
    const group = await requests.directory(requestId);
    try {
      const value = await read(group);
      if (value.request.requestId !== requestId) throw new TypeError('pending request directory substitutes its original requestId');
      return value;
    } finally { await group.close(); }
  }
  return Object.freeze({
    list(): Promise<readonly PendingRequestSummary[]> {
      return serial(async () => {
        const result: PendingRequestSummary[] = [];
        for (const requestId of await requests.names()) {
          // Only explicit acknowledgement of a strictly known response moves a
          // group to this identity-bound cleanup namespace. It is local data,
          // never a peer response or authority to execute/retry anything.
          if (requestId.startsWith('.ack-')) { await requests.assertAcknowledgedDirectory(requestId); continue; }
          assertRequestId(requestId); const value = await load(requestId), response = value.response;
          const snapshot = response?.ok && 'snapshot' in response.result ? response.result.snapshot : undefined;
          result.push(Object.freeze({ metadata: value.metadata, state: response === undefined ? 'unresolved' : 'known',
            ...(snapshot && 'run' in snapshot ? { knownRunId: snapshot.run.id } : {}),
            ...(snapshot && 'session' in snapshot ? { knownSessionId: snapshot.session.id } : {}) }));
        }
        return Object.freeze(result);
      });
    },
    retain(suppliedRequest: unknown): Promise<Readonly<PendingRequestRecord & { existing: boolean }>> {
      const original = mutation(suppliedRequest), bytes = canonicalJsonBytes(original);
      return serial(async () => {
        const created = await requests.createDirectory(original.requestId);
        try {
          if (created.created) {
            const metadata: PendingRequestMetadata = { schemaVersion: 1, protocolVersion: 1, method: original.method,
              requestId: original.requestId, requestDigest: original.requestDigest, stateRoot: expected,
              sourceBundleDigest: binding.sourceBundleDigest, controlSourceDigest: CONTROL_V1_SOURCE_DIGEST };
            if (await created.directory.publish('request.json', bytes) !== 'created' ||
                await created.directory.publish('metadata.json', canonicalJsonBytes(metadata)) !== 'created')
              throw new TypeError('new pending request publication was replaced');
            await created.directory.sync(); await requests.sync();
          }
          const retained = await read(created.directory);
          if (retained.request.requestId !== original.requestId) throw new TypeError('pending request directory substitutes its original requestId');
          if (!retained.bytes.equals(bytes)) throw new TypeError('pending request conflicts with the retained original bytes');
          return Object.freeze({ ...retained, existing: !created.created });
        } finally { await created.directory.close(); }
      });
    },
    load(requestId: string): Promise<PendingRequestRecord> { assertRequestId(requestId); return serial(() => load(requestId)); },
    resolve(suppliedRequest: unknown, suppliedResponse: unknown): Promise<PendingRequestRecord> {
      const original = mutation(suppliedRequest), originalBytes = canonicalJsonBytes(original);
      const response = decodeInstalledControlResponse(suppliedResponse, original), responseBytes = canonicalJsonBytes(response);
      return serial(async () => {
        const group = await requests.directory(original.requestId);
        try {
          const retained = await read(group);
          if (!retained.bytes.equals(originalBytes)) throw new TypeError('known response differs from the retained original request');
          if (retained.response !== undefined && !equal(retained.response, response)) throw new TypeError('known response conflicts with the retained original response');
          await group.publish('response.json', responseBytes);
          await group.sync(); await requests.sync();
          const completed = await read(group);
          if (completed.response === undefined || !equal(completed.response, response))
            throw new TypeError('known response changed during durable publication');
          return completed;
        } finally { await group.close(); }
      });
    },
    acknowledge(requestId: string): Promise<void> {
      assertRequestId(requestId);
      const original = acknowledging.get(requestId); if (original) return original;
      const result = serial(async () => {
        const group = await requests.directory(requestId);
        let value: PendingRequestRecord;
        const identity = group.identity;
        try {
          value = await read(group);
          if (value.request.requestId !== requestId || value.response === undefined)
            throw new TypeError('only a strictly known original response can be acknowledged');
        } finally { await group.close(); }
        await requests.acknowledgeDirectory(requestId, identity, [
          { name: 'metadata.json', bytes: canonicalJsonBytes(value.metadata) },
          { name: 'request.json', bytes: value.bytes },
          { name: 'response.json', bytes: canonicalJsonBytes(value.response) }
        ]);
      });
      acknowledging.set(requestId, result);
      void result.finally(() => { if (acknowledging.get(requestId) === result) acknowledging.delete(requestId); }).catch(() => {});
      return result;
    },
    close(): Promise<void> { closed = true; return tail; }
  });
}

export type PendingRequests = Awaited<ReturnType<typeof openPendingRequests>>;
