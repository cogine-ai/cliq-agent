import { canonicalSha256, normalizeCanonicalText } from './canonical.js';
import { assertAdmissionKey, assertRequestId, assertArtifactRef, normalizeAbsolutePath, normalizeBoundedText, parseCanonicalTime } from './identity.js';
import { controlWireInteger, controlWireRecord, controlWireText, assertControlWireJson } from './control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ArtifactDescriptorV1, Session } from './types.js';

export type SessionForkRequestV1 = Readonly<{ protocolVersion: 1; method: 'session.fork'; requestId: string; requestDigest: string;
  admissionKey: string; sessionId: string; expectedContextRevision: number; throughItemSeq: number; name?: string }>;
export type SessionCompactRequestV1 = Readonly<{ protocolVersion: 1; method: 'session.compact'; requestId: string; requestDigest: string;
  sessionId: string; expectedContextRevision: number; fromItemSeq: number; throughItemSeq: number; summaryMarkdown: string; retainedItemIds: readonly string[] }>;
export type SessionListRequestV1 = Readonly<{ protocolVersion: 1; method: 'session.list'; workspacePath?: string; cursor?: string; limit?: number }>;
export type SessionHandoffRequestV1 = Readonly<{ protocolVersion: 1; method: 'session.handoff.create'; sessionId: string;
  expectedContextRevision: number; throughItemSeq?: number }>;
export type SessionContinuityRequestV1 = SessionForkRequestV1 | SessionCompactRequestV1 | SessionListRequestV1 | SessionHandoffRequestV1;
export type SessionSummaryV1 = Omit<Session, 'contextProjectionRef' | 'forkedThroughItemSeq'>;
export type SessionCompactionItem = Readonly<{ schemaVersion: 1; kind: 'compaction'; fromItemSeq: number; throughItemSeq: number;
  sourceItemsDigest: string; summaryRef: string; summaryDigest: string; retainedItemIds: readonly string[]; previousProjectionRef: string; createdAt: string }>;
export type SessionHandoffEntryV1 = Readonly<{ index: number; sourceKind: 'run_terminal' | 'summary'; fromItemSeq: number;
  throughItemSeq: number; sourceRef: string; sourceDigest: string; contentUtf8: string }>;
export type SessionHandoffV1 = Readonly<{ schemaVersion: 1; format: 'cliq-session-handoff-v1'; sessionId: string;
  workspaceIdentityRef: string; workspaceIdentityDigest: string; contextRevision: number; throughItemSeq: number;
  contextProjectionRef: string; contextProjectionDigest: string; entries: readonly SessionHandoffEntryV1[];
  excludedRanges: readonly Readonly<{ fromItemSeq: number; throughItemSeq: number; sourceItemsDigest: string }>[]; handoffDigest: string }>;
export type SessionContinuityResultV1 =
  | Readonly<{ method: 'session.fork'; snapshot: { schemaVersion: 1; session: Session } }>
  | Readonly<{ method: 'session.compact'; snapshot: { schemaVersion: 1; session: Session } }>
  | Readonly<{ method: 'session.list'; sessions: readonly SessionSummaryV1[]; nextCursor?: string }>
  | Readonly<{ method: 'session.handoff.create'; json: ArtifactDescriptorV1; markdown: ArtifactDescriptorV1 }>;

export function decodeSessionSummary(value: unknown): SessionSummaryV1 {
  const data = controlWireRecord(value, ['schemaVersion', 'id', 'workspaceIdentityRef', 'contextRevision', 'latestItemSeq', 'createdAt', 'updatedAt'], ['name', 'parentSessionId']);
  if (data.schemaVersion !== 1) throw new TypeError('Session summary version differs');
  controlWireText(data.id); assertArtifactRef(data.workspaceIdentityRef as string); controlWireInteger(data.contextRevision, 1); controlWireInteger(data.latestItemSeq);
  parseCanonicalTime(data.createdAt as string); parseCanonicalTime(data.updatedAt as string);
  if (Object.hasOwn(data, 'name')) controlWireText(data.name, 256);
  if (Object.hasOwn(data, 'parentSessionId')) controlWireText(data.parentSessionId);
  if ((data.updatedAt as string) < (data.createdAt as string)) throw new TypeError('Session summary times differ');
  return data as SessionSummaryV1;
}

export function normalizeSessionSummary(value: string): string {
  const text = normalizeCanonicalText(value).replace(/\r\n?/gu, '\n');
  const bytes = Buffer.byteLength(text);
  if (bytes < 1 || bytes > 262_144) throw new TypeError('Session summary exceeds its fixed UTF-8 bound');
  return text;
}
export function decodeSessionContinuityRequest(value: unknown): SessionContinuityRequestV1 {
  assertControlWireJson(value);
  const data = value as Record<string, unknown>, method = data?.method;
  if (data?.protocolVersion !== 1) throw new TypeError('control protocol version must be 1');
  if (method === 'session.list') {
    controlWireRecord(data, ['protocolVersion', 'method'], ['workspacePath', 'cursor', 'limit']);
    if (Object.hasOwn(data, 'workspacePath')) {
      if (typeof data.workspacePath !== 'string') throw new TypeError('Session workspace filter is invalid');
      normalizeAbsolutePath(data.workspacePath);
    }
    if (Object.hasOwn(data, 'cursor')) controlWireText(data.cursor, 512);
    if (Object.hasOwn(data, 'limit')) controlWireInteger(data.limit, 1, 100);
  } else if (method === 'session.handoff.create') {
    controlWireRecord(data, ['protocolVersion', 'method', 'sessionId', 'expectedContextRevision'], ['throughItemSeq']);
    controlWireText(data.sessionId); controlWireInteger(data.expectedContextRevision, 1);
    if (Object.hasOwn(data, 'throughItemSeq')) controlWireInteger(data.throughItemSeq);
  } else if (method === 'session.fork' || method === 'session.compact') {
    const fields = ['protocolVersion', 'method', 'requestId', 'requestDigest', 'sessionId', 'expectedContextRevision', 'throughItemSeq'];
    controlWireRecord(data, [...fields, ...(method === 'session.fork' ? ['admissionKey'] : ['fromItemSeq', 'summaryMarkdown', 'retainedItemIds'])],
      method === 'session.fork' ? ['name'] : []);
    assertRequestId(data.requestId as string); controlWireText(data.sessionId); controlWireInteger(data.expectedContextRevision, 1);
    controlWireInteger(data.throughItemSeq);
    if (method === 'session.fork') {
      assertAdmissionKey(data.admissionKey as string);
      if (Object.hasOwn(data, 'name')) {
        if (typeof data.name !== 'string') throw new TypeError('Session name is invalid');
        normalizeBoundedText(data.name, 1, 256);
      }
    } else {
      controlWireInteger(data.fromItemSeq, 1, data.throughItemSeq as number);
      if (typeof data.summaryMarkdown !== 'string') throw new TypeError('Session summary is invalid');
      normalizeSessionSummary(data.summaryMarkdown);
      if (!Array.isArray(data.retainedItemIds) || data.retainedItemIds.length > 256) throw new TypeError('Session retained ids must be a bounded array');
      for (const id of data.retainedItemIds) controlWireText(id);
      if (new Set(data.retainedItemIds).size !== data.retainedItemIds.length) throw new TypeError('Session retained ids must be unique');
    }
    const { requestDigest, ...core } = data;
    if (typeof requestDigest !== 'string' || canonicalSha256(core) !== requestDigest) throw new TypeError('Session mutation digest differs');
  } else throw new TypeError('unknown Session continuity method');
  return immutableSnapshot(data) as SessionContinuityRequestV1;
}
