import { immutableSnapshot } from '../model/immutable.js';
import type { RunSnapshotV1, RunStatus } from './types.js';
import type { AuthorizationGrantSummaryV1, AuthorizationGrantTargetV1, AuthorizationGrantV1 } from './authorization.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireText, decodeWireGrantSummary, decodeWireRun } from './control-wire-data.js';

export type RunListRequestV1 = Readonly<{ protocolVersion: 1; method: 'run.list'; sessionId?: string;
  operation?: 'agent' | 'delivery'; statuses?: readonly RunStatus[]; cursor?: string; limit?: number }>;
export type AuthorizationListRequestV1 = Readonly<{ protocolVersion: 1; method: 'authorization.list';
  targetKind?: AuthorizationGrantTargetV1['kind']; state?: AuthorizationGrantV1['state']; cursor?: string; limit?: number }>;
export type ControlListRequestV1 = RunListRequestV1 | AuthorizationListRequestV1;
export type ControlListResultV1 = Readonly<{ method: 'run.list'; runs: readonly RunSnapshotV1[]; nextCursor?: string }>
  | Readonly<{ method: 'authorization.list'; grants: readonly AuthorizationGrantSummaryV1[]; nextCursor?: string }>;

const statuses = ['cancelled', 'completed_unverified', 'failed', 'queued', 'running', 'succeeded', 'waiting'] as const;
const targets = ['read_scope', 'source_git_inspection', 'execution_identity_read', 'verifier_execution', 'dependency_install_scripts'] as const;
function choice<T extends string>(value: unknown, values: readonly T[]): T {
  if (typeof value !== 'string' || !values.includes(value as T)) throw new TypeError('list filter is not closed');
  return value as T;
}
export function decodeControlListRequest(value: unknown): ControlListRequestV1 {
  assertControlWireJson(value);
  const method = (value as { method?: unknown } | null)?.method;
  if (method !== 'run.list' && method !== 'authorization.list') throw new TypeError('unknown list method');
  const data = controlWireRecord(value, ['protocolVersion', 'method'], ['cursor', 'limit',
    ...(method === 'run.list' ? ['sessionId', 'operation', 'statuses'] : ['targetKind', 'state'])]);
  if (data.protocolVersion !== 1) throw new TypeError('control protocol version must be 1');
  const base = { protocolVersion: 1 as const, method, limit: controlWireInteger(data.limit ?? 50, 1, 100),
    ...(Object.hasOwn(data, 'cursor') ? { cursor: controlWireText(data.cursor, 512) } : {}) };
  if (method === 'authorization.list') return immutableSnapshot({ ...base, method,
    ...(Object.hasOwn(data, 'targetKind') ? { targetKind: choice(data.targetKind, targets) } : {}),
    ...(Object.hasOwn(data, 'state') ? { state: choice(data.state, ['active', 'consumed', 'revoked'] as const) } : {}) });
  let selected: RunStatus[] | undefined;
  if (Object.hasOwn(data, 'statuses')) {
    if (!Array.isArray(data.statuses) || data.statuses.length > statuses.length) throw new TypeError('Run statuses must be bounded');
    selected = data.statuses.map(value => choice(value, statuses)).sort();
    if (new Set(selected).size !== selected.length) throw new TypeError('Run statuses must be unique');
  }
  return immutableSnapshot({ ...base, method,
    ...(Object.hasOwn(data, 'sessionId') ? { sessionId: controlWireText(data.sessionId) } : {}),
    ...(Object.hasOwn(data, 'operation') ? { operation: choice(data.operation, ['agent', 'delivery'] as const) } : {}),
    ...(selected === undefined ? {} : { statuses: selected }) });
}
export function decodeListRunSnapshot(value: unknown): RunSnapshotV1 {
  const data = controlWireRecord(value, ['schemaVersion', 'operation', 'run', 'latestRunItemSeq']);
  if (data.schemaVersion !== 1 || !['agent', 'delivery'].includes(data.operation as string)) throw new TypeError('invalid Run list snapshot');
  decodeWireRun(data.run); controlWireInteger(data.latestRunItemSeq);
  return immutableSnapshot(data) as RunSnapshotV1;
}
export function decodeControlListResult(value: unknown, method: ControlListRequestV1['method']): ControlListResultV1 {
  const key = method === 'run.list' ? 'runs' : 'grants';
  const data = controlWireRecord(value, ['method', key], ['nextCursor']);
  if (data.method !== method || !Array.isArray(data[key]) || data[key].length > 100) throw new TypeError('invalid bounded list page');
  const entries = (data[key] as unknown[]).map(value => method === 'run.list' ? decodeListRunSnapshot(value) : decodeWireGrantSummary(value));
  if (Object.hasOwn(data, 'nextCursor')) {
    controlWireText(data.nextCursor, 512);
    if (!entries.length) throw new TypeError('empty list page cannot issue a cursor');
  }
  let previousTime = '', previousId = '';
  for (const entry of entries) {
    const time = 'run' in entry ? entry.run.createdAt : entry.createdAt;
    const id = 'run' in entry ? entry.run.id : entry.grantId;
    if (previousTime > time || previousTime === time && Buffer.compare(Buffer.from(previousId), Buffer.from(id)) >= 0)
      throw new TypeError('list page is not ordered by its original stable identity');
    previousTime = time; previousId = id;
  }
  return immutableSnapshot({ ...data, [key]: entries }) as ControlListResultV1;
}
export function validateControlListResponse(result: ControlListResultV1, request: ControlListRequestV1): void {
  if (result.method !== request.method) throw new TypeError('list response method differs');
  const entries = result.method === 'run.list' ? result.runs : result.grants;
  if (entries.length > (request.limit ?? 50) || result.nextCursor !== undefined && entries.length !== (request.limit ?? 50))
    throw new TypeError('list response exceeds or truncates its original page');
  if (result.method === 'run.list' && request.method === result.method) {
    if (result.runs.some(({ operation, run }) => request.sessionId !== undefined && run.sessionId !== request.sessionId ||
        request.operation !== undefined && operation !== request.operation || request.statuses?.length && !request.statuses.includes(run.status)))
      throw new TypeError('Run list response differs from its original filters');
  } else if (result.method === 'authorization.list' && request.method === result.method && result.grants.some(grant =>
      request.targetKind !== undefined && grant.targetKind !== request.targetKind || request.state !== undefined && grant.state !== request.state))
    throw new TypeError('authorization list response differs from its original filters');
}
