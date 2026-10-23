import { assertArtifactRef, normalizeBoundedText, parseCanonicalTime, requiredSafeInteger } from './identity.js';
import type { ArtifactDescriptorV1, BudgetUsage, Checkpoint, InvocationJournalEntry, Run, RunEvent, RunItemReferenceV1, RunSnapshotV1, Session, SessionItem } from './types.js';
import type { AuthorizationGrantSummaryV1 } from './authorization.js';

/** Data validation only. None of these values is a StateOwner, native proof,
 * artifact registration, authorization grant or permission to mutate state. */
export function assertControlWireJson(value: unknown, depth = 0): void {
  if (depth > 32) throw new TypeError('control data exceeds its depth bound');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (typeof value !== 'object' || value === null ||
      (!Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value))))
    throw new TypeError('control data must be plain JSON');
  const fields = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(fields)) {
    const field = fields[key as string]!;
    if (Array.isArray(value) && key === 'length') continue;
    if (typeof key !== 'string' || !field.enumerable || !Object.hasOwn(field, 'value'))
      throw new TypeError('control data requires enumerable data fields');
    assertControlWireJson(field.value, depth + 1);
  }
  if (Array.isArray(value) && (Object.keys(value).length !== value.length ||
      Object.keys(value).some((key, index) => key !== String(index)))) throw new TypeError('control arrays must be dense');
}
export function controlWireRecord(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('invalid control record');
  const fields = Object.getOwnPropertyDescriptors(value);
  if (required.some(key => !Object.hasOwn(fields, key)) || Reflect.ownKeys(fields).some(key =>
    typeof key !== 'string' || (!required.includes(key) && !optional.includes(key)) ||
    !fields[key]!.enumerable || !Object.hasOwn(fields[key]!, 'value') || fields[key]!.value === undefined))
    throw new TypeError('unknown or missing control field');
  return value as Record<string, unknown>;
}
export function controlWireText(value: unknown, maximum = 128, minimum = 1): string {
  if (typeof value !== 'string' || normalizeBoundedText(value, minimum, maximum) !== value)
    throw new TypeError('control text is not bounded canonical UTF-8');
  return value;
}
export function controlWireInteger(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum)
    throw new TypeError('control integer is outside its bound');
  return value as number;
}
export function controlWireRef(value: unknown): string {
  if (typeof value !== 'string') throw new TypeError('control artifact reference is not text');
  assertArtifactRef(value); return value;
}
export function decodeControlRange(value: unknown): Readonly<{ min: number; max: number }> {
  const data = controlWireRecord(value, ['min', 'max']);
  return { min: controlWireInteger(data.min, 1), max: controlWireInteger(data.max, data.min as number) };
}
function time(value: unknown): void {
  if (typeof value !== 'string') throw new TypeError('control time must be text');
  parseCanonicalTime(value);
}
export const BUDGET_FIELDS = ['modelTokens', 'costMicros', 'toolCalls', 'repairAttempts'] as const;
function invalid(message: string): never { throw new TypeError(message); }
function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalid(`${label} must be an object`);
  return value as Record<string, unknown>;
}
function requireSafeInteger(value: unknown, label: string, minimum = 0): number {
  let parsed: number;
  try { parsed = requiredSafeInteger(value, label); }
  catch { invalid(`${label} must be a safe integer`); }
  if (parsed! < minimum) invalid(`${label} must be at least ${minimum}`);
  return parsed!;
}
function rejectUnknownKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) invalid(`${label}.${key} is not legal in this state`);
}
function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) invalid(`${label} must be a nonempty string`);
  return value as string;
}
function requireCanonicalTime(value: unknown, label: string): string {
  const timestamp = requireString(value, label);
  try { parseCanonicalTime(timestamp); } catch { invalid(`${label} must be a canonical UTC millisecond`); }
  return timestamp;
}
function requireArtifactRef(value: unknown, label: string): string {
  const ref = requireString(value, label);
  try { assertArtifactRef(ref); } catch { invalid(`${label} must be a canonical ArtifactRef`); }
  return ref;
}
function requireDigest(value: unknown, label: string): string { return requireArtifactRef(value, label); }
const has = (value: Record<string, unknown>, key: string) => Object.hasOwn(value, key);
function requireAbsent(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  for (const key of keys) if (has(value, key)) invalid(`${label}.${key} is forbidden in this state`);
}
function requireEvidencePair(value: Record<string, unknown>, refKey: string, digestKey: string, label: string): void {
  if (has(value, refKey) !== has(value, digestKey)) invalid(`${label}.${refKey}/${digestKey} must be present or absent together`);
  if (has(value, refKey)) { requireArtifactRef(value[refKey], `${label}.${refKey}`); requireDigest(value[digestKey], `${label}.${digestKey}`); }
}
const isZeroBudget = (value: BudgetUsage) => BUDGET_FIELDS.every(field => value[field] === 0);
/** Shared retained-data decoder. The enclosing wire JSON check excludes bigint
 * and accessors; storage callers retain their existing safe-integer behavior. */
export function decodeWireBudget(value: unknown, label = 'BudgetUsage'): BudgetUsage {
  const record = requireRecord(value, label);
  rejectUnknownKeys(record, BUDGET_FIELDS, label);
  for (const field of BUDGET_FIELDS) requireSafeInteger(record[field], `${label}.${field}`);
  return { modelTokens: record.modelTokens as number, costMicros: record.costMicros as number,
    toolCalls: record.toolCalls as number, repairAttempts: record.repairAttempts as number };
}
const RUN_STATUSES = ['queued', 'running', 'waiting', 'succeeded', 'completed_unverified', 'failed', 'cancelled'];
const NEXT_STEPS = ['agent', 'tool', 'verify', 'finalize', 'delivery', null];
const WAITING_REASONS = ['approval', 'input', 'child', 'reconciliation'];
const TERMINAL_REASONS: Partial<Record<Run['status'], readonly string[]>> = {
  succeeded: ['verified'], completed_unverified: ['no_required_verifier'],
  failed: ['verification_failed', 'verifier_infrastructure_failed', 'verifier_mutated_source', 'budget_exhausted', 'runtime_failed'],
  cancelled: ['cancelled_by_user', 'parent_cancelled']
};
type PublicState = Pick<Run, 'status' | 'nextStep' | 'frontierRef' | 'waitingReason' | 'waitingOnRef' | 'resultRef' | 'terminalReason' | 'terminalDetailRef'>;
export function decodeWirePublicState(value: unknown): PublicState {
  const state = requireRecord(value, 'Run state');
  if (!RUN_STATUSES.includes(state.status as string) || !NEXT_STEPS.includes(state.nextStep as string | null))
    invalid('Run state discriminator is invalid');
  if (state.waitingReason !== undefined && !WAITING_REASONS.includes(state.waitingReason as string)) invalid('Run waiting reason is invalid');
  if (state.status === 'waiting') {
    if (state.waitingReason === undefined || state.waitingOnRef === undefined) invalid('waiting Run has no exact waiting subject');
  } else if (state.waitingReason !== undefined || state.waitingOnRef !== undefined) invalid('nonwaiting Run retains waiting metadata');
  const reasons = TERMINAL_REASONS[state.status as Run['status']];
  if (reasons !== undefined) {
    if (state.nextStep !== null || state.frontierRef !== undefined || !reasons.includes(state.terminalReason as string))
      invalid('terminal Run state/reason is inconsistent');
    const success = state.status === 'succeeded' || state.status === 'completed_unverified';
    if (success ? state.resultRef === undefined || state.terminalDetailRef !== undefined : state.resultRef !== undefined || state.terminalDetailRef === undefined)
      invalid('terminal Run result/detail metadata is inconsistent');
  } else if (state.nextStep === null || state.frontierRef === undefined || state.resultRef !== undefined || state.terminalReason !== undefined || state.terminalDetailRef !== undefined)
    invalid('nonterminal Run metadata is inconsistent');
  return state as PublicState;
}
export function decodeWireRun(value: unknown): Run {
  assertControlWireJson(value);
  const run = controlWireRecord(value, ['id', 'sessionId', 'specRef', 'status', 'nextStep', 'revision', 'leaseEpoch', 'latestCheckpointId',
    'budgetReserved', 'budgetConsumed', 'repairCount', 'cancelRequested', 'createdAt', 'deadlineAt', 'updatedAt'],
  ['parentRunId', 'frontierRef', 'waitingReason', 'waitingOnRef', 'activeWorkerLaunchId', 'resultRef', 'terminalReason', 'terminalDetailRef', 'stopIntentRef']);
  for (const field of ['id', 'sessionId', 'latestCheckpointId']) controlWireText(run[field]);
  controlWireRef(run.specRef); controlWireInteger(run.revision, 1); controlWireInteger(run.leaseEpoch); controlWireInteger(run.repairCount);
  for (const field of ['createdAt', 'updatedAt', 'deadlineAt']) time(run[field]);
  decodeWireBudget(run.budgetReserved); decodeWireBudget(run.budgetConsumed);
  for (const field of ['parentRunId', 'activeWorkerLaunchId']) if (Object.hasOwn(run, field)) controlWireText(run[field]);
  for (const field of ['frontierRef', 'waitingOnRef', 'resultRef', 'terminalDetailRef', 'stopIntentRef'])
    if (Object.hasOwn(run, field)) controlWireRef(run[field]);
  if (typeof run.cancelRequested !== 'boolean') invalid('Run cancellation metadata is invalid');
  decodeWirePublicState(run);
  if ((run.status === 'running') !== (run.activeWorkerLaunchId !== undefined)) invalid('Run active launch metadata is inconsistent');
  if ((run.status === 'succeeded' || run.status === 'completed_unverified') && (run.stopIntentRef !== undefined || run.cancelRequested))
    invalid('successful Run retains stop metadata');
  if ((run.status === 'failed' || run.status === 'cancelled') && run.stopIntentRef === undefined) invalid('stopped Run has no winning stop intent');
  return run as Run;
}
export function decodeWireSession(value: unknown): Session {
  assertControlWireJson(value);
  const session = controlWireRecord(value, ['schemaVersion', 'id', 'workspaceIdentityRef', 'contextRevision', 'latestItemSeq',
    'contextProjectionRef', 'createdAt', 'updatedAt'], ['name', 'parentSessionId', 'forkedThroughItemSeq']);
  if (session.schemaVersion !== 1) invalid('Session schema version is invalid');
  controlWireText(session.id); controlWireRef(session.workspaceIdentityRef); controlWireRef(session.contextProjectionRef);
  controlWireInteger(session.contextRevision, 1); controlWireInteger(session.latestItemSeq); time(session.createdAt); time(session.updatedAt);
  if (Object.hasOwn(session, 'name')) controlWireText(session.name, 256);
  if (Object.hasOwn(session, 'parentSessionId') !== Object.hasOwn(session, 'forkedThroughItemSeq')) invalid('Session lineage is incomplete');
  if (Object.hasOwn(session, 'parentSessionId')) {
    controlWireText(session.parentSessionId);
    controlWireInteger(session.forkedThroughItemSeq, 0, session.latestItemSeq as number);
  }
  return session as Session;
}
export function decodeWireCheckpoint(value: unknown): Checkpoint {
  assertControlWireJson(value);
  const checkpoint = controlWireRecord(value, ['id', 'schemaVersion', 'runId', 'basedOnRunRevision', 'runItemSeq',
    'contextManifestRef', 'journalSeq', 'workspaceStateRef', 'createdAt', 'reason']);
  if (checkpoint.schemaVersion !== 1) invalid('Checkpoint schema version is invalid');
  controlWireText(checkpoint.id); controlWireText(checkpoint.runId); time(checkpoint.createdAt);
  for (const field of ['basedOnRunRevision', 'runItemSeq', 'journalSeq']) controlWireInteger(checkpoint[field]);
  controlWireRef(checkpoint.contextManifestRef); controlWireRef(checkpoint.workspaceStateRef);
  if (!['initial', 'auto', 'manual', 'pre-effect', 'handoff'].includes(checkpoint.reason as string)) invalid('Checkpoint reason is invalid');
  return checkpoint as Checkpoint;
}
export function decodeWireEvent(value: unknown, snapshot?: Pick<RunSnapshotV1, 'run' | 'latestRunItemSeq'>): RunEvent {
  assertControlWireJson(value);
  const event = requireRecord(value, 'Run event');
  if (event.kind === 'state_changed') {
    controlWireRecord(event, ['schemaVersion', 'kind', 'runId', 'eventSeq', 'runRevision', 'status', 'nextStep', 'latestRunItemSeq', 'occurredAt'],
      ['waitingReason', 'waitingOnRef', 'frontierRef', 'resultRef', 'terminalReason', 'terminalDetailRef']);
    controlWireInteger(event.runRevision, 1, snapshot?.run.revision);
    controlWireInteger(event.latestRunItemSeq, 0, snapshot?.latestRunItemSeq);
    for (const field of ['waitingOnRef', 'frontierRef', 'resultRef', 'terminalDetailRef'])
      if (Object.hasOwn(event, field)) controlWireRef(event[field]);
    decodeWirePublicState(event);
  } else if (event.kind === 'progress') {
    controlWireRecord(event, ['schemaVersion', 'kind', 'runId', 'eventSeq', 'observedRunRevision', 'phase', 'occurredAt'],
      ['opId', 'messageRef', 'completedUnits', 'totalUnits']);
    if (!['agent', 'tool', 'verify', 'recovery', 'delivery'].includes(event.phase as string)) invalid('Run progress observation is invalid');
    controlWireInteger(event.observedRunRevision, 1, snapshot?.run.revision);
    if (Object.hasOwn(event, 'opId')) controlWireText(event.opId);
    if (Object.hasOwn(event, 'messageRef')) controlWireRef(event.messageRef);
    for (const field of ['completedUnits', 'totalUnits']) if (Object.hasOwn(event, field)) controlWireInteger(event[field]);
  } else invalid('Run event kind is not closed');
  if (event.schemaVersion !== 1) invalid('Run event schema version is invalid');
  controlWireText(event.runId); controlWireInteger(event.eventSeq, 1); time(event.occurredAt);
  if (snapshot && event.runId !== snapshot.run.id) invalid('Run event belongs to another Run');
  return event as RunEvent;
}
export function decodeWireRunItemReference(value: unknown): RunItemReferenceV1 {
  const item = controlWireRecord(value, ['schemaVersion', 'itemId', 'itemSeq', 'payloadRef', 'payloadDigest', 'createdAt']);
  if (item.schemaVersion !== 1 || controlWireRef(item.payloadRef) !== controlWireRef(item.payloadDigest)) invalid('Run item payload identity differs');
  controlWireText(item.itemId); controlWireInteger(item.itemSeq, 1); time(item.createdAt);
  return item as RunItemReferenceV1;
}
export function decodeWireSessionItem(value: unknown): SessionItem {
  const item = controlWireRecord(value, ['schemaVersion', 'itemId', 'sessionId', 'itemSeq', 'kind', 'payloadRef', 'createdAt']);
  if (item.schemaVersion !== 1 || !['compaction', 'run_terminal', 'legacy_record', 'legacy_compaction', 'legacy_plan', 'legacy_handoff', 'legacy_bookmark'].includes(item.kind as string))
    invalid('Session item kind is invalid');
  controlWireText(item.itemId); controlWireText(item.sessionId); controlWireInteger(item.itemSeq, 1); controlWireRef(item.payloadRef); time(item.createdAt);
  return item as SessionItem;
}
export function decodeWireArtifactDescriptor(value: unknown): ArtifactDescriptorV1 {
  const data = controlWireRecord(value, ['schemaVersion', 'ref', 'digest', 'sizeBytes', 'mediaType']);
  if (data.schemaVersion !== 1 || controlWireRef(data.ref) !== controlWireRef(data.digest)) invalid('invalid artifact descriptor');
  controlWireInteger(data.sizeBytes); controlWireText(data.mediaType);
  return data as ArtifactDescriptorV1;
}
export function decodeWireRuntimeBundleSummary(value: unknown): Readonly<{
  schemaVersion: 1; runtimeBundleRef: string; bundleDigest: string; bundleVersion: string;
}> {
  const data = controlWireRecord(value, ['schemaVersion', 'runtimeBundleRef', 'bundleDigest', 'bundleVersion']);
  if (data.schemaVersion !== 1 || controlWireRef(data.runtimeBundleRef) !== controlWireRef(data.bundleDigest)) invalid('invalid RuntimeBundle summary');
  controlWireText(data.bundleVersion);
  return data as { schemaVersion: 1; runtimeBundleRef: string; bundleDigest: string; bundleVersion: string };
}
export function decodeWireGrantSummary(value: unknown): AuthorizationGrantSummaryV1 {
  const data = controlWireRecord(value, ['schemaVersion', 'grantId', 'state', 'targetKind', 'purpose', 'targetDigest', 'useCount', 'rowVersion', 'createdAt', 'expiresAt'],
    ['consumedAt', 'revokedAt']);
  const { state, targetKind, purpose } = data;
  const validPurpose = targetKind === 'read_scope' ? purpose === 'source' : targetKind === 'execution_identity_read'
    ? purpose === 'verifier' || purpose === 'mcp_stdio' : targetKind === 'verifier_execution' ? purpose === 'verifier'
      : targetKind === 'dependency_install_scripts' && purpose === 'dependency_install_scripts';
  if (data.schemaVersion !== 1 || !['active', 'consumed', 'revoked'].includes(state as string) || !validPurpose ||
      data.useCount !== (state === 'consumed' ? 1 : 0) || data.rowVersion !== (state === 'active' ? 1 : 2) ||
      Object.hasOwn(data, 'consumedAt') !== (state === 'consumed') || Object.hasOwn(data, 'revokedAt') !== (state === 'revoked'))
    invalid('authorization summary has an invalid closed lifecycle');
  controlWireText(data.grantId); controlWireRef(data.targetDigest); time(data.createdAt); time(data.expiresAt);
  const start = parseCanonicalTime(data.createdAt as string), expiry = parseCanonicalTime(data.expiresAt as string);
  if (expiry <= start || expiry - start > 86_400_000) invalid('authorization summary lifetime is invalid');
  if (state === 'consumed') {
    time(data.consumedAt);
    if (parseCanonicalTime(data.consumedAt as string) < start || (data.consumedAt as string) >= (data.expiresAt as string))
      invalid('authorization summary consumption is outside its lifetime');
  }
  if (state === 'revoked') {
    time(data.revokedAt);
    if (parseCanonicalTime(data.revokedAt as string) < start) invalid('authorization summary revocation precedes creation');
  }
  return data as AuthorizationGrantSummaryV1;
}

const JOURNAL_BASE_KEYS = [
  'seq',
  'runId',
  'opId',
  'opKind',
  'attempt',
  'leaseEpoch',
  'phase',
  'target',
  'requestRef',
  'replayClass',
  'idempotencyKey',
  'grantRef',
  'budgetDelta',
  'timestamp'
] as const;
const JOURNAL_CLAIM_KEYS = [
  'sandboxLaunchSpecRef',
  'dispatchId',
  'supervisorInstanceId',
  'stateOwnerEpoch',
  'brokerFenceTokenDigest'
] as const;
const JOURNAL_TERMINAL_KEYS = [
  'resultRef',
  'receiptRef',
  'errorRef',
  'evidenceRef',
  'evidenceDigest',
  'attestationRef',
  'budgetSettlementRef'
] as const;

function decodeJournalBase(record: Record<string, unknown>): void {
  requireSafeInteger(record.seq, 'Journal.seq', 1);
  requireString(record.runId, 'Journal.runId');
  requireString(record.opId, 'Journal.opId');
  if (typeof record.opKind !== 'string' || !['model', 'tool', 'mcp-server', 'mcp', 'verifier', 'publish'].includes(record.opKind)) {
    invalid('Journal.opKind is not closed');
  }
  requireSafeInteger(record.attempt, 'Journal.attempt');
  requireSafeInteger(record.leaseEpoch, 'Journal.leaseEpoch', 1);
  requireString(record.target, 'Journal.target');
  requireArtifactRef(record.requestRef, 'Journal.requestRef');
  if (typeof record.replayClass !== 'string' || !['retry', 'workspace-rollback-retry', 'reconcile', 'manual'].includes(record.replayClass)) {
    invalid('Journal.replayClass is not closed');
  }
  if (has(record, 'idempotencyKey')) requireString(record.idempotencyKey, 'Journal.idempotencyKey');
  if (has(record, 'grantRef')) requireArtifactRef(record.grantRef, 'Journal.grantRef');
  decodeWireBudget(record.budgetDelta, 'Journal.budgetDelta');
  requireCanonicalTime(record.timestamp, 'Journal.timestamp');
  requireEvidencePair(record, 'evidenceRef', 'evidenceDigest', 'Journal');
}

function requireClaimIdentity(record: Record<string, unknown>): void {
  requireString(record.dispatchId, 'Journal.dispatchId');
  requireString(record.supervisorInstanceId, 'Journal.supervisorInstanceId');
  requireSafeInteger(record.stateOwnerEpoch, 'Journal.stateOwnerEpoch', 1);
  if (has(record, 'sandboxLaunchSpecRef')) {
    requireArtifactRef(record.sandboxLaunchSpecRef, 'Journal.sandboxLaunchSpecRef');
  }
  if (has(record, 'brokerFenceTokenDigest')) {
    requireDigest(record.brokerFenceTokenDigest, 'Journal.brokerFenceTokenDigest');
  }
}

export function decodeWireJournal(value: unknown): InvocationJournalEntry {
  const record = requireRecord(value, 'Journal');
  decodeJournalBase(record);
  const phase = record.phase;
  if (typeof phase !== 'string' || !['prepared', 'dispatch_claimed', 'completed', 'failed', 'unknown', 'abandoned'].includes(phase)) {
    invalid('Journal.phase is not closed');
  }

  if (phase === 'prepared') {
    rejectUnknownKeys(record, JOURNAL_BASE_KEYS, 'Journal(prepared)');
    requireAbsent(record, [...JOURNAL_CLAIM_KEYS, ...JOURNAL_TERMINAL_KEYS], 'Journal(prepared)');
  } else if (phase === 'dispatch_claimed') {
    const birthKeys = record.opKind === 'publish' ? ['evidenceRef', 'evidenceDigest'] : [];
    rejectUnknownKeys(record, [...JOURNAL_BASE_KEYS, ...JOURNAL_CLAIM_KEYS, ...birthKeys], 'Journal(dispatch_claimed)');
    requireClaimIdentity(record);
    if (!isZeroBudget(decodeWireBudget(record.budgetDelta, 'Journal.budgetDelta'))) {
      invalid('dispatch_claimed must have zero budgetDelta');
    }
    requireAbsent(record, JOURNAL_TERMINAL_KEYS.filter(key => !birthKeys.includes(key)), 'Journal(dispatch_claimed)');
    if (record.opKind === 'publish' && (!has(record, 'evidenceRef') || !has(record, 'evidenceDigest')))
      invalid('publication dispatch requires its complete original arena birth evidence');
  } else if (phase === 'completed') {
    rejectUnknownKeys(record, [...JOURNAL_BASE_KEYS, ...JOURNAL_CLAIM_KEYS, 'resultRef', 'receiptRef', 'budgetSettlementRef',
      ...(record.opKind === 'publish' ? ['evidenceRef', 'evidenceDigest'] : [])], 'Journal(completed)');
    requireClaimIdentity(record);
    requireArtifactRef(record.budgetSettlementRef, 'Journal.budgetSettlementRef');
    if (!has(record, 'resultRef') && !has(record, 'receiptRef')) invalid('completed requires a result or receipt');
    if (has(record, 'resultRef')) requireArtifactRef(record.resultRef, 'Journal.resultRef');
    if (has(record, 'receiptRef')) requireArtifactRef(record.receiptRef, 'Journal.receiptRef');
    if (record.opKind === 'publish' && (!has(record, 'receiptRef') || !has(record, 'evidenceRef') ||
        record.receiptRef !== record.evidenceRef)) invalid('completed publication requires its identical terminal receipt and evidence');
  } else if (phase === 'unknown') {
    rejectUnknownKeys(record, [...JOURNAL_BASE_KEYS, ...JOURNAL_CLAIM_KEYS, 'evidenceRef', 'evidenceDigest', 'budgetSettlementRef'], 'Journal(unknown)');
    requireClaimIdentity(record);
    requireEvidencePair(record, 'evidenceRef', 'evidenceDigest', 'Journal(unknown)');
    if (!has(record, 'evidenceRef')) invalid('unknown requires ambiguity evidence');
    requireArtifactRef(record.budgetSettlementRef, 'Journal.budgetSettlementRef');
  } else if (phase === 'abandoned') {
    rejectUnknownKeys(record, [...JOURNAL_BASE_KEYS, ...JOURNAL_CLAIM_KEYS, 'attestationRef', 'budgetSettlementRef'], 'Journal(abandoned)');
    requireClaimIdentity(record);
    requireArtifactRef(record.attestationRef, 'Journal.attestationRef');
    requireArtifactRef(record.budgetSettlementRef, 'Journal.budgetSettlementRef');
    if (!isZeroBudget(decodeWireBudget(record.budgetDelta, 'Journal.budgetDelta'))) {
      invalid('abandoned must have zero additional budgetDelta');
    }
  } else {
    const claimed = has(record, 'dispatchId') || has(record, 'supervisorInstanceId') || has(record, 'stateOwnerEpoch');
    if (claimed) {
      rejectUnknownKeys(record, [...JOURNAL_BASE_KEYS, ...JOURNAL_CLAIM_KEYS, 'errorRef', 'receiptRef', 'evidenceRef', 'evidenceDigest', 'budgetSettlementRef'], 'Journal(failed post-claim)');
      requireClaimIdentity(record);
      requireArtifactRef(record.errorRef, 'Journal.errorRef');
      requireArtifactRef(record.budgetSettlementRef, 'Journal.budgetSettlementRef');
      if (has(record, 'evidenceRef')) requireEvidencePair(record, 'evidenceRef', 'evidenceDigest', 'Journal(failed post-claim)');
      if (!has(record, 'evidenceRef') && record.opKind !== 'verifier') {
        invalid('post-claim failed requires no-release evidence');
      }
      if (has(record, 'receiptRef')) requireArtifactRef(record.receiptRef, 'Journal.receiptRef');
    } else {
      rejectUnknownKeys(record, [...JOURNAL_BASE_KEYS, 'errorRef', 'budgetSettlementRef'], 'Journal(failed pre-dispatch)');
      requireArtifactRef(record.errorRef, 'Journal.errorRef');
      requireArtifactRef(record.budgetSettlementRef, 'Journal.budgetSettlementRef');
      if (!isZeroBudget(decodeWireBudget(record.budgetDelta, 'Journal.budgetDelta'))) {
        invalid('pre-dispatch failed must consume zero budget');
      }
    }
  }
  return record as InvocationJournalEntry;
}
