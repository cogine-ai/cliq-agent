import {
  assertArtifactRef,
  parseCanonicalTime,
  requiredSafeInteger
} from '../kernel/identity.js';
import type {
  BudgetUsage,
  ChildAllocationV1,
  InvocationJournalEntry,
  WorkerLaunch,
  WorkspaceGenerationStateV1
} from '../kernel/types.js';
import { KernelStorageError } from './errors.js';

const BUDGET_FIELDS = ['modelTokens', 'costMicros', 'toolCalls', 'repairAttempts'] as const;
const ZERO_BUDGET: BudgetUsage = {
  modelTokens: 0,
  costMicros: 0,
  toolCalls: 0,
  repairAttempts: 0
};

function invalid(message: string): never {
  throw new KernelStorageError('STATE_TRANSITION_INVALID', message);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) invalid(`${label} must be an object`);
  return value;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) invalid(`${label} must be a nonempty string`);
  return value;
}

function requireCanonicalTime(value: unknown, label: string): string {
  const timestamp = requireString(value, label);
  try {
    parseCanonicalTime(timestamp);
  } catch {
    invalid(`${label} must be a canonical UTC millisecond`);
  }
  return timestamp;
}

function requireArtifactRef(value: unknown, label: string): string {
  const ref = requireString(value, label);
  try {
    assertArtifactRef(ref);
  } catch {
    invalid(`${label} must be a canonical ArtifactRef`);
  }
  return ref;
}

function requireDigest(value: unknown, label: string): string {
  return requireArtifactRef(value, label);
}

function requireSafeInteger(value: unknown, label: string, minimum = 0): number {
  let parsed: number;
  try {
    parsed = requiredSafeInteger(value, label);
  } catch {
    invalid(`${label} must be a safe integer`);
  }
  if (parsed! < minimum) invalid(`${label} must be at least ${minimum}`);
  return parsed!;
}

function requireLiteral<T extends string | number | boolean>(
  value: unknown,
  expected: T,
  label: string
): T {
  if (value !== expected) invalid(`${label} must be ${String(expected)}`);
  return expected;
}

function rejectUnknownKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) invalid(`${label}.${key} is not legal in this state`);
  }
}

function has(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function requireAbsent(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  for (const key of keys) {
    if (has(value, key)) invalid(`${label}.${key} is forbidden in this state`);
  }
}

function requireEvidencePair(value: Record<string, unknown>, refKey: string, digestKey: string, label: string): void {
  if (has(value, refKey) !== has(value, digestKey)) {
    invalid(`${label}.${refKey}/${digestKey} must be present or absent together`);
  }
  if (has(value, refKey)) {
    requireArtifactRef(value[refKey], `${label}.${refKey}`);
    requireDigest(value[digestKey], `${label}.${digestKey}`);
  }
}

export function decodeBudgetUsage(value: unknown, label = 'BudgetUsage'): BudgetUsage {
  const record = requireRecord(value, label);
  rejectUnknownKeys(record, BUDGET_FIELDS, label);
  for (const field of BUDGET_FIELDS) requireSafeInteger(record[field], `${label}.${field}`);
  return {
    modelTokens: record.modelTokens as number,
    costMicros: record.costMicros as number,
    toolCalls: record.toolCalls as number,
    repairAttempts: record.repairAttempts as number
  };
}

export function isZeroBudget(value: BudgetUsage): boolean {
  return BUDGET_FIELDS.every((field) => value[field] === 0);
}

export function addBudget(left: BudgetUsage, right: BudgetUsage, label = 'budget sum'): BudgetUsage {
  const result = { ...ZERO_BUDGET };
  for (const field of BUDGET_FIELDS) {
    const next = left[field] + right[field];
    if (!Number.isSafeInteger(next) || next < 0) invalid(`${label}.${field} overflowed`);
    result[field] = next;
  }
  return result;
}

export function subtractBudget(left: BudgetUsage, right: BudgetUsage, label = 'budget difference'): BudgetUsage {
  const result = { ...ZERO_BUDGET };
  for (const field of BUDGET_FIELDS) {
    const next = left[field] - right[field];
    if (!Number.isSafeInteger(next) || next < 0) invalid(`${label}.${field} would be negative`);
    result[field] = next;
  }
  return result;
}

export function assertBudgetWithin(
  consumed: BudgetUsage,
  reserved: BudgetUsage,
  required: BudgetUsage,
  ceilings: BudgetUsage
): void {
  for (const field of BUDGET_FIELDS) {
    const total = consumed[field] + reserved[field] + required[field];
    if (!Number.isSafeInteger(total) || total > ceilings[field]) {
      throw new KernelStorageError('BUDGET_EXHAUSTED', `${field} reservation exceeds the admitted ceiling`);
    }
  }
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
  if (!['model', 'tool', 'mcp-server', 'mcp', 'verifier', 'publish'].includes(String(record.opKind))) {
    invalid('Journal.opKind is not closed');
  }
  requireSafeInteger(record.attempt, 'Journal.attempt');
  requireSafeInteger(record.leaseEpoch, 'Journal.leaseEpoch', 1);
  requireString(record.target, 'Journal.target');
  requireArtifactRef(record.requestRef, 'Journal.requestRef');
  if (!['retry', 'workspace-rollback-retry', 'reconcile', 'manual'].includes(String(record.replayClass))) {
    invalid('Journal.replayClass is not closed');
  }
  if (has(record, 'idempotencyKey')) requireString(record.idempotencyKey, 'Journal.idempotencyKey');
  if (has(record, 'grantRef')) requireArtifactRef(record.grantRef, 'Journal.grantRef');
  decodeBudgetUsage(record.budgetDelta, 'Journal.budgetDelta');
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

export function decodeInvocationJournalEntry(value: unknown): InvocationJournalEntry {
  const record = requireRecord(value, 'Journal');
  decodeJournalBase(record);
  const phase = record.phase;
  if (!['prepared', 'dispatch_claimed', 'completed', 'failed', 'unknown', 'abandoned'].includes(String(phase))) {
    invalid('Journal.phase is not closed');
  }

  if (phase === 'prepared') {
    rejectUnknownKeys(record, JOURNAL_BASE_KEYS, 'Journal(prepared)');
    requireAbsent(record, [...JOURNAL_CLAIM_KEYS, ...JOURNAL_TERMINAL_KEYS], 'Journal(prepared)');
  } else if (phase === 'dispatch_claimed') {
    rejectUnknownKeys(record, [...JOURNAL_BASE_KEYS, ...JOURNAL_CLAIM_KEYS], 'Journal(dispatch_claimed)');
    requireClaimIdentity(record);
    if (!isZeroBudget(decodeBudgetUsage(record.budgetDelta, 'Journal.budgetDelta'))) {
      invalid('dispatch_claimed must have zero budgetDelta');
    }
    requireAbsent(record, JOURNAL_TERMINAL_KEYS, 'Journal(dispatch_claimed)');
  } else if (phase === 'completed') {
    rejectUnknownKeys(record, [...JOURNAL_BASE_KEYS, ...JOURNAL_CLAIM_KEYS, 'resultRef', 'receiptRef', 'budgetSettlementRef'], 'Journal(completed)');
    requireClaimIdentity(record);
    requireArtifactRef(record.budgetSettlementRef, 'Journal.budgetSettlementRef');
    if (!has(record, 'resultRef') && !has(record, 'receiptRef')) invalid('completed requires a result or receipt');
    if (has(record, 'resultRef')) requireArtifactRef(record.resultRef, 'Journal.resultRef');
    if (has(record, 'receiptRef')) requireArtifactRef(record.receiptRef, 'Journal.receiptRef');
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
    if (!isZeroBudget(decodeBudgetUsage(record.budgetDelta, 'Journal.budgetDelta'))) {
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
      if (!isZeroBudget(decodeBudgetUsage(record.budgetDelta, 'Journal.budgetDelta'))) {
        invalid('pre-dispatch failed must consume zero budget');
      }
    }
  }
  return record as InvocationJournalEntry;
}

const WORKER_BASE_KEYS = [
  'schemaVersion',
  'launchId',
  'runId',
  'plannedRunRevision',
  'supervisorInstanceId',
  'spawnNonceDigest',
  'activationNonceDigest',
  'phase',
  'workspaceGenerationRef',
  'containmentPlanRef',
  'sandboxLaunchSpecRef',
  'leaseVersion',
  'generationWriteState',
  'createdAt',
  'activationDeadlineAt'
] as const;
const WORKER_IDENTITY_KEYS = ['workerIdentityDigest', 'processContainmentRef'] as const;
const WORKER_LEASE_KEYS = ['leaseEpoch', 'leaseExpiresAt', 'activatedAt'] as const;

export function decodeWorkerLaunch(value: unknown): WorkerLaunch {
  const record = requireRecord(value, 'WorkerLaunch');
  requireLiteral(record.schemaVersion, 1, 'WorkerLaunch.schemaVersion');
  requireString(record.launchId, 'WorkerLaunch.launchId');
  requireString(record.runId, 'WorkerLaunch.runId');
  requireSafeInteger(record.plannedRunRevision, 'WorkerLaunch.plannedRunRevision', 1);
  requireString(record.supervisorInstanceId, 'WorkerLaunch.supervisorInstanceId');
  requireDigest(record.spawnNonceDigest, 'WorkerLaunch.spawnNonceDigest');
  requireDigest(record.activationNonceDigest, 'WorkerLaunch.activationNonceDigest');
  requireArtifactRef(record.workspaceGenerationRef, 'WorkerLaunch.workspaceGenerationRef');
  requireArtifactRef(record.containmentPlanRef, 'WorkerLaunch.containmentPlanRef');
  requireArtifactRef(record.sandboxLaunchSpecRef, 'WorkerLaunch.sandboxLaunchSpecRef');
  requireSafeInteger(record.leaseVersion, 'WorkerLaunch.leaseVersion');
  requireCanonicalTime(record.createdAt, 'WorkerLaunch.createdAt');
  requireCanonicalTime(record.activationDeadlineAt, 'WorkerLaunch.activationDeadlineAt');
  const phase = record.phase;
  if (!['reserved', 'preactivated', 'activated', 'reconciling', 'retired'].includes(String(phase))) {
    invalid('WorkerLaunch.phase is not closed');
  }
  if (!['preactivated_readonly', 'active', 'revoking', 'checkpointing', 'fenced_reconciling', 'sealed'].includes(String(record.generationWriteState))) {
    invalid('WorkerLaunch.generationWriteState is not closed');
  }

  if (phase === 'reserved') {
    rejectUnknownKeys(record, WORKER_BASE_KEYS, 'WorkerLaunch(reserved)');
    requireLiteral(record.leaseVersion, 0, 'WorkerLaunch.leaseVersion');
    requireLiteral(record.generationWriteState, 'preactivated_readonly', 'WorkerLaunch.generationWriteState');
  } else if (phase === 'preactivated') {
    rejectUnknownKeys(record, [...WORKER_BASE_KEYS, ...WORKER_IDENTITY_KEYS], 'WorkerLaunch(preactivated)');
    requireDigest(record.workerIdentityDigest, 'WorkerLaunch.workerIdentityDigest');
    requireArtifactRef(record.processContainmentRef, 'WorkerLaunch.processContainmentRef');
    requireLiteral(record.leaseVersion, 0, 'WorkerLaunch.leaseVersion');
    requireLiteral(record.generationWriteState, 'preactivated_readonly', 'WorkerLaunch.generationWriteState');
  } else if (phase === 'activated') {
    rejectUnknownKeys(record, [...WORKER_BASE_KEYS, ...WORKER_IDENTITY_KEYS, ...WORKER_LEASE_KEYS, 'quiesceId'], 'WorkerLaunch(activated)');
    requireDigest(record.workerIdentityDigest, 'WorkerLaunch.workerIdentityDigest');
    requireArtifactRef(record.processContainmentRef, 'WorkerLaunch.processContainmentRef');
    requireSafeInteger(record.leaseEpoch, 'WorkerLaunch.leaseEpoch', 1);
    requireSafeInteger(record.leaseVersion, 'WorkerLaunch.leaseVersion', 1);
    requireCanonicalTime(record.leaseExpiresAt, 'WorkerLaunch.leaseExpiresAt');
    requireCanonicalTime(record.activatedAt, 'WorkerLaunch.activatedAt');
    if (!['active', 'revoking', 'checkpointing'].includes(String(record.generationWriteState))) {
      invalid('activated launch must project an active/revoking/checkpointing generation');
    }
    if ((record.generationWriteState === 'active') === has(record, 'quiesceId')) {
      invalid('quiesceId is required exactly while an activated launch is revoking/checkpointing');
    }
  } else if (phase === 'reconciling') {
    rejectUnknownKeys(record, [...WORKER_BASE_KEYS, ...WORKER_IDENTITY_KEYS, ...WORKER_LEASE_KEYS, 'quiesceId'], 'WorkerLaunch(reconciling)');
    requireDigest(record.workerIdentityDigest, 'WorkerLaunch.workerIdentityDigest');
    requireArtifactRef(record.processContainmentRef, 'WorkerLaunch.processContainmentRef');
    requireSafeInteger(record.leaseEpoch, 'WorkerLaunch.leaseEpoch', 1);
    requireSafeInteger(record.leaseVersion, 'WorkerLaunch.leaseVersion', 1);
    requireCanonicalTime(record.leaseExpiresAt, 'WorkerLaunch.leaseExpiresAt');
    requireCanonicalTime(record.activatedAt, 'WorkerLaunch.activatedAt');
    requireLiteral(record.generationWriteState, 'fenced_reconciling', 'WorkerLaunch.generationWriteState');
    if (has(record, 'quiesceId')) requireString(record.quiesceId, 'WorkerLaunch.quiesceId');
  } else {
    rejectUnknownKeys(record, [...WORKER_BASE_KEYS, ...WORKER_IDENTITY_KEYS, ...WORKER_LEASE_KEYS, 'quiesceId', 'retiredAt', 'retirementEvidenceRef'], 'WorkerLaunch(retired)');
    requireCanonicalTime(record.retiredAt, 'WorkerLaunch.retiredAt');
    requireArtifactRef(record.retirementEvidenceRef, 'WorkerLaunch.retirementEvidenceRef');
    if (has(record, 'workerIdentityDigest')) {
      requireDigest(record.workerIdentityDigest, 'WorkerLaunch.workerIdentityDigest');
    }
    if (has(record, 'processContainmentRef')) {
      requireArtifactRef(record.processContainmentRef, 'WorkerLaunch.processContainmentRef');
    }
    if (has(record, 'leaseEpoch')) requireSafeInteger(record.leaseEpoch, 'WorkerLaunch.leaseEpoch', 1);
    if (has(record, 'leaseExpiresAt')) {
      requireCanonicalTime(record.leaseExpiresAt, 'WorkerLaunch.leaseExpiresAt');
    }
    if (has(record, 'activatedAt')) requireCanonicalTime(record.activatedAt, 'WorkerLaunch.activatedAt');
    if (has(record, 'quiesceId')) requireString(record.quiesceId, 'WorkerLaunch.quiesceId');
    if (!['sealed', 'fenced_reconciling'].includes(String(record.generationWriteState))) {
      invalid('retired launch must retain sealed or fenced generation projection');
    }
  }
  return record as WorkerLaunch;
}

const GENERATION_BASE_KEYS = [
  'schemaVersion',
  'generationId',
  'runId',
  'generationRef',
  'generationIdentityDigest',
  'rowVersion',
  'sourceCheckpointId',
  'sourceWorkspaceStateRef',
  'sourceWorkspaceStateDigest',
  'lastVerifiedTreeDigest',
  'updatedAt',
  'phase'
] as const;

export function decodeWorkspaceGenerationState(value: unknown): WorkspaceGenerationStateV1 {
  const record = requireRecord(value, 'WorkspaceGeneration');
  requireLiteral(record.schemaVersion, 1, 'WorkspaceGeneration.schemaVersion');
  requireString(record.generationId, 'WorkspaceGeneration.generationId');
  requireString(record.runId, 'WorkspaceGeneration.runId');
  requireArtifactRef(record.generationRef, 'WorkspaceGeneration.generationRef');
  requireDigest(record.generationIdentityDigest, 'WorkspaceGeneration.generationIdentityDigest');
  requireSafeInteger(record.rowVersion, 'WorkspaceGeneration.rowVersion', 1);
  requireString(record.sourceCheckpointId, 'WorkspaceGeneration.sourceCheckpointId');
  requireArtifactRef(record.sourceWorkspaceStateRef, 'WorkspaceGeneration.sourceWorkspaceStateRef');
  requireDigest(record.sourceWorkspaceStateDigest, 'WorkspaceGeneration.sourceWorkspaceStateDigest');
  requireDigest(record.lastVerifiedTreeDigest, 'WorkspaceGeneration.lastVerifiedTreeDigest');
  requireCanonicalTime(record.updatedAt, 'WorkspaceGeneration.updatedAt');
  const phase = record.phase;
  const evidence = ['snapshotEvidenceRef', 'snapshotEvidenceDigest'] as const;
  const active = ['activeWorkerLaunchId', 'leaseEpoch'] as const;

  if (phase === 'materializing') {
    rejectUnknownKeys(record, GENERATION_BASE_KEYS, 'WorkspaceGeneration(materializing)');
  } else if (phase === 'preactivated_readonly' || phase === 'sealed') {
    rejectUnknownKeys(record, [...GENERATION_BASE_KEYS, ...evidence], `WorkspaceGeneration(${String(phase)})`);
    requireEvidencePair(record, evidence[0], evidence[1], 'WorkspaceGeneration');
  } else if (phase === 'active') {
    rejectUnknownKeys(record, [...GENERATION_BASE_KEYS, ...evidence, ...active], 'WorkspaceGeneration(active)');
    requireEvidencePair(record, evidence[0], evidence[1], 'WorkspaceGeneration');
    requireString(record.activeWorkerLaunchId, 'WorkspaceGeneration.activeWorkerLaunchId');
    requireSafeInteger(record.leaseEpoch, 'WorkspaceGeneration.leaseEpoch', 1);
  } else if (phase === 'revoking' || phase === 'checkpointing') {
    rejectUnknownKeys(record, [...GENERATION_BASE_KEYS, ...evidence, ...active, 'quiesceId'], `WorkspaceGeneration(${String(phase)})`);
    requireEvidencePair(record, evidence[0], evidence[1], 'WorkspaceGeneration');
    requireString(record.activeWorkerLaunchId, 'WorkspaceGeneration.activeWorkerLaunchId');
    requireSafeInteger(record.leaseEpoch, 'WorkspaceGeneration.leaseEpoch', 1);
    requireString(record.quiesceId, 'WorkspaceGeneration.quiesceId');
  } else if (phase === 'fenced_reconciling') {
    rejectUnknownKeys(record, [...GENERATION_BASE_KEYS, ...evidence, ...active, 'waitingSubjectRef', 'waitingSubjectDigest', 'fencedFromPhase', 'quiesceId'], 'WorkspaceGeneration(fenced_reconciling)');
    requireEvidencePair(record, evidence[0], evidence[1], 'WorkspaceGeneration');
    requireString(record.activeWorkerLaunchId, 'WorkspaceGeneration.activeWorkerLaunchId');
    requireSafeInteger(record.leaseEpoch, 'WorkspaceGeneration.leaseEpoch', 1);
    requireEvidencePair(record, 'waitingSubjectRef', 'waitingSubjectDigest', 'WorkspaceGeneration');
    if (!['active', 'revoking', 'checkpointing'].includes(String(record.fencedFromPhase))) {
      invalid('fencedFromPhase is not closed');
    }
    if ((record.fencedFromPhase === 'active') === has(record, 'quiesceId')) {
      invalid('quiesceId is required exactly when fencing revoking/checkpointing');
    }
  } else if (phase === 'quarantined') {
    rejectUnknownKeys(record, [...GENERATION_BASE_KEYS, 'quarantineEvidenceRef', 'quarantineEvidenceDigest', 'observedState'], 'WorkspaceGeneration(quarantined)');
    requireEvidencePair(record, 'quarantineEvidenceRef', 'quarantineEvidenceDigest', 'WorkspaceGeneration');
    requireRecord(record.observedState, 'WorkspaceGeneration.observedState');
  } else if (phase === 'retired') {
    rejectUnknownKeys(record, [...GENERATION_BASE_KEYS, 'retirementEvidenceRef', 'retirementEvidenceDigest'], 'WorkspaceGeneration(retired)');
    requireEvidencePair(record, 'retirementEvidenceRef', 'retirementEvidenceDigest', 'WorkspaceGeneration');
  } else {
    invalid('WorkspaceGeneration.phase is not closed');
  }
  return record as WorkspaceGenerationStateV1;
}

const CHILD_BASE_KEYS = [
  'schemaVersion',
  'parentRunId',
  'childRunId',
  'admissionKey',
  'delegateBatchItemId',
  'delegateCallId',
  'delegateCallIndex',
  'delegateOpId',
  'delegateOperationGrantRef',
  'capabilityGrantRef',
  'mode',
  'grantedAdditiveCeilings',
  'grantedChildDepth',
  'grantedChildConcurrency',
  'childDeadlineAt',
  'createdAt',
  'state'
] as const;

function decodeChildTerminal(value: unknown, expectedMode: 'read_only' | 'mutating'): void {
  const terminal = requireRecord(value, 'ChildAllocation.terminal');
  if (terminal.mode !== expectedMode) invalid('ChildAllocation terminal mode changed');
  if (!['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(String(terminal.status))) {
    invalid('ChildAllocation terminal status is invalid');
  }
  requireArtifactRef(terminal.modelContentRef, 'ChildAllocation.terminal.modelContentRef');
  requireDigest(terminal.modelContentDigest, 'ChildAllocation.terminal.modelContentDigest');
  if (terminal.status === 'succeeded' || terminal.status === 'completed_unverified') {
    const allowed = expectedMode === 'mutating'
      ? ['mode', 'status', 'resultRef', 'patchManifestRef', 'modelContentRef', 'modelContentDigest']
      : ['mode', 'status', 'resultRef', 'modelContentRef', 'modelContentDigest'];
    rejectUnknownKeys(terminal, allowed, 'ChildAllocation.terminal');
    requireArtifactRef(terminal.resultRef, 'ChildAllocation.terminal.resultRef');
    if (expectedMode === 'mutating') {
      requireArtifactRef(terminal.patchManifestRef, 'ChildAllocation.terminal.patchManifestRef');
    }
  } else {
    rejectUnknownKeys(
      terminal,
      ['mode', 'status', 'terminalDetailRef', 'modelContentRef', 'modelContentDigest'],
      'ChildAllocation.terminal'
    );
    requireArtifactRef(terminal.terminalDetailRef, 'ChildAllocation.terminal.terminalDetailRef');
  }
}

export function decodeChildAllocation(value: unknown): ChildAllocationV1 {
  const record = requireRecord(value, 'ChildAllocation');
  requireLiteral(record.schemaVersion, 1, 'ChildAllocation.schemaVersion');
  requireString(record.parentRunId, 'ChildAllocation.parentRunId');
  requireString(record.childRunId, 'ChildAllocation.childRunId');
  if (record.parentRunId === record.childRunId) invalid('ChildAllocation cannot point a Run at itself');
  requireString(record.admissionKey, 'ChildAllocation.admissionKey');
  requireString(record.delegateBatchItemId, 'ChildAllocation.delegateBatchItemId');
  requireString(record.delegateCallId, 'ChildAllocation.delegateCallId');
  requireSafeInteger(record.delegateCallIndex, 'ChildAllocation.delegateCallIndex');
  requireString(record.delegateOpId, 'ChildAllocation.delegateOpId');
  requireArtifactRef(record.delegateOperationGrantRef, 'ChildAllocation.delegateOperationGrantRef');
  requireArtifactRef(record.capabilityGrantRef, 'ChildAllocation.capabilityGrantRef');
  if (record.mode !== 'read_only' && record.mode !== 'mutating') invalid('ChildAllocation.mode is invalid');
  decodeBudgetUsage(record.grantedAdditiveCeilings, 'ChildAllocation.grantedAdditiveCeilings');
  requireSafeInteger(record.grantedChildDepth, 'ChildAllocation.grantedChildDepth');
  requireSafeInteger(record.grantedChildConcurrency, 'ChildAllocation.grantedChildConcurrency', 1);
  requireCanonicalTime(record.childDeadlineAt, 'ChildAllocation.childDeadlineAt');
  requireCanonicalTime(record.createdAt, 'ChildAllocation.createdAt');

  if (record.state === 'reserved') {
    rejectUnknownKeys(record, CHILD_BASE_KEYS, 'ChildAllocation(reserved)');
  } else if (record.state === 'child_terminal') {
    rejectUnknownKeys(
      record,
      [...CHILD_BASE_KEYS, 'terminal', 'inclusiveBudgetUsage', 'terminalAt'],
      'ChildAllocation(child_terminal)'
    );
    decodeChildTerminal(record.terminal, record.mode);
    decodeBudgetUsage(record.inclusiveBudgetUsage, 'ChildAllocation.inclusiveBudgetUsage');
    requireCanonicalTime(record.terminalAt, 'ChildAllocation.terminalAt');
  } else if (record.state === 'settled') {
    rejectUnknownKeys(
      record,
      [
        ...CHILD_BASE_KEYS,
        'terminal',
        'inclusiveBudgetUsage',
        'terminalAt',
        'childResultItemId',
        'parentSettlementRevision',
        'releasedUnusedBudget',
        'settledAt'
      ],
      'ChildAllocation(settled)'
    );
    decodeChildTerminal(record.terminal, record.mode);
    decodeBudgetUsage(record.inclusiveBudgetUsage, 'ChildAllocation.inclusiveBudgetUsage');
    requireCanonicalTime(record.terminalAt, 'ChildAllocation.terminalAt');
    requireString(record.childResultItemId, 'ChildAllocation.childResultItemId');
    requireSafeInteger(record.parentSettlementRevision, 'ChildAllocation.parentSettlementRevision', 1);
    decodeBudgetUsage(record.releasedUnusedBudget, 'ChildAllocation.releasedUnusedBudget');
    requireCanonicalTime(record.settledAt, 'ChildAllocation.settledAt');
  } else {
    invalid('ChildAllocation.state is invalid');
  }
  return record as ChildAllocationV1;
}
