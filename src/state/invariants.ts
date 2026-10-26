import {
  assertArtifactRef,
  identityHash,
  parseCanonicalTime,
  requiredSafeInteger
} from '../kernel/identity.js';
import type {
  BudgetUsage,
  ChildAllocationV1,
  InvocationJournalEntry,
  PreparingWorkerLaunch,
  RetiredWorkerPreparation,
  WorkerLaunch,
  WorkerPreparation,
  WorkspaceGenerationStateV1
} from '../kernel/types.js';
import { KernelStorageError } from './errors.js';
import { types } from 'node:util';

import { assertControlWireJson, BUDGET_FIELDS, decodeWireBudget, decodeWireJournal } from '../kernel/control-wire-data.js';
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
  try { return decodeWireBudget(value, label); }
  catch (error) { if (error instanceof TypeError) invalid(error.message); throw error; }
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

export function decodeInvocationJournalEntry(value: unknown): InvocationJournalEntry {
  try {
    // Retained storage historically accepts safe bigint counters. Normalize
    // only those closed numeric positions for the common data validator;
    // public JSON/wire callers still reject bigint before this seam.
    const copy = (input: unknown, integers: readonly string[]): unknown => {
      if (!input || typeof input !== 'object' || Array.isArray(input) || types.isProxy(input) ||
          ![Object.prototype, null].includes(Object.getPrototypeOf(input))) return input;
      const descriptors = Object.getOwnPropertyDescriptors(input);
      if (Reflect.ownKeys(descriptors).some(key => typeof key !== 'string') ||
          Object.values(descriptors).some(field => !field.enumerable || !Object.hasOwn(field, 'value')))
        throw new TypeError('Journal retained data must contain only own data fields');
      return Object.fromEntries(Object.entries(descriptors).map(([key, field]) => [key,
        typeof field.value === 'bigint' && integers.includes(key) ? requiredSafeInteger(field.value, `Journal.${key}`) : field.value]));
    };
    const normalized = copy(value, ['seq', 'attempt', 'leaseEpoch', 'stateOwnerEpoch']);
    if (normalized && typeof normalized === 'object' && !Array.isArray(normalized) && !types.isProxy(normalized) &&
        [Object.prototype, null].includes(Object.getPrototypeOf(normalized))) {
      const fields = normalized as Record<string, unknown>;
      if (Object.hasOwn(fields, 'budgetDelta')) fields.budgetDelta = copy(fields.budgetDelta, BUDGET_FIELDS);
    }
    decodeWireJournal(normalized); return value as InvocationJournalEntry;
  }
  catch (error) { if (error instanceof TypeError) invalid(error.message); throw error; }
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
  'activationDeadlineAt',
  'preparation'
] as const;
const WORKER_IDENTITY_KEYS = ['workerIdentityDigest', 'processContainmentRef'] as const;
const WORKER_LEASE_KEYS = ['leaseEpoch', 'leaseExpiresAt', 'activatedAt'] as const;

function decodeWorkerPreparation(record: Record<string, unknown>): WorkerPreparation {
  const preparation = requireRecord(record.preparation, 'WorkerLaunch.preparation');
  rejectUnknownKeys(preparation, ['stateOwnerEpoch', 'sourceCheckpointId', 'sourceWorkspaceStateRef',
    'generationCreationNonceDigest', 'generationId', 'generation', 'controller', 'reservation'], 'WorkerLaunch.preparation');
  requireSafeInteger(preparation.stateOwnerEpoch, 'WorkerLaunch.preparation.stateOwnerEpoch', 1);
  const checkpoint = requireString(preparation.sourceCheckpointId, 'WorkerLaunch.preparation.sourceCheckpointId');
  const workspace = requireArtifactRef(preparation.sourceWorkspaceStateRef, 'WorkerLaunch.preparation.sourceWorkspaceStateRef');
  const nonce = requireDigest(preparation.generationCreationNonceDigest, 'WorkerLaunch.preparation.generationCreationNonceDigest');
  if (preparation.generationId !== identityHash(record.runId as string, checkpoint, workspace, nonce))
    invalid('WorkerLaunch.preparation.generationId differs from its immutable source and nonce');
  if (has(preparation, 'generation')) {
    const generation = requireRecord(preparation.generation, 'WorkerLaunch.preparation.generation');
    rejectUnknownKeys(generation, ['generationRef', 'generationIdentityDigest'], 'WorkerLaunch.preparation.generation');
    requireArtifactRef(generation.generationRef, 'WorkerLaunch.preparation.generation.generationRef');
    requireDigest(generation.generationIdentityDigest, 'WorkerLaunch.preparation.generation.generationIdentityDigest');
  }
  if (has(preparation, 'controller')) {
    const controller = requireRecord(preparation.controller, 'WorkerLaunch.preparation.controller');
    rejectUnknownKeys(controller, ['birthIdentityRef', 'birthIdentityDigest', 'privateGitInputRef'], 'WorkerLaunch.preparation.controller');
    requireArtifactRef(controller.birthIdentityRef, 'WorkerLaunch.preparation.controller.birthIdentityRef');
    requireDigest(controller.birthIdentityDigest, 'WorkerLaunch.preparation.controller.birthIdentityDigest');
    if (has(controller, 'privateGitInputRef')) requireArtifactRef(controller.privateGitInputRef, 'WorkerLaunch.preparation.controller.privateGitInputRef');
  }
  if (has(preparation, 'reservation')) {
    const reservation = requireRecord(preparation.reservation, 'WorkerLaunch.preparation.reservation');
    rejectUnknownKeys(reservation, ['deviceId', 'fileId', 'ownerUid'], 'WorkerLaunch.preparation.reservation');
    for (const key of ['deviceId', 'fileId'] as const) {
      if (!/^(0|[1-9][0-9]*)$/u.test(requireString(reservation[key], `WorkerLaunch.preparation.reservation.${key}`)))
        invalid(`WorkerLaunch.preparation.reservation.${key} must be a canonical unsigned decimal`);
    }
    requireSafeInteger(reservation.ownerUid, 'WorkerLaunch.preparation.reservation.ownerUid');
  }
  const createdAt = requireCanonicalTime(record.createdAt, 'WorkerLaunch.createdAt');
  const deadlineAt = requireCanonicalTime(record.activationDeadlineAt, 'WorkerLaunch.activationDeadlineAt');
  if (parseCanonicalTime(deadlineAt) - parseCanonicalTime(createdAt) !== 120_000)
    invalid('WorkerLaunch preparation requires its original fixed 120-second deadline');
  return preparation as WorkerPreparation;
}

export function decodeWorkerLaunch(value: unknown): WorkerLaunch {
  const record = requireRecord(value, 'WorkerLaunch');
  requireLiteral(record.schemaVersion, 1, 'WorkerLaunch.schemaVersion');
  requireString(record.launchId, 'WorkerLaunch.launchId');
  requireString(record.runId, 'WorkerLaunch.runId');
  requireSafeInteger(record.plannedRunRevision, 'WorkerLaunch.plannedRunRevision', 1);
  requireString(record.supervisorInstanceId, 'WorkerLaunch.supervisorInstanceId');
  requireDigest(record.spawnNonceDigest, 'WorkerLaunch.spawnNonceDigest');
  requireDigest(record.activationNonceDigest, 'WorkerLaunch.activationNonceDigest');
  const retiredPreparation = record.phase === 'retired' && record.retirementKind === 'preparation';
  if (record.phase === 'preparing' || retiredPreparation) {
    rejectUnknownKeys(record, ['schemaVersion', 'launchId', 'runId', 'plannedRunRevision', 'supervisorInstanceId',
      'spawnNonceDigest', 'activationNonceDigest', 'phase', 'preparation', 'createdAt', 'activationDeadlineAt',
      ...(retiredPreparation ? ['retirementKind', 'retiredAt', 'retirementEvidenceRef'] : [])], 'WorkerLaunch(preparation)');
    decodeWorkerPreparation(record);
    if (retiredPreparation) {
      const retiredAt = requireCanonicalTime(record.retiredAt, 'WorkerLaunch.retiredAt');
      if (parseCanonicalTime(retiredAt) < parseCanonicalTime(record.createdAt as string))
        invalid('WorkerLaunch preparation retirement precedes its creation');
      requireArtifactRef(record.retirementEvidenceRef, 'WorkerLaunch.retirementEvidenceRef');
    }
    return record as PreparingWorkerLaunch | RetiredWorkerPreparation;
  }
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
  if (has(record, 'preparation')) {
    const preparation = decodeWorkerPreparation(record);
    if (!preparation.generation || !preparation.controller || !preparation.reservation)
      invalid('bound WorkerLaunch requires complete actual preparation birth bindings');
    if (record.workspaceGenerationRef !== preparation.generation.generationRef)
      invalid('bound WorkerLaunch differs from its original preparation generation');
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
    if (!['preactivated_readonly', 'sealed', 'fenced_reconciling'].includes(String(record.generationWriteState))) {
      invalid('retired launch must retain its preactivation, sealed or fenced generation projection');
    }
    if (record.generationWriteState === 'preactivated_readonly') {
      requireLiteral(record.leaseVersion, 0, 'WorkerLaunch.leaseVersion');
      for (const key of [...WORKER_LEASE_KEYS, 'quiesceId']) {
        if (has(record, key)) invalid('retired preactivation launch cannot contain activation or lease fields');
      }
      if (has(record, 'workerIdentityDigest') && !has(record, 'processContainmentRef')) {
        invalid('retired preactivation identity requires its genuinely observed containment');
      }
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
    rejectUnknownKeys(record, [...GENERATION_BASE_KEYS, ...evidence, ...active, 'waitingSubjectRef', 'waitingSubjectDigest', 'fencedFromPhase', 'fencedJournalSeq', 'quiesceId'], 'WorkspaceGeneration(fenced_reconciling)');
    requireEvidencePair(record, evidence[0], evidence[1], 'WorkspaceGeneration');
    requireString(record.activeWorkerLaunchId, 'WorkspaceGeneration.activeWorkerLaunchId');
    requireSafeInteger(record.leaseEpoch, 'WorkspaceGeneration.leaseEpoch', 1);
    requireEvidencePair(record, 'waitingSubjectRef', 'waitingSubjectDigest', 'WorkspaceGeneration');
    requireSafeInteger(record.fencedJournalSeq, 'WorkspaceGeneration.fencedJournalSeq', 0);
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
  try { assertControlWireJson(value); }
  catch { invalid('ChildAllocation must be closed JSON data'); }
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
  const granted = decodeBudgetUsage(record.grantedAdditiveCeilings, 'ChildAllocation.grantedAdditiveCeilings');
  requireSafeInteger(record.grantedChildDepth, 'ChildAllocation.grantedChildDepth');
  requireSafeInteger(record.grantedChildConcurrency, 'ChildAllocation.grantedChildConcurrency', 1);
  requireCanonicalTime(record.childDeadlineAt, 'ChildAllocation.childDeadlineAt');
  requireCanonicalTime(record.createdAt, 'ChildAllocation.createdAt');
  if ((record.childDeadlineAt as string) <= (record.createdAt as string)) invalid('ChildAllocation deadline must follow its original creation');

  if (record.state === 'reserved') {
    rejectUnknownKeys(record, CHILD_BASE_KEYS, 'ChildAllocation(reserved)');
  } else if (record.state === 'child_terminal') {
    rejectUnknownKeys(
      record,
      [...CHILD_BASE_KEYS, 'terminal', 'inclusiveBudgetUsage', 'terminalAt'],
      'ChildAllocation(child_terminal)'
    );
    decodeChildTerminal(record.terminal, record.mode);
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
    requireCanonicalTime(record.terminalAt, 'ChildAllocation.terminalAt');
    requireString(record.childResultItemId, 'ChildAllocation.childResultItemId');
    requireSafeInteger(record.parentSettlementRevision, 'ChildAllocation.parentSettlementRevision', 1);
    requireCanonicalTime(record.settledAt, 'ChildAllocation.settledAt');
  } else {
    invalid('ChildAllocation.state is invalid');
  }
  if (record.state === 'child_terminal' || record.state === 'settled') {
    const usage = decodeBudgetUsage(record.inclusiveBudgetUsage, 'ChildAllocation.inclusiveBudgetUsage');
    if (BUDGET_FIELDS.some(field => usage[field] > granted[field])) invalid('ChildAllocation inclusive usage exceeds its original granted ceiling');
    if ((record.terminalAt as string) < (record.createdAt as string)) invalid('ChildAllocation terminal time precedes its original creation');
    if (record.state === 'settled') {
      const unused = decodeBudgetUsage(record.releasedUnusedBudget, 'ChildAllocation.releasedUnusedBudget');
      if (BUDGET_FIELDS.some(field => unused[field] !== granted[field] - usage[field])) invalid('ChildAllocation unused budget differs from its exact original grant minus usage');
      if ((record.settledAt as string) < (record.terminalAt as string)) invalid('ChildAllocation settlement precedes its original terminal outcome');
    }
  }
  return record as ChildAllocationV1;
}

/** Budget data only. Incoming reservations belong to the parent, and inclusive
 * settled child use already contains its descendants; neither is added twice. */
export function childAllocationBudgetFacts(runId: string, allocations: readonly ChildAllocationV1[]): {
  reserved: BudgetUsage; consumed: BudgetUsage; nonterminalDirectChildren: number;
} {
  let reserved = { ...ZERO_BUDGET }, consumed = { ...ZERO_BUDGET }, nonterminalDirectChildren = 0;
  const children = new Set<string>();
  let incoming = false;
  for (const value of allocations) {
    const row = decodeChildAllocation(value);
    if (row.parentRunId !== runId) {
      if (row.childRunId !== runId || incoming) invalid('child budget cut has a foreign or duplicate incoming allocation');
      incoming = true; continue;
    }
    if (children.has(row.childRunId)) invalid('child budget cut duplicates an outgoing allocation');
    children.add(row.childRunId);
    if (row.state === 'settled') consumed = addBudget(consumed, row.inclusiveBudgetUsage, 'inclusive child consumed budget');
    else reserved = addBudget(reserved, row.grantedAdditiveCeilings, 'conservative child reserved budget');
    if (row.state === 'reserved') nonterminalDirectChildren++;
  }
  return { reserved, consumed, nonterminalDirectChildren };
}
