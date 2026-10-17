import { canonicalSha256 } from './canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, modelOperationId, normalizeBoundedText, parseCanonicalTime } from './identity.js';
import type { Run, RunAssemblyV1, RunFrontier, RunSpec } from './types.js';
import type { ModelRequestV1 } from '../model/request.js';

/** The closed model-call branch of OperationGrantV1. Decoded data is not a
 * broker token, a worker observation or current credential authority. */
export type ModelOperationGrantV1 = {
  schemaVersion: 1; format: 'cliq-operation-grant-v1'; grantId: string;
  principalId: string; runId: string; policyRef: string; frontierRef: string;
  opId: string; requestRef: string; requestDigest: string; targetRef: string; targetDigest: string;
  subject: { kind: 'model_call'; turnId: string; phase: 'model_turn' | 'context_compaction'; assemblyRef: string };
  provenance: { kind: 'run_assembly'; assemblyRef: string; assemblyDigest: string };
  maxDispatchedAttempts: number; issuedAt: string; expiresAt: string; grantDigest: string;
};
export type ModelGrantFrame = {
  principalId: string; run: Run; spec: RunSpec; assembly: RunAssemblyV1;
  frontier: Extract<RunFrontier, { kind: 'agent' }>; frontierRef: string;
  request: ModelRequestV1; requestRef: string; targetRef: string; targetDigest: string;
};

function exact(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) {
    throw new TypeError('model grant has unknown or missing fields');
  }
}
export function decodeModelOperationGrant(value: unknown): ModelOperationGrantV1 {
  exact(value, ['schemaVersion', 'format', 'grantId', 'principalId', 'runId', 'policyRef', 'frontierRef', 'opId',
    'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'subject', 'provenance', 'maxDispatchedAttempts',
    'issuedAt', 'expiresAt', 'grantDigest']);
  if (value.schemaVersion !== 1 || value.format !== 'cliq-operation-grant-v1') throw new TypeError('invalid model grant format');
  for (const key of ['grantId', 'principalId', 'runId', 'opId']) {
    if (typeof value[key] !== 'string' || normalizeBoundedText(value[key], 1, 128) !== value[key]) throw new TypeError('invalid model grant identity');
  }
  for (const key of ['policyRef', 'frontierRef', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'grantDigest']) {
    if (typeof value[key] !== 'string') throw new TypeError('invalid model grant reference');
    assertArtifactRef(value[key]);
  }
  exact(value.subject, ['kind', 'turnId', 'phase', 'assemblyRef']);
  if (value.subject.kind !== 'model_call' || !['model_turn', 'context_compaction'].includes(value.subject.phase as string) ||
      typeof value.subject.turnId !== 'string' || normalizeBoundedText(value.subject.turnId, 1, 128) !== value.subject.turnId ||
      typeof value.subject.assemblyRef !== 'string') throw new TypeError('invalid model grant subject');
  assertArtifactRef(value.subject.assemblyRef);
  exact(value.provenance, ['kind', 'assemblyRef', 'assemblyDigest']);
  if (value.provenance.kind !== 'run_assembly' || typeof value.provenance.assemblyRef !== 'string' ||
      typeof value.provenance.assemblyDigest !== 'string' || value.provenance.assemblyRef !== value.subject.assemblyRef) {
    throw new TypeError('invalid model grant provenance');
  }
  assertArtifactRef(value.provenance.assemblyRef); assertArtifactRef(value.provenance.assemblyDigest);
  if (!Number.isSafeInteger(value.maxDispatchedAttempts) || (value.maxDispatchedAttempts as number) < 1 ||
      (value.maxDispatchedAttempts as number) > 5 || typeof value.issuedAt !== 'string' || typeof value.expiresAt !== 'string' ||
      parseCanonicalTime(value.issuedAt) >= parseCanonicalTime(value.expiresAt)) throw new TypeError('invalid model grant lifetime or dispatch bound');
  if (value.grantDigest !== digestOmitting(value, 'grantDigest') || value.grantId !== identityHash('cliq-operation-grant-v1',
      value.runId, value.opId, value.requestDigest, value.subject, value.issuedAt)) throw new TypeError('model grant digest or id does not rehash');
  return value as unknown as ModelOperationGrantV1;
}

/** Deterministic data proposal, committed only by the typed preparation reducer. */
export function planModelOperationGrant(frame: ModelGrantFrame, issuedAt: string, expiresAt: string): ModelOperationGrantV1 {
  const { run, spec, assembly, frontier, request } = frame;
  exact(frontier, ['schemaVersion', 'kind', 'phase', 'turnId', 'contextItemSeq', 'cause',
    ...(frontier.phase === 'context_compaction' ? ['compactionPlanRef'] : [])]);
  if (frontier.schemaVersion !== 1 || !['model_turn', 'context_compaction'].includes(frontier.phase) ||
      !Number.isSafeInteger(frontier.contextItemSeq) || frontier.contextItemSeq < 0 ||
      !['initial', 'tool_batch_complete', 'repair', 'child_results', 'input'].includes(frontier.cause)) {
    throw new TypeError('model grant frontier is invalid');
  }
  if (spec.operation !== 'agent' || frontier.kind !== 'agent' ||
      canonicalSha256(frontier) !== frame.frontierRef || canonicalSha256(assembly) !== spec.assemblyRef ||
      digestOmitting(assembly, 'assemblyDigest') !== assembly.assemblyDigest || canonicalSha256(request) !== frame.requestRef ||
      request.requestDigest !== digestOmitting(request, 'requestDigest') || request.runId !== run.id ||
      request.opId !== modelOperationId(run.id, frontier) || request.assemblyRef !== spec.assemblyRef ||
      request.assemblyDigest !== assembly.assemblyDigest || request.provider !== assembly.provider.name || request.model !== assembly.provider.model ||
      request.kind !== (frontier.phase === 'model_turn' ? 'normal' : 'context_compaction') ||
      request.negotiatedMode !== (frontier.phase === 'model_turn' ? assembly.provider.negotiation.mode : 'text-only') ||
      request.compactionPlanRef !== frontier.compactionPlanRef || parseCanonicalTime(issuedAt) < parseCanonicalTime(run.createdAt) ||
      parseCanonicalTime(expiresAt) > parseCanonicalTime(run.deadlineAt)) throw new TypeError('model grant proposal differs from its immutable frame');
  const subject: ModelOperationGrantV1['subject'] = { kind: 'model_call', turnId: frontier.turnId, phase: frontier.phase, assemblyRef: spec.assemblyRef };
  const core = { schemaVersion: 1 as const, format: 'cliq-operation-grant-v1' as const,
    grantId: identityHash('cliq-operation-grant-v1', run.id, request.opId, request.requestDigest, subject, issuedAt),
    principalId: frame.principalId, runId: run.id, policyRef: spec.policyRef, frontierRef: frame.frontierRef,
    opId: request.opId, requestRef: frame.requestRef, requestDigest: request.requestDigest,
    targetRef: frame.targetRef, targetDigest: frame.targetDigest, subject,
    provenance: { kind: 'run_assembly' as const, assemblyRef: spec.assemblyRef, assemblyDigest: assembly.assemblyDigest },
    maxDispatchedAttempts: assembly.retry.model.maxDispatchedAttempts, issuedAt, expiresAt };
  return decodeModelOperationGrant({ ...core, grantDigest: canonicalSha256(core) });
}
