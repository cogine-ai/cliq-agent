import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting, modelOperationId } from './identity.js';
import { decodeModelOperationGrant, planModelOperationGrant, type ModelGrantFrame } from './model-grant.js';
import type { InvocationJournalEntry, Run, RunFrontier, RunSpec } from './types.js';
import { normalInput, ref, testFixture } from '../model/testing/fixtures.js';
import { validateRunAssembly } from '../model/run-assembly.js';
import { assertModelGrantDispatch } from '../state/model-grant.js';

const issuedAt = '2026-09-06T00:00:00.000Z', expiresAt = '2026-09-06T01:00:00.000Z';
const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };

/** Pure secret-free data. No worker, endpoint registration, credentials or
 * installation authority is created by these grant contract examples. */
function frame(): ModelGrantFrame {
  const fixture = testFixture();
  const validated = validateRunAssembly(fixture);
  assert.equal(validated.ok, true);
  if (!validated.ok) throw new Error('invalid offline model fixture');
  const frontier: Extract<RunFrontier, { kind: 'agent' }> = { schemaVersion: 1, kind: 'agent', phase: 'model_turn',
    turnId: 'turn-1', contextItemSeq: 0, cause: 'initial' };
  const spec: RunSpec = { schemaVersion: 1, operation: 'agent', objectiveRef: ref(100), admittedContextRef: ref(101),
    baseWorkspaceManifestRef: ref(102), sourceProjectionRef: ref(103), assemblyRef: fixture.assemblyRef,
    policyRef: ref(104), sandboxProfileRef: ref(105), verifierSpecRef: ref(106), credentialGrantRefs: fixture.runSpecCredentialGrantRefs,
    budgets: { wallTimeMs: 3_600_000, modelTokens: 1_000_000, costMicros: 1_000_000, toolCalls: 10, repairAttempts: 1,
      childDepth: 0, childConcurrency: 0 } };
  const run: Run = { id: 'run-1', sessionId: 'session-1', specRef: canonicalSha256(spec), status: 'running', nextStep: 'agent',
    frontierRef: canonicalSha256(frontier), revision: 1, leaseEpoch: 1, activeWorkerLaunchId: 'worker-1', latestCheckpointId: 'checkpoint-1',
    budgetReserved: zero, budgetConsumed: zero, repairCount: 0, cancelRequested: false,
    createdAt: issuedAt, deadlineAt: expiresAt, updatedAt: issuedAt };
  const input = normalInput(fixture);
  input.invocation = { runId: run.id, opId: modelOperationId(run.id, frontier), attempt: 0 };
  input.projection.frontierDigest = run.frontierRef!;
  input.projection.runSpecRef = run.specRef;
  input.projection.projectionDigest = digestOmitting(input.projection, 'projectionDigest');
  input.projectionRef = canonicalSha256(input.projection);
  const request = validated.model.prepare(input).request;
  return { principalId: 'principal-1', run, spec, assembly: fixture.assembly, frontier, frontierRef: run.frontierRef!,
    request, requestRef: canonicalSha256(request), targetRef: ref(107), targetDigest: ref(108) };
}
function journal(selected: ModelGrantFrame, grantRef: string): InvocationJournalEntry {
  return { seq: 1, runId: selected.run.id, opId: selected.request.opId, opKind: 'model', attempt: 0, leaseEpoch: 1,
    phase: 'prepared', target: selected.targetRef, requestRef: selected.requestRef, grantRef, replayClass: 'retry',
    budgetDelta: zero, timestamp: issuedAt };
}

test('model OperationGrant closes the original immutable native-tools frame, not a later Run frontier', () => {
  const selected = frame(), grant = planModelOperationGrant(selected, issuedAt, expiresAt);
  assert.deepEqual(decodeModelOperationGrant(grant), grant);
  assert.deepEqual(grant.subject, { kind: 'model_call', turnId: 'turn-1', phase: 'model_turn', assemblyRef: selected.spec.assemblyRef });
  assert.deepEqual(grant.provenance, { kind: 'run_assembly', assemblyRef: selected.spec.assemblyRef, assemblyDigest: selected.assembly.assemblyDigest });
  assert.equal(grant.targetRef, selected.targetRef);
  assert.equal(grant.targetDigest, selected.targetDigest);
  assert.equal(grant.principalId, selected.principalId);
  assert.equal(grant.policyRef, selected.spec.policyRef);
  assert.equal(grant.maxDispatchedAttempts, selected.assembly.retry.model.maxDispatchedAttempts);
  const advanced = { ...selected, run: { ...selected.run, nextStep: 'tool' as const, frontierRef: ref(999), revision: 2 } };
  assert.deepEqual(planModelOperationGrant(advanced, issuedAt, expiresAt), grant);
  assert.throws(() => decodeModelOperationGrant({ ...grant, maxLaunches: 1 }), /unknown or missing fields/);
  assert.throws(() => decodeModelOperationGrant({ ...grant, subject: { ...grant.subject, workerLaunchId: 'foreign' } }), /unknown or missing fields/);
  assert.throws(() => decodeModelOperationGrant({ ...grant, targetDigest: ref(999) }), /digest or id/);
  for (const maximum of [0, 6]) {
    const altered = { ...grant, maxDispatchedAttempts: maximum };
    altered.grantDigest = digestOmitting(altered, 'grantDigest');
    assert.throws(() => decodeModelOperationGrant(altered), /dispatch bound/);
  }
});

test('model grant proposal rejects rehashed request, assembly and frontier substitutions', () => {
  const selected = frame();
  for (const change of [
    (value: ModelGrantFrame) => { value.requestRef = ref(999); },
    (value: ModelGrantFrame) => { value.frontierRef = ref(999); },
    (value: ModelGrantFrame) => { value.spec.assemblyRef = ref(999); },
    (value: ModelGrantFrame) => { value.frontier.turnId = 'another-turn'; value.frontierRef = canonicalSha256(value.frontier); },
    (value: ModelGrantFrame) => { value.request.model = 'another-model'; },
    (value: ModelGrantFrame) => { value.request.negotiatedMode = 'text-only'; }
  ]) {
    const altered = structuredClone(selected);
    change(altered);
    altered.request.requestDigest = digestOmitting(altered.request, 'requestDigest');
    if (altered.requestRef === selected.requestRef) altered.requestRef = canonicalSha256(altered.request);
    assert.throws(() => planModelOperationGrant(altered, issuedAt, expiresAt), /immutable frame/);
  }
});

test('model grant lifetime and operation-wide dispatch capacity remain strict at release', () => {
  const selected = frame(), grant = planModelOperationGrant(selected, issuedAt, expiresAt);
  const prepared = journal(selected, canonicalSha256(grant));
  const claim = { ...prepared, seq: 2, phase: 'dispatch_claimed' as const, dispatchId: 'dispatch-1' };
  const check = (history: InvocationJournalEntry[], includingCurrentClaim = false, now = issuedAt) =>
    assertModelGrantDispatch(grant, { run: selected.run, prepared, history, now, includingCurrentClaim });
  check([prepared]);
  check([prepared, claim], true);
  const exhausted = Array.from({ length: grant.maxDispatchedAttempts }, (_, attempt) => ({ ...claim, attempt, seq: attempt * 2 + 2,
    grantRef: ref(200 + attempt) }));
  assert.throws(() => check(exhausted), /capacity is exhausted/);
  assert.throws(() => check([...exhausted.map(entry => ({ ...entry, attempt: entry.attempt + 1 })), claim], true), /capacity is exhausted/);
  assert.throws(() => check([prepared, claim], true, expiresAt), /expired/);
  assert.throws(() => check([prepared, claim], true, '2026-09-05T23:59:59.999Z'), /stale/);
  assert.throws(() => check([prepared], true), /permanent current claim/);
  assert.throws(() => check([prepared, { ...claim, target: ref(999) }], true), /permanent current claim/);
  assert.throws(() => assertModelGrantDispatch(grant, { run: { ...selected.run, frontierRef: ref(999) }, prepared, history: [], now: issuedAt }), /another current frame/);
  assert.throws(() => assertModelGrantDispatch(grant, { run: selected.run, prepared: { ...prepared, grantRef: ref(999) }, history: [], now: issuedAt }), /another current frame/);
  assert.throws(() => assertModelGrantDispatch(grant, { run: selected.run, prepared: { ...prepared, requestRef: ref(999) }, history: [], now: issuedAt }), /another current frame/);
  assert.throws(() => assertModelGrantDispatch(grant, { run: selected.run, prepared: { ...prepared, target: ref(999) }, history: [], now: issuedAt }), /another current frame/);
  assert.throws(() => planModelOperationGrant(selected, '2026-09-05T23:59:59.999Z', expiresAt), /immutable frame/);
  assert.throws(() => planModelOperationGrant(selected, issuedAt, '2026-09-06T01:00:00.001Z'), /immutable frame/);
});
