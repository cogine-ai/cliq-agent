// Retained-data reader regressions using real SQLite, Session and CAS. No
// dispatch is claimed and none of this data establishes executable authority,
// physical retirement, or installed verifier qualification.
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { rename } from 'node:fs/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { FinalCandidateItem } from '../kernel/result.js';
import type { BudgetSettlementV1, InvocationJournalEntry, RunFrontier, RunItemReferenceV1, RunSpec, VerifierSpec } from '../kernel/types.js';
import type { VerifierCommandV1, VerifierEnvironmentV1 } from '../kernel/verifier.js';
import type { VerifierPolicyDecisionItem } from '../kernel/verifier-invocation.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { readCandidateVerifierPlan } from './final-candidate-plan.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { loadVerifierPolicy, planVerifierRequest } from './verifier-policy.js';
import { readVerifierProgress, type VerifierRecoveryCut } from './verifier-recovery.js';

test('retained verifier projection validates every undispatched attempt and cannot replace missing original authority with its latest grant', async () => {
  const fixture = await createAgentFixture('verifier-retained-attempts', undefined, { mode: 'yolo' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const original = await fixture.store.readRecoveryClosure(fixture.runId), artifacts = fixture.store.artifacts;
    const assembly = structuredClone(fixture.authority.assembly), ref = canonicalSha256;
    const guest = await artifacts.publishCanonical({ inertRetainedData: true }, 'offline-data-not-a-toolchain');
    assembly.runtime.guestToolchainManifestRef = guest.ref;
    assembly.runtime.guestToolchainManifestDigest = guest.ref;
    assembly.assemblyDigest = digestOmitting(assembly, 'assemblyDigest');
    const assemblyArtifact = await artifacts.publishCanonical(assembly, assembly.format);
    const command: VerifierCommandV1 = { schemaVersion: 1, format: 'cliq-verifier-command-v1', verifierId: 'checks', verifierVersion: '1',
      executable: { kind: 'guest_toolchain', guestToolchainManifestRef: guest.ref, guestToolchainManifestDigest: guest.ref, toolId: 'node',
        executionPath: '/usr/bin/node', executableDigest: ref('inert-node'), abiFingerprint: guest.ref },
      argv: [{ kind: 'non_secret_literal', value: '--test' }, { kind: 'non_secret_literal', value: '--test-concurrency=1' },
        { kind: 'non_secret_literal', value: 'checks.mjs' }], cwd: '.', commandDigest: '' };
    command.commandDigest = digestOmitting(command, 'commandDigest');
    const commandArtifact = await artifacts.publishCanonical(command, command.format);
    const environment: VerifierEnvironmentV1 = { schemaVersion: 1, format: 'cliq-verifier-environment-v1', verifierId: 'checks', verifierVersion: '1',
      commandRef: commandArtifact.ref, commandDigest: command.commandDigest, variables: [], writableEphemeralPaths: [],
      sourceProjectionRef: original.runSpec.sourceProjectionRef, sourceAccess: 'read_only', networkAccess: 'denied',
      sandboxProfile: 'cliq-verifier-readonly-v1', runtimeBundleRef: assembly.runtime.runtimeBundleRef,
      runtimeBundleManifestDigest: assembly.runtime.runtimeBundleManifestDigest, guestToolchainManifestRef: guest.ref,
      guestToolchainManifestDigest: guest.ref, environmentDigest: '' };
    environment.environmentDigest = digestOmitting(environment, 'environmentDigest');
    const environmentArtifact = await artifacts.publishCanonical(environment, environment.format);
    const entry: VerifierSpec['verifiers'][number] = { index: 0, id: 'checks', version: '1', gate: 'required', commandRef: commandArtifact.ref,
      commandDigest: command.commandDigest, environmentRef: environmentArtifact.ref, environmentDigest: environment.environmentDigest,
      timeoutMs: 1000, retries: 1, outputLimitBytes: 65_536, entryDigest: '' };
    entry.entryDigest = digestOmitting(entry, 'entryDigest');
    const spec: VerifierSpec = { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers: [entry], specDigest: '' };
    spec.specDigest = digestOmitting(spec, 'specDigest');
    const specArtifact = await artifacts.publishCanonical(spec, spec.format);
    const runSpec: RunSpec = { ...original.runSpec, assemblyRef: assemblyArtifact.ref, verifierSpecRef: specArtifact.ref };
    const createdAt = sampleCanonicalNow();
    const candidate: FinalCandidateItem = { schemaVersion: 1, kind: 'final_candidate', operation: 'agent', itemId: 'inert-candidate',
      runId: fixture.runId, producingItemId: 'inert-final-turn', producingOpId: 'inert-model-op',
      baseSourceRef: runSpec.baseWorkspaceManifestRef, resultSourceRef: ref('inert-source'), diffRef: ref('inert-diff'),
      summaryRef: ref('inert-summary'), sourceDigest: ref('inert-source-tree'), diffDigest: ref('inert-diff-digest'), createdAt };
    const candidateArtifact = await artifacts.publishCanonical(candidate, 'cliq-run-item-v1');
    const candidateRow: RunItemReferenceV1 = { schemaVersion: 1, itemId: candidate.itemId, itemSeq: 1, payloadRef: candidateArtifact.ref,
      payloadDigest: candidateArtifact.ref, createdAt };
    const plan = await readCandidateVerifierPlan(artifacts, runSpec, { runId: fixture.runId, candidateItemId: candidate.itemId,
      resultSourceRef: candidate.resultSourceRef });
    const planArtifact = await artifacts.publishCanonical(plan, 'cliq-verifier-plan-v1');
    const frontier: Extract<RunFrontier, { kind: 'verify' }> = { schemaVersion: 1, kind: 'verify', phase: 'verifiers',
      candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef, verifierPlanRef: planArtifact.ref,
      nextVerifierIndex: 0, afterPass: 'finalize' };
    const context = { runId: fixture.runId, frontierRef: ref(frontier), assemblyRef: assemblyArtifact.ref,
      candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef, sourceDigest: candidate.sourceDigest,
      verifierPlanRef: planArtifact.ref, plan, verifierSpecRef: specArtifact.ref, verifierSpec: spec, verifierIndex: 0, command, environment };
    const planned = planVerifierRequest(context);
    await artifacts.publishCanonical(planned.request, planned.request.format);
    await artifacts.publishCanonical(planned.target, planned.target.format);
    const policy = await artifacts.readCanonical<RunPolicySnapshotV1>(runSpec.policyRef);
    const workspace = await artifacts.readCanonical<{ identityDigest: string }>(fixture.store.getSession(original.run.sessionId).workspaceIdentityRef);
    const evaluator = loadVerifierPolicy({ policy, policyRef: runSpec.policyRef, assembly, assemblyRef: assemblyArtifact.ref,
      principalId: policy.principalId, workspaceIdentityDigest: workspace.identityDigest, context });
    const items = [candidateRow], journal: InvocationJournalEntry[] = [];
    for (let attempt = 0; attempt < 2; attempt++) {
      const now = new Date(Date.parse(createdAt) + attempt).toISOString();
      const evidence = evaluator.evaluate(planned.request, planned.target, now);
      const evidenceArtifact = await artifacts.publishCanonical(evidence, evidence.format);
      const grant = evaluator.grant(planned.request, planned.target, evidence, now, original.run.deadlineAt);
      const grantArtifact = await artifacts.publishCanonical(grant, grant.format);
      const decisionId = identityHash('cliq-verifier-policy-item-v1', fixture.runId, planned.request.opId, evidenceArtifact.ref);
      const decision: VerifierPolicyDecisionItem = { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'verifier_launch',
        itemId: decisionId, runId: fixture.runId, opId: planned.request.opId, principalId: policy.principalId,
        decisionRef: evidenceArtifact.ref, policyChannelEvidenceRef: evidenceArtifact.ref, policyChannelEvidenceDigest: evidence.evidenceDigest,
        createdAt: now, decisionSource: 'direct_policy', decision: 'allow', grantRef: grantArtifact.ref };
      const payload = await artifacts.publishCanonical(decision, 'cliq-run-item-v1');
      items.push({ schemaVersion: 1, itemId: decisionId, itemSeq: items.length + 1, payloadRef: payload.ref, payloadDigest: payload.ref, createdAt: now });
      const prepared: InvocationJournalEntry = { seq: journal.length + 1, runId: fixture.runId, opId: planned.request.opId, opKind: 'verifier',
        attempt, leaseEpoch: 1, phase: 'prepared', target: planned.request.targetRef, requestRef: ref(planned.request),
        replayClass: 'retry', grantRef: grantArtifact.ref, budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, timestamp: now };
      journal.push(prepared);
      if (!attempt) {
        const closure = await artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-verifier-preparation-closure-v1',
          runId: fixture.runId, opId: prepared.opId, attempt, preparedJournalSeq: prepared.seq, requestRef: prepared.requestRef,
          targetRef: prepared.target, grantRef: prepared.grantRef, disposition: 'unclaimed' }, 'cliq-verifier-preparation-closure-v1');
        const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
        const settlement: BudgetSettlementV1 = { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId: fixture.runId,
          opId: prepared.opId, attempt, preparedJournalSeq: prepared.seq, terminalJournalSeq: journal.length + 1, terminalPhase: 'failed',
          reserved: prepared.budgetDelta, consumed: zero, released: prepared.budgetDelta,
          budgetConsumedBefore: zero, budgetConsumedAfter: zero, budgetReservedBefore: prepared.budgetDelta, budgetReservedAfter: zero,
          settledAt: now, settlementDigest: '' };
        settlement.settlementDigest = digestOmitting(settlement, 'settlementDigest');
        const settlementArtifact = await artifacts.publishCanonical(settlement, settlement.format);
        journal.push({ ...prepared, seq: journal.length + 1, phase: 'failed', errorRef: closure.ref,
          budgetSettlementRef: settlementArtifact.ref, budgetDelta: zero });
      }
    }
    const cut: VerifierRecoveryCut = { run: original.run, runSpec, workspaceGenerations: original.workspaceGenerations, items, journal };
    const progress = await readVerifierProgress(driver, artifacts, cut, candidate.itemId);
    assert.equal(progress.nextVerifierIndex, 0); assert.equal(progress.complete, false); assert.equal(progress.entries[0]!.receipt, undefined);
    const historicalGrant = journal[0]!.grantRef!, grantPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, historicalGrant);
    const retainedGrant = path.join(fixture.stateRoot, 'retained-historical-verifier-grant');
    await rename(grantPath, retainedGrant);
    try { await assert.rejects(readVerifierProgress(driver, artifacts, cut, candidate.itemId)); }
    finally { await rename(retainedGrant, grantPath); }
    await assert.rejects(readVerifierProgress(driver, artifacts, { ...cut, items: items.filter(row => row !== items[1]) }, candidate.itemId),
      /unique original owned policy decision/);
    await assert.rejects(readVerifierProgress(driver, artifacts, { ...cut, journal: journal.map((row, index) => index === 1
      ? { ...row, errorRef: ref('not-original-preparation-closure') } : row) }, candidate.itemId));
    const oldSettlement = await artifacts.readCanonical<BudgetSettlementV1>(journal[1]!.budgetSettlementRef!);
    const charged = { ...oldSettlement, consumed: journal[0]!.budgetDelta, budgetConsumedAfter: journal[0]!.budgetDelta, settlementDigest: '' };
    charged.settlementDigest = digestOmitting(charged, 'settlementDigest');
    const chargedArtifact = await artifacts.publishCanonical(charged, charged.format);
    await assert.rejects(readVerifierProgress(driver, artifacts, { ...cut, journal: journal.map((row, index) => index === 1
      ? { ...row, budgetSettlementRef: chargedArtifact.ref } : row) }, candidate.itemId), /original zero settlement/);
    const weakSettlement = { ...oldSettlement, reserved: oldSettlement.consumed, released: oldSettlement.consumed,
      budgetReservedBefore: oldSettlement.consumed, settlementDigest: '' };
    weakSettlement.settlementDigest = digestOmitting(weakSettlement, 'settlementDigest');
    const weakArtifact = await artifacts.publishCanonical(weakSettlement, weakSettlement.format);
    await assert.rejects(readVerifierProgress(driver, artifacts, { ...cut, journal: journal.map((row, index) => index === 0
      ? { ...row, budgetDelta: oldSettlement.consumed } : index === 1 ? { ...row, budgetSettlementRef: weakArtifact.ref } : row) }, candidate.itemId),
      /verifier reservation/);
    for (const phase of ['unknown', 'completed'] as const) {
      const altered = journal.map((row, index) => index === 1 ? { ...row, phase } : row);
      await assert.rejects(readVerifierProgress(driver, artifacts, { ...cut, journal: altered }, candidate.itemId), /illegal Journal lifecycle/);
    }
    // Malicious retained rows cannot turn an unresolved or claimed-failed
    // attempt into new authority. No native claim is created by these inputs.
    const claim: InvocationJournalEntry = { ...journal[0]!, seq: 2, phase: 'dispatch_claimed', dispatchId: 'inert-dispatch',
      supervisorInstanceId: 'inert-supervisor', stateOwnerEpoch: 1, sandboxLaunchSpecRef: ref('inert-launch-spec'),
      budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } };
    const refunded: BudgetSettlementV1 = { ...oldSettlement, terminalJournalSeq: 3, terminalPhase: 'unknown', settlementDigest: '' };
    refunded.settlementDigest = digestOmitting(refunded, 'settlementDigest');
    const refundArtifact = await artifacts.publishCanonical(refunded, refunded.format);
    await assert.rejects(readVerifierProgress(driver, artifacts, { ...cut, journal: [journal[0]!, claim,
      { ...claim, seq: 3, phase: 'unknown', budgetSettlementRef: refundArtifact.ref }] }, candidate.itemId), /full consumption/);
    for (const phase of ['unknown', 'failed'] as const) {
      const fullSettlement: BudgetSettlementV1 = { ...oldSettlement, terminalJournalSeq: 3, terminalPhase: phase,
        consumed: journal[0]!.budgetDelta, budgetConsumedAfter: journal[0]!.budgetDelta, settlementDigest: '' };
      fullSettlement.settlementDigest = digestOmitting(fullSettlement, 'settlementDigest');
      const full = await artifacts.publishCanonical(fullSettlement, fullSettlement.format);
      await assert.rejects(readVerifierProgress(driver, artifacts, { ...cut, journal: [journal[0]!, claim,
        { ...claim, seq: 3, phase, budgetDelta: journal[0]!.budgetDelta, budgetSettlementRef: full.ref }, { ...journal[2]!, seq: 4 }] },
      candidate.itemId), /replacement lacks/);
    }
    const requestPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, ref(planned.request));
    const retainedRequest = path.join(fixture.stateRoot, 'retained-verifier-request');
    await rename(requestPath, retainedRequest);
    try { await assert.rejects(readVerifierProgress(driver, artifacts, cut, candidate.itemId)); }
    finally { await rename(retainedRequest, requestPath); }
    assert.equal((await fixture.store.readRecoveryClosure(fixture.runId)).journal.length, 0,
      'reader-only data is never admitted or claimed as a production invocation');
  } finally { driver.close(); await disposeFixture(fixture); }
});
