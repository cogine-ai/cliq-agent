import assert from 'node:assert/strict';
import test from 'node:test';
import { assertDeliveryModelFreeCut } from './run-model-free.js';
import type { InvocationJournalEntry, Run, RunSpec } from '../kernel/types.js';
import type { RecoveryClosureV1 } from '../kernel/types.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readResourceStopCause } from './resource-stop.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { testFixture } from '../model/testing/fixtures.js';
import { MODEL_BROKER_ENTRY_ID } from './model-broker-native.js';
import { validateInstalledBrokerAmbiguityHistory } from './broker-ambiguity.js';

// Inert data only, never installed/admitted or submitted to a reducer. There
// is no StateOwner, worker, publication or recovery evidence in this seam.
function fixture() {
  const ref = 'a'.repeat(64), at = '2026-01-01T00:00:00.000Z';
  const run: Run = { id: 'data-run', sessionId: 'data-session', specRef: ref, status: 'queued', nextStep: 'delivery', frontierRef: ref,
    revision: 1, leaseEpoch: 0, latestCheckpointId: 'data-checkpoint', repairCount: 0, cancelRequested: false,
    budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
    budgetConsumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
    createdAt: at, updatedAt: at, deadlineAt: '2026-01-01T00:01:00.000Z' };
  const runSpec: RunSpec = { schemaVersion: 1, operation: 'delivery', objectiveRef: ref, admittedContextRef: ref,
    baseWorkspaceManifestRef: ref, sourceProjectionRef: ref, assemblyRef: ref, policyRef: ref, sandboxProfileRef: ref, verifierSpecRef: ref,
    credentialGrantRefs: [], budgets: { wallTimeMs: 60000, modelTokens: 0, costMicros: 0, toolCalls: 10, repairAttempts: 0, childDepth: 0, childConcurrency: 0 } };
  return { run, runSpec, journal: [], childAllocations: [] };
}

function inheritedBrokerInput(data: Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'journal' | 'childAllocations'> = fixture()) {
  // Complete inert assembly data from the existing pure-data fixture, not a
  // verified RuntimeBundle, admitted Delivery or native/process proof.
  const assembly = testFixture('openai-compatible').assembly;
  assembly.provider.adapter = { ...assembly.provider.adapter, adapterId: MODEL_BROKER_ENTRY_ID, version: '1' };
  assembly.provider.negotiation.streaming = false;
  const spec = { ...data.runSpec, assemblyRef: canonicalSha256(assembly) };
  const run = { ...data.run, specRef: canonicalSha256(spec) };
  return { driver: undefined as never, artifacts: undefined as never, run, spec, assembly,
    journal: data.journal, childAllocations: data.childAllocations, principalId: 'inert-principal' };
}

test('a model-free Delivery retains an installed broker assembly without interpreting it as Agent model authority', async () => {
  const input = inheritedBrokerInput(), before = structuredClone(input);
  await validateInstalledBrokerAmbiguityHistory(input);
  assert.deepEqual(input, before, 'domain routing changes no original retained data');
  for (const opKind of ['verifier', 'publish'] as const) {
    const entry: InvocationJournalEntry = { seq: 1, runId: input.run.id, opId: 'inert-shared-history', opKind, attempt: 0,
      leaseEpoch: 1, phase: 'prepared', target: 'a'.repeat(64), requestRef: 'b'.repeat(64), replayClass: 'manual',
      budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, timestamp: input.run.createdAt };
    await validateInstalledBrokerAmbiguityHistory({ ...input, journal: [entry] });
  }
});

test('Delivery broker-history routing first rejects every model, child, credential, budget, repair and token capability', async () => {
  const input = inheritedBrokerInput();
  const forbidden = async (value: typeof input) => assert.rejects(validateInstalledBrokerAmbiguityHistory(value),
    /^TypeError: delivery continuation cannot carry model, tool, credential, repair or child authority$/u);
  for (const name of ['modelTokens', 'costMicros', 'repairAttempts', 'childDepth', 'childConcurrency'] as const)
    await forbidden({ ...input, spec: { ...input.spec, budgets: { ...input.spec.budgets, [name]: 1 } } });
  await forbidden({ ...input, spec: { ...input.spec, credentialGrantRefs: ['a'.repeat(64)] } });
  await forbidden({ ...input, run: { ...input.run, parentRunId: 'inert-parent' } });
  await forbidden({ ...input, run: { ...input.run, repairCount: 1 } });
  // Deliberately invalid retained data. No child allocation is created or
  // offered as authority; even its presence must be refused before reading it.
  await forbidden({ ...input, childAllocations: [{} as RecoveryClosureV1['childAllocations'][number]] });
  for (const dimension of ['budgetReserved', 'budgetConsumed'] as const)
    for (const name of ['modelTokens', 'costMicros', 'repairAttempts'] as const)
      await forbidden({ ...input, run: { ...input.run, [dimension]: { ...input.run[dimension], [name]: 1 } } });
  for (const opKind of ['model', 'tool', 'mcp', 'mcp-server', 'verifier', 'publish'] as const) {
    const entry: InvocationJournalEntry = { seq: 1, runId: input.run.id, opId: 'inert-forbidden-history', opKind, attempt: 0,
      leaseEpoch: 1, phase: 'prepared', target: 'a'.repeat(64), requestRef: 'b'.repeat(64), replayClass: 'manual',
      budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, timestamp: input.run.createdAt };
    if (!['verifier', 'publish'].includes(opKind)) await forbidden({ ...input, journal: [entry] });
    await forbidden({ ...input, journal: [{ ...entry, brokerFenceTokenDigest: 'c'.repeat(64) }] });
    for (const name of ['modelTokens', 'costMicros', 'repairAttempts'] as const)
      await forbidden({ ...input, journal: [{ ...entry, budgetDelta: { ...entry.budgetDelta, [name]: 1 } }] });
  }
});

test('an Agent with an inherited installed broker still requires its original recipe even with an empty Journal', async () => {
  const delivery = inheritedBrokerInput();
  const assembly = structuredClone(delivery.assembly);
  assembly.provider.adapter.version = 'not-the-installed-recipe';
  const spec = { ...delivery.spec, operation: 'agent' as const, assemblyRef: canonicalSha256(assembly) };
  const input = { ...delivery, assembly, spec, run: { ...delivery.run, specRef: canonicalSha256(spec) } };
  // Hash-consistent but deliberately unsupported recipe data. A model-free
  // Delivery's empty Journal must not exempt an Agent from its recipe guard.
  await assert.rejects(validateInstalledBrokerAmbiguityHistory(input),
    { code: 'RECOVERY_REQUIRED', message: 'installed broker ambiguity does not close its original permanent claim' });
});

test('a delivery data cut cannot carry model, tool, credential, repair or child authority', () => {
  const base = fixture();
  assert.doesNotThrow(() => assertDeliveryModelFreeCut(base));
  for (const name of ['modelTokens', 'costMicros', 'repairAttempts', 'childDepth', 'childConcurrency'] as const)
    assert.throws(() => assertDeliveryModelFreeCut({ ...base, runSpec: { ...base.runSpec,
      budgets: { ...base.runSpec.budgets, [name]: 1 } } }));
  assert.throws(() => assertDeliveryModelFreeCut({ ...base, runSpec: { ...base.runSpec, credentialGrantRefs: ['a'.repeat(64)] } }));
  assert.throws(() => assertDeliveryModelFreeCut({ ...base, run: { ...base.run, parentRunId: 'parent' } }));
  assert.throws(() => assertDeliveryModelFreeCut({ ...base, run: { ...base.run, repairCount: 1 } }));
  assert.throws(() => assertDeliveryModelFreeCut({ ...base, run: { ...base.run,
    budgetConsumed: { ...base.run.budgetConsumed, modelTokens: 1 } } }));
  for (const opKind of ['model', 'tool', 'mcp', 'mcp-server'] as const)
    assert.throws(() => assertDeliveryModelFreeCut({ ...base, journal: [{ seq: 1, runId: base.run.id, opId: 'not-authority', opKind,
      attempt: 0, leaseEpoch: 1, phase: 'prepared', target: 'a'.repeat(64), requestRef: 'b'.repeat(64), replayClass: 'manual',
      budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, timestamp: base.run.createdAt }] }));
});

test('only model-free verifier/publication data can pass the necessary invariant, never a broker claim', () => {
  const base = fixture();
  for (const opKind of ['verifier', 'publish'] as const) {
    const entry: InvocationJournalEntry = { seq: 1, runId: base.run.id, opId: 'data-only', opKind, attempt: 0,
      leaseEpoch: 1, phase: 'prepared', target: 'a'.repeat(64), requestRef: 'b'.repeat(64), replayClass: 'manual',
      budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, timestamp: base.run.createdAt };
    assert.doesNotThrow(() => assertDeliveryModelFreeCut({ ...base, journal: [entry] }));
    assert.throws(() => assertDeliveryModelFreeCut({ ...base, journal: [{ ...entry, brokerFenceTokenDigest: 'c'.repeat(64) }] }));
    for (const name of ['modelTokens', 'costMicros', 'repairAttempts'] as const)
      assert.throws(() => assertDeliveryModelFreeCut({ ...base, journal: [{ ...entry, budgetDelta: { ...entry.budgetDelta, [name]: 1 } }] }));
  }
});

test('an unadmitted initial delivery cut cannot turn zero model budgets into a resource StopIntent', async () => {
  // Complete inert data, not an admitted delivery or a native proof. Initial
  // merge limits require the real original source/admission closure even when
  // no candidate exists; missing storage cannot be treated as its absence.
  const data = fixture(), ref = 'a'.repeat(64);
  const cut: RecoveryClosureV1 = { ...data, items: [], workerLaunches: [], workspaceGenerations: [],
    latestCheckpoint: { schemaVersion: 1, id: data.run.latestCheckpointId, runId: data.run.id,
      // Root Delivery admission really creates its initial Checkpoint at 0.
      // This remains inert unadmitted data, not a fabricated owning cut.
      basedOnRunRevision: 0, runItemSeq: 0, contextManifestRef: ref, journalSeq: 0,
      workspaceStateRef: ref, createdAt: data.run.createdAt, reason: 'initial' } };
  await assert.rejects(readResourceStopCause(undefined as unknown as SqliteDriver,
    undefined as unknown as ArtifactCatalog, cut, cut.run.createdAt), { code: 'RECOVERY_REQUIRED' });
  await assert.rejects(readResourceStopCause(undefined as unknown as SqliteDriver,
    undefined as unknown as ArtifactCatalog, { ...cut, runSpec: { ...cut.runSpec, credentialGrantRefs: ['b'.repeat(64)] } },
    cut.run.createdAt), /model, tool, credential/);
});
