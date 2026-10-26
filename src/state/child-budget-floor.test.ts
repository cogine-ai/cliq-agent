import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { calculateModelCostMicros } from '../model/pricing.js';
import { testFixture } from '../model/testing/fixtures.js';
import { readChildContinuationBudgetFloor } from './child-budget-floor.js';
import { admitChildRun, completeChildAdmissionRefusal, isChildAdmissionRefused } from './child-run-admission.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { createChildRunFixture, offlineDelegateRequest } from './testing/child-runs.js';
import { activateFixtureWorker, disposeFixture } from './testing/fixtures.js';
import { batch } from './testing/tool-calls.js';
import { retireFixtureToolSelection } from './testing/tool-effects.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';

// Cost projections use the frozen test table; every positive child below is
// admitted by the ordinary real Store/SQLite/CAS/owner writer. No provider or
// physical Linux qualification is represented by this fixture.
function exactCeiling() {
  const input = testFixture(), table = input.material.priceTable!.value,
    tokens = table.requestTokenCeiling.inputTokens + table.requestTokenCeiling.outputTokens,
    cost = calculateModelCostMicros(table.requestTokenCeiling, table.prices), child = offlineDelegateRequest('Inspect').requestedBudgets;
  return { modelTokens: child.modelTokens + 3 * tokens, costMicros: child.costMicros + 3 * cost, toolCalls: child.toolCalls + 2 };
}

test('one frozen model continuation floor is shared across actual sibling admissions and counts only unsettled mutating merge obligations', async () => {
  const fixture = await createChildRunFixture('child-continuation-shared-floor', 2, { mode: 'mutating' });
  try {
    const allocations = (await fixture.store.readRecoveryClosure(fixture.runId)).childAllocations.filter(row => row.parentRunId === fixture.runId),
      empty = await readChildContinuationBudgetFloor(fixture.store.artifacts, { parentRunId: fixture.runId,
        assembly: fixture.authority.assembly, allocations: [], nextMode: 'read_only' }),
      siblings = await readChildContinuationBudgetFloor(fixture.store.artifacts, { parentRunId: fixture.runId,
        assembly: fixture.authority.assembly, allocations, nextMode: 'mutating' });
    assert.equal(siblings.modelTokens, empty.modelTokens); assert.equal(siblings.costMicros, empty.costMicros);
    assert.equal(empty.toolCalls, 1); assert.equal(siblings.toolCalls, 4);
    const table = fixture.authority.material.priceTable!.value;
    assert.equal(empty.modelTokens, 2 * (table.requestTokenCeiling.inputTokens + table.requestTokenCeiling.outputTokens));
    assert.equal(empty.costMicros, 2 * calculateModelCostMicros(table.requestTokenCeiling, table.prices));
  } finally { await disposeFixture(fixture); }
});

test('the local zero-cost data projection keeps both full token envelopes without inventing a price or changing any admitted Run', async () => {
  const f = await createAgentFixture('child-floor-local-zero-cost-data');
  try {
    const before = f.store.getRun(f.runId), assembly = structuredClone(f.authority.assembly), endpoint = { scheme: 'http' as const, host: '127.0.0.1' as const, port: 11434 },
      ref = 'a'.repeat(64), provenance: import('../model/pricing.js').LocalZeroCostProvenanceV1 = { schemaVersion: 1, format: 'cliq-local-zero-cost-v1',
        ownerPrincipalId: 'inert-data-principal', provider: 'ollama', model: assembly.provider.model, serviceSpecRef: ref, serviceSpecDigest: ref,
        stableServiceIdentityDigest: ref, endpoint, endpointIdentityDigest: canonicalSha256(endpoint), boundaryEvidenceRef: ref,
        boundaryEvidenceDigest: ref, capabilityEvidenceRef: ref, capabilityDigest: ref, createdAt: '2026-10-01T00:00:00.000Z',
        validThrough: '2026-11-01T00:00:00.000Z', provenanceDigest: '' };
    provenance.provenanceDigest = digestOmitting(provenance, 'provenanceDigest');
    const raw = await f.store.artifacts.publishCanonical(provenance, provenance.format);
    // This is only retained arithmetic data. It is never validated as local
    // endpoint authority, admitted, loaded, prepared or sent to any provider.
    assembly.provider.name = 'ollama'; assembly.provider.endpoint = { kind: 'local_zero_cost', identityDigest: provenance.provenanceDigest, localProvenanceRef: raw.ref };
    assembly.provider.pricing = { kind: 'zero_cost', maxRunCostMicros: 0, provenanceRef: raw.ref };
    const floor = await readChildContinuationBudgetFloor(f.store.artifacts, { parentRunId: f.runId, assembly, allocations: [], nextMode: 'read_only' });
    assert.equal(floor.costMicros, 0);
    assert.equal(floor.modelTokens, 2 * assembly.context.contextLimitTokens + assembly.context.reservedOutputTokens + assembly.context.summaryTokenCap);
    assert.equal(floor.toolCalls, 1); assert.deepEqual(f.store.getRun(f.runId), before);
  } finally { await disposeFixture(f); }
});

test('the genuine admission preserves an explicit child ceiling at the exact floor boundary and refuses one missing model, price or await unit without any child effect', async () => {
  const boundary = exactCeiling(), positive = await createChildRunFixture('child-continuation-exact-floor', 1, { parentBudgets: boundary });
  try {
    const request = offlineDelegateRequest('Inspect').requestedBudgets, child = positive.children[0]!.child,
      spec = await positive.store.artifacts.readCanonical<import('../kernel/types.js').RunSpec>(child.specRef);
    assert.equal(spec.budgets.modelTokens, request.modelTokens); assert.equal(spec.budgets.costMicros, request.costMicros);
    assert.equal(spec.budgets.toolCalls, request.toolCalls);
  } finally { await disposeFixture(positive); }
  for (const field of ['modelTokens', 'costMicros', 'toolCalls'] as const) {
    const fixture = await createAgentFixture(`child-continuation-one-missing-${field}`, { ...boundary, [field]: boundary[field] - 1,
      childDepth: 1 }, { mode: 'yolo', tools: ['delegate', 'await_children', 'read'] });
    try {
      await batch(fixture, [{ name: 'delegate', input: offlineDelegateRequest('Inspect') }]);
      const selected = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
      if (selected.disposition !== 'retirement_required') throw new Error('delegate must retire its original worker');
      await retireFixtureToolSelection(fixture, selected);
      const driver = Reflect.get(fixture.store, 'driver') as SqliteDriver, owner = Reflect.get(fixture.store, 'owner') as StateOwnerContext,
        before = await fixture.store.readRecoveryClosure(fixture.runId);
      let refusal: unknown;
      await assert.rejects(admitChildRun(driver, fixture.store.artifacts, owner, { runId: fixture.runId,
        expectedRunRevision: before.run.revision, releaseKeys: fixture.signed.releaseKeys }), error => {
          refusal = error; assert(isChildAdmissionRefused(error)); assert.match(error.message, new RegExp(`refused by ${field}`)); return true;
        });
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
      assert.equal(driver.prepare('SELECT count(*) AS n FROM runs WHERE parent_run_id=?').get<{n:bigint}>(fixture.runId)!.n, 0n);
      await assert.rejects(completeChildAdmissionRefusal(driver, fixture.store.artifacts, owner, new Error('child allocation is refused')));
      await completeChildAdmissionRefusal(driver, fixture.store.artifacts, owner, refusal);
      const refused = await fixture.store.readRecoveryClosure(fixture.runId);
      assert.equal(refused.journal.length, before.journal.length + 3); assert.equal(refused.run.nextStep, 'agent');
      assert.equal(refused.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 1);
      assert.deepEqual(refused.childAllocations, before.childAllocations); assert.equal(refused.run.budgetReserved.modelTokens, 0);
      assert.equal(driver.prepare('SELECT count(*) AS n FROM runs WHERE parent_run_id=?').get<{n:bigint}>(fixture.runId)!.n, 0n);
      await assert.rejects(completeChildAdmissionRefusal(driver, fixture.store.artifacts, owner, refusal));
      Object.assign(fixture, await activateFixtureWorker(fixture, 'parent-after-no-child', 30_000));
      const next = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
      const result = next.projection.messages.filter(message => message.role === 'tool').at(-1)!;
      assert.equal(result.contentUtf8, JSON.stringify({ reason: field, schemaVersion: 1, status: 'not_admitted' }));
    } finally { await disposeFixture(fixture); }
  }
});
