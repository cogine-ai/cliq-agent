import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { admitChildRun } from './child-run-admission.js';
import { readChildAdmission } from './child-admission.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { batch } from './testing/tool-calls.js';
import { retireFixtureToolSelection } from './testing/tool-effects.js';
import { readToolCut } from './tool-cut.js';
import { activateOfflineChild, completeOfflineChild, createChildRunFixture } from './testing/child-runs.js';

const delegated = (objective: string) => ({ objective, mode: 'read_only',
  context: { source: 'parent_current', additionalArtifactRefs: [] },
  requestedBudgets: { wallTimeMs: 60_000, modelTokens: 10_000, costMicros: 5000, toolCalls: 5,
    repairAttempts: 0, childDepth: 0, childConcurrency: 1 },
  capabilities: { builtinToolNames: ['read'], registeredMcpServerIds: [], allowShell: false, allowSourceWrite: false },
  verifierMode: 'none', allowUnverifiedHelper: true });

// Genuine Store/owner, signed test runtime, SQLite and CAS. Existing inert
// worker-retirement data fixtures exercise storage history only; no native
// execution, child model call or installed platform qualification is claimed.
test('two delegate calls own independent children and budgets through the original exact batch prefix', async () => {
  const fixture = await createAgentFixture('children-two-delegates', { childDepth: 2, childConcurrency: 2 },
    { mode: 'yolo', tools: ['delegate', 'read'] });
  try {
    await batch(fixture, [{ name: 'delegate', input: delegated('Inspect first') }, { name: 'delegate', input: delegated('Inspect second') }]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const selection = await fixture.agent.prepareTool({ expectedRunRevision: before.run.revision, leaseEpoch: before.run.leaseEpoch });
    assert.equal(selection.disposition, 'retirement_required');
    if (selection.disposition !== 'retirement_required') throw new Error('original parent must retire first');
    assert.equal(selection.reason, 'child_admission');
    for (const field of ['entry', 'grant', 'request', 'target']) assert(!Object.hasOwn(selection, field));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await retireFixtureToolSelection(fixture, selection);
    const driver = Reflect.get(fixture.store, 'driver') as SqliteDriver;
    const owner = Reflect.get(fixture.store, 'owner') as StateOwnerContext;
    const queued = fixture.store.getRun(fixture.runId);
    const noWorker = await fixture.agent.prepareTool({ expectedRunRevision: queued.revision, leaseEpoch: queued.leaseEpoch });
    assert.equal(noWorker.disposition, 'child_admission_required');
    const first = await admitChildRun(driver, fixture.store.artifacts, owner, { runId: fixture.runId,
      expectedRunRevision: queued.revision, releaseKeys: fixture.signed.releaseKeys });
    const firstOrigin = await readChildAdmission(driver, fixture.store.artifacts, first.childRunId);
    assert.equal(firstOrigin.run.parentRunId, fixture.runId);
    assert.equal(firstOrigin.delegated.objective, 'Inspect first');
    assert.equal(first.child.leaseEpoch, 0); assert.equal(first.child.activeWorkerLaunchId, undefined);
    const secondCut = await readToolCut(driver, fixture.store.artifacts, fixture.runId, fixture.agent.resolveToolInput);
    assert.equal(secondCut.call.index, 1); assert.equal(secondCut.call.toolName, 'delegate');
    const second = await admitChildRun(driver, fixture.store.artifacts, owner, { runId: fixture.runId,
      expectedRunRevision: first.run.revision, releaseKeys: fixture.signed.releaseKeys });
    const secondOrigin = await readChildAdmission(driver, fixture.store.artifacts, second.childRunId);
    assert.notEqual(first.childRunId, second.childRunId);
    assert.equal(secondOrigin.delegated.objective, 'Inspect second');
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.childAllocations.length, 2);
    assert.equal(after.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 2);
    assert.equal(after.run.budgetReserved.toolCalls, 10);
    assert.equal(after.journal.filter(row => row.opKind === 'child_admission').length, 6);
    assert.equal(after.workerLaunches.length, 0);
    const items = await fixture.store.artifacts.mapReads(after.items, row =>
      fixture.store.artifacts.readCanonical<{ kind: string }>(row.payloadRef));
    assert.equal(items.filter(item => item.kind === 'child_handle').length, 2);
    const beforeReplay = canonicalJsonBytes(after);
    await assert.rejects(admitChildRun(driver, fixture.store.artifacts, owner, { runId: fixture.runId,
      expectedRunRevision: first.run.revision, releaseKeys: fixture.signed.releaseKeys }));
    assert.deepEqual(canonicalJsonBytes(await fixture.store.readRecoveryClosure(fixture.runId)), beforeReplay);
  } finally { await disposeFixture(fixture); }
});

test('an ordinary child terminal commits its incoming usage once without changing the live parent or Session', async () => {
  const fixture = await createChildRunFixture('children-ordinary-terminal');
  try {
    const parent = fixture.store.getRun(fixture.runId), session = fixture.store.getSession(parent.sessionId);
    const child = await activateOfflineChild(fixture);
    const result = await completeOfflineChild(child);
    assert.equal(result.run.status, 'completed_unverified');
    assert.equal(result.run.parentRunId, parent.id);
    assert.deepEqual(fixture.store.getRun(parent.id), parent);
    assert.deepEqual(fixture.store.getSession(parent.sessionId), session);
    const original = await readChildAdmission(fixture.driver, fixture.store.artifacts, child.runId);
    assert.equal(original.allocation.state, 'child_terminal');
    assert.equal(original.allocation.terminalAt, result.run.updatedAt);
    assert.deepEqual(original.allocation.inclusiveBudgetUsage, result.run.budgetConsumed);
    assert.equal(original.allocation.terminal.status, 'completed_unverified');
    assert.equal('patchManifestRef' in original.allocation.terminal, false);
    const replay = await child.agent.commitRunResult({ expectedRunRevision: result.run.revision });
    assert.deepEqual(replay, result);
    assert.deepEqual((await readChildAdmission(fixture.driver, fixture.store.artifacts, child.runId)).allocation, original.allocation);
    assert.deepEqual(fixture.store.getRun(parent.id), parent);
    await fixture.store.readRecoveryClosure(child.runId);
    await fixture.store.readRecoveryClosure(parent.id);
  } finally { await disposeFixture(fixture); }
});
