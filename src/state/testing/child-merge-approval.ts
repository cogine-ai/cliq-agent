// Real Store, parent/child admission and authenticated delegate approval.
// Existing inert model/worker fixtures remain storage components only; this
// helper never qualifies a provider, child edit or native resource lifecycle.
import assert from 'node:assert/strict';
import { createAgentFixture } from './agent-fixtures.js';
import { activateFixtureWorker, disposeFixture, uuidv7 } from './fixtures.js';
import { batch } from './tool-calls.js';
import { retireFixtureToolSelection } from './tool-effects.js';
import { offlineDelegateRequest, activateOfflineChild, completeOfflineChild } from './child-runs.js';
import { admitChildRun } from '../child-run-admission.js';
import { publishInProcessChannel } from '../store.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import type { StateOwnerContext } from '../state-owner.js';

export async function createMergeApprovalFixture(label: string) {
  const fixture = await createAgentFixture(label, { childDepth: 2, childConcurrency: 1 },
    { mode: 'default', tools: ['await_children', 'delegate', 'edit', 'read'] });
  try {
    await batch(fixture, [{ name: 'delegate', input: offlineDelegateRequest('Inspect a private child fork', 'mutating') }]);
    let selected = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    assert.equal(selected.disposition, 'retirement_required');
    if (selected.disposition !== 'retirement_required') throw new Error('the real original delegate worker must retire');
    assert.equal(selected.reason, 'approval'); await retireFixtureToolSelection(fixture, selected);
    selected = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    assert.equal(selected.disposition, 'approval_required');
    if (selected.disposition !== 'approval_required') throw new Error('the original delegate must receive its own explicit approval');
    const waiting = await fixture.agent.waitForToolApproval({ expectedRunRevision: selected.run.revision, waitingOnRef: selected.waitingOnRef });
    const approved = await fixture.agent.approveTool({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      expectedRunRevision: waiting.run.revision, waitingOnRef: selected.waitingOnRef, decision: 'allow' });
    const driver = Reflect.get(fixture.store, 'driver') as SqliteDriver, owner = Reflect.get(fixture.store, 'owner') as StateOwnerContext;
    const child = await admitChildRun(driver, fixture.store.artifacts, owner, { runId: fixture.runId,
      expectedRunRevision: approved.run.revision, releaseKeys: fixture.signed.releaseKeys });
    const result = { ...fixture, driver, owner, children: [child], originalDelegateApproval: approved.response };
    Object.assign(result, await activateFixtureWorker(result, 'parent-merge-ask-await', 30_000));
    await batch(result, [{ name: 'await_children', input: { childRunIds: [child.childRunId] } }]);
    const retiring = await result.agent.prepareTool({ expectedRunRevision: result.store.getRun(result.runId).revision, leaseEpoch: result.leaseEpoch });
    if (retiring.disposition !== 'retirement_required') throw new Error('the real original await worker must retire');
    await retireFixtureToolSelection(result, retiring);
    const awaiting = await result.agent.waitForChildren({ expectedRunRevision: result.store.getRun(result.runId).revision });
    await completeOfflineChild(await activateOfflineChild(result), { changedWorkspace: true });
    await result.agent.settleChildren({ expectedRunRevision: awaiting.run.revision });
    return result;
  } catch (error) { await disposeFixture(fixture); throw error; }
}
