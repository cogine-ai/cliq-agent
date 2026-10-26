import assert from 'node:assert/strict';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { identityHash } from '../../kernel/identity.js';
import type { ToolContractManifestV1 } from '../../kernel/types.js';
import { readChildAdmission } from '../child-admission.js';
import { sampleCanonicalNow } from '../canonical-time.js';
import { admitChildRun } from '../child-run-admission.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import type { StateOwnerContext } from '../state-owner.js';
import { createAgentFixture } from './agent-fixtures.js';
import { activateFixtureWorker, disposeFixture } from './fixtures.js';
import { batch } from './tool-calls.js';
import { quiescedToolCheckpoint, retireFixtureToolSelection } from './tool-effects.js';

export const offlineDelegateRequest = (objective: string, mode: 'read_only' | 'mutating' = 'read_only') => ({ objective, mode,
  context: { source: 'parent_current' as const, additionalArtifactRefs: [] },
  requestedBudgets: { wallTimeMs: 60_000, modelTokens: 100_000, costMicros: 500_000, toolCalls: 5,
    repairAttempts: 0, childDepth: 0, childConcurrency: 1 },
  capabilities: { builtinToolNames: mode === 'mutating' ? ['edit', 'read'] : ['read'], registeredMcpServerIds: [], allowShell: false, allowSourceWrite: mode === 'mutating' },
  verifierMode: 'none' as const, allowUnverifiedHelper: true });

/** Real StateOwner/Store/SQLite/CAS and signed test-root authority. The original
 * worker/model observations are existing inert fixtures, not physical/backend
 * evidence, provider calls or installed child qualification. */
export async function createChildRunFixture(label: string, count = 1, options: { mode?: 'read_only' | 'mutating'; childDepth?: number; childRequestsInput?: boolean; parentBudgets?: Partial<import('../../kernel/types.js').RunSpec['budgets']> } = {}) {
  const fixture = await createAgentFixture(label, { ...options.parentBudgets, childDepth: 2, childConcurrency: count },
    { mode: 'yolo', tools: ['await_children', 'delegate', 'edit', 'read', ...(options.childRequestsInput ? ['request_input' as const] : [])] });
  try {
    await batch(fixture, Array.from({ length: count }, (_, i) => ({ name: 'delegate', input: (() => { const request = offlineDelegateRequest(`Inspect child ${i}`, options.mode);
      if (options.childRequestsInput) request.capabilities.builtinToolNames.push('request_input');
      if (options.childDepth) {
        // The explicit child ceiling must fund its own later subtree plus
        // the same frozen parent continuation floor; production never shrinks
        // an insufficient request. These are ordinary requested fixture data.
        Object.assign(request.requestedBudgets, { childDepth: options.childDepth, modelTokens: 400_000, costMicros: 2_000_000, toolCalls: 20 });
        request.capabilities.builtinToolNames.push('await_children', 'delegate');
      }
      return request; })() })));
    const selected = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      leaseEpoch: fixture.leaseEpoch });
    assert.equal(selected.disposition, 'retirement_required');
    if (selected.disposition !== 'retirement_required') throw new Error('original fixture worker must retire');
    assert.equal(selected.reason, 'child_admission');
    await retireFixtureToolSelection(fixture, selected);
    const driver = Reflect.get(fixture.store, 'driver') as SqliteDriver, owner = Reflect.get(fixture.store, 'owner') as StateOwnerContext;
    const children: Array<Awaited<ReturnType<typeof admitChildRun>>> = [];
    for (let i = 0; i < count; i++) children.push(await admitChildRun(driver, fixture.store.artifacts, owner,
      { runId: fixture.runId, expectedRunRevision: fixture.store.getRun(fixture.runId).revision, releaseKeys: fixture.signed.releaseKeys }));
    return { ...fixture, driver, owner, children };
  } catch (error) { await disposeFixture(fixture); throw error; }
}

export async function loadOfflineChild(fixture: Awaited<ReturnType<typeof createChildRunFixture>>, index = 0) {
  const runId = fixture.children[index]!.childRunId;
  const original = await readChildAdmission(fixture.driver, fixture.store.artifacts, runId);
  const manifest = await fixture.store.artifacts.readCanonical<ToolContractManifestV1>(original.capabilityGrant.childToolManifestRef);
  const tools = await fixture.store.artifacts.mapReads(manifest.entries, async entry => ({ name: entry.name, description: entry.description,
    inputSchemaRef: entry.inputSchemaRef, inputSchemaDigest: entry.inputSchemaDigest, replayClass: entry.replayClass,
    inputSchema: await fixture.store.artifacts.readCanonical(entry.inputSchemaRef) }));
  const material = { ...fixture.authority.material, resolveVerifiedTools: (reference: { manifestRef: string; manifestDigest: string }) =>
    reference.manifestRef === canonicalSha256(manifest) && reference.manifestDigest === manifest.manifestDigest ? tools : null };
  const agent = await fixture.store.loadAgentRun({ runId, material, releaseKeys: fixture.signed.releaseKeys });
  return { ...fixture, runId, agent, childMaterial: material };
}

export async function activateOfflineChild(fixture: Awaited<ReturnType<typeof createChildRunFixture>>, index = 0) {
  const loaded = await loadOfflineChild(fixture, index);
  return { ...loaded, ...await activateFixtureWorker(loaded, `child-${index}`, 30_000) };
}

/** Same ordinary reducer chain as root RunResult tests, with its existing
 * explicitly inert process-death/snapshot fixtures. No new evidence brand. */
export async function completeOfflineChild(fixture: Awaited<ReturnType<typeof activateOfflineChild>>, options: { changedWorkspace?: boolean | string } = {}) {
  const { store, agent, runId, leaseEpoch } = fixture;
  const prepared = await agent.prepareModel({ expectedRunRevision: store.getRun(runId).revision, leaseEpoch });
  await store.claimInvocationDispatch({ runId, expectedRunRevision: prepared.run.revision, leaseEpoch,
    opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'offline-child-model' });
  const response = agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  response.push(Buffer.from(JSON.stringify({ id: 'offline-child-response', object: 'response', status: 'completed', model: 'model-1',
    output: [{ type: 'message', id: 'offline-child-message', role: 'assistant', status: 'completed',
      content: [{ type: 'output_text', text: 'The child inspection is complete.', annotations: [] }] }] })));
  const completed = await agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
    expectedRunRevision: prepared.run.revision, result: response.finish(sampleCanonicalNow(), agent.resolveToolInput) });
  assert.equal(completed.disposition, 'candidate_required');
  const owner = await agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
  const itemId = identityHash('cliq-model-turn-item-v1', runId, prepared.entry.opId, String(prepared.entry.attempt));
  const proof = await quiescedToolCheckpoint(fixture, identityHash('cliq-final-candidate-checkpoint-v1', runId, itemId), options.changedWorkspace);
  await owner.complete({ expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint });
  await agent.completeVerification({ expectedRunRevision: store.getRun(runId).revision });
  return agent.commitRunResult({ expectedRunRevision: store.getRun(runId).revision });
}

export async function createChildMergeFixture(label: string, changedWorkspace = false, childCount = 1) {
  const fixture = await createChildRunFixture(label, childCount, { mode: 'mutating' });
  try {
    Object.assign(fixture, await activateFixtureWorker(fixture, 'parent-merge-await', 30_000));
    await batch(fixture, [{ name: 'await_children', input: { childRunIds: [fixture.children[0]!.childRunId] } }]);
    const selected = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      leaseEpoch: fixture.leaseEpoch });
    if (selected.disposition !== 'retirement_required') throw new Error('merge await must retire the original fixture parent');
    await retireFixtureToolSelection(fixture, selected);
    const waiting = await fixture.agent.waitForChildren({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    await completeOfflineChild(await activateOfflineChild(fixture), { changedWorkspace });
    await fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision });
    return fixture;
  } catch (error) { await disposeFixture(fixture); throw error; }
}
