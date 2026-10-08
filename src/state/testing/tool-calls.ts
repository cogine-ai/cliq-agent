import assert from 'node:assert/strict';
import { digestOmitting } from '../../kernel/identity.js';
import type { ToolObservationV1 } from '../../kernel/tool-authorization.js';
import type { createAgentFixture } from './agent-fixtures.js';
import { sampleCanonicalNow } from '../canonical-time.js';
import { publishFixtureEditLaunch } from './worker-launch.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;

export async function batch(fixture: Fixture, calls: Array<{ name: string; input: unknown }>) {
  const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
  await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
    leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'model-dispatch' });
  const response = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  response.push(Buffer.from(JSON.stringify({ id: 'response', object: 'response', status: 'completed', model: 'model-1',
    output: calls.map((call, index) => ({ type: 'function_call', id: `wire-${index}`, call_id: `call-${index}`,
      name: call.name, arguments: JSON.stringify(call.input) })) })));
  return fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt, expectedRunRevision: prepared.run.revision,
    result: response.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
}

export async function prepareTool(fixture: Fixture) {
  const result = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
  assert.equal(result.disposition, 'prepared');
  if (result.disposition !== 'prepared') throw new Error('test expected authorized tool preparation');
  return result;
}

export async function claimTool(fixture: Fixture, prepared: Awaited<ReturnType<typeof prepareTool>>) {
  const dispatchId = `tool-dispatch-${prepared.request.callIndex}`;
  const launch = prepared.request.toolName === 'edit' ? await publishFixtureEditLaunch(fixture, prepared, dispatchId) : undefined;
  return fixture.agent.claimTool({ expectedRunRevision: prepared.run.revision, leaseEpoch: fixture.leaseEpoch,
    opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId,
    ...(launch ? { sandboxLaunchSpecRef: launch.sandboxLaunchSpecRef } : {}) });
}

export async function observation(fixture: Fixture, claimed: Awaited<ReturnType<typeof claimTool>>, content: unknown) {
  const value: ToolObservationV1 = { schemaVersion: 1, format: 'cliq-tool-observation-v1', runId: fixture.runId,
    opId: claimed.entry.opId, attempt: claimed.entry.attempt, requestRef: claimed.entry.requestRef, targetRef: claimed.entry.target,
    grantRef: claimed.entry.grantRef!, dispatchId: claimed.entry.dispatchId!, outcome: 'executed', content,
    observedAt: sampleCanonicalNow(), observationDigest: '' };
  value.observationDigest = digestOmitting(value, 'observationDigest');
  return (await fixture.store.artifacts.publishCanonical(value, value.format)).ref;
}
