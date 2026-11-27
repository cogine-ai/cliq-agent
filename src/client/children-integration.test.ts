import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { decodeInstalledControlRequest, decodeInstalledControlResponse } from '../kernel/control-wire.js';
import { parseJsonStrict } from '../kernel/json.js';
import { activateFixtureWorker, disposeFixture, uuidv7 } from '../state/testing/fixtures.js';
import { createChildRunFixture, loadOfflineChild } from '../state/testing/child-runs.js';
import { batch } from '../state/testing/tool-calls.js';
import { retireFixtureToolSelection } from '../state/testing/tool-effects.js';
import { publishInProcessChannel } from '../state/store.js';
import { readWaitingPresentation } from './artifacts.js';
import { humanResponse } from './view.js';

// Actual ordinary Store/SQL/CAS source with the existing explicitly inert
// worker fixture. Client JSON/format checks are never native/Linux authority.
test('Run.list and the common client retain a real child wait and registered parent cancellation through the same closed wire', async () => {
  const f = await createChildRunFixture('common-child-list-and-wait');
  try {
    Object.assign(f, await activateFixtureWorker(f, 'parent-await-presentation', 30000));
    await batch(f, [{ name: 'await_children', input: { childRunIds: [f.children[0]!.childRunId] } }]);
    const selected = await f.agent.prepareTool({ expectedRunRevision: f.store.getRun(f.runId).revision, leaseEpoch: f.leaseEpoch });
    if (selected.disposition !== 'retirement_required') throw new Error('the original parent must retire before child wait');
    await retireFixtureToolSelection(f, selected);
    const waiting = await f.agent.waitForChildren({ expectedRunRevision: f.store.getRun(f.runId).revision });
    const list = decodeInstalledControlRequest({ protocolVersion: 1, method: 'run.list', sessionId: waiting.run.sessionId, limit: 100 });
    if (list.method !== 'run.list') throw new Error('the exact list decoder must remain closed');
    const readList = async () => {
      const response = await f.store.listControl(list, await publishInProcessChannel(f.store));
      const decoded = decodeInstalledControlResponse(parseJsonStrict(canonicalJsonBytes(response).toString('utf8')), list);
      assert(canonicalJsonBytes(decoded).equals(canonicalJsonBytes(response)));
      if (!decoded.ok || decoded.result.method !== 'run.list') throw new Error('the actual list response must retain its method');
      return decoded.result;
    };
    const page = await readList(); assert.equal(page.runs.length, 2);
    const parent = page.runs.find(row => row.run.id === f.runId)!;
    const child = page.runs.find(row => row.run.parentRunId === f.runId)!; assert.equal(child.run.id, f.children[0]!.childRunId);
    assert(humanResponse(list, { protocolVersion: 1, ok: true, result: page }).some(line =>
      line === `${child.run.id}  Queued · child of ${JSON.stringify(f.runId)}`));
    const before = await f.store.readRecoveryClosure(f.runId);
    const app = { artifact: (ref: string, options: { signal?: AbortSignal }) =>
      (options.signal ? f.store.artifacts.withReadSignal(options.signal) : f.store.artifacts).readBytes(ref),
      readRun: async () => { throw new Error('a child wait presentation needs only its original referenced set'); } };
    const view = await readWaitingPresentation(app, parent);
    assert.equal(view.text, `Waiting for child tasks (1):\n  ${JSON.stringify(child.run.id)}`);
    assert.equal(view.waitingOnRef, waiting.run.waitingOnRef); assert.equal(view.responseKind, undefined);
    const subject = await f.store.artifacts.readCanonical<{ subject: { waitSetRef: string } }>(waiting.run.waitingOnRef!);
    assert(!view.text.includes(subject.subject.waitSetRef));
    await assert.rejects(readWaitingPresentation(app, { ...parent, run: { ...parent.run, frontierRef: 'a'.repeat(64) } }), /captured wait/);
    const wrongBytes = { ...app, artifact: async (ref: string, options: { signal?: AbortSignal }) =>
      ref === subject.subject.waitSetRef ? canonicalJsonBytes({ wrong: 'source' }) : app.artifact(ref, options) };
    await assert.rejects(readWaitingPresentation(wrongBytes, parent), /complete original set/);
    assert.deepEqual(await f.store.readRecoveryClosure(f.runId), before);
    const cancel = await f.agent.cancelRun({ ...await publishInProcessChannel(f.store), requestId: uuidv7(), expectedRunRevision: waiting.run.revision });
    const loaded = await loadOfflineChild(f), revoked = await loaded.agent.stopFromParent({ expectedRunRevision: child.run.revision });
    await loaded.agent.commitTerminalStop({ expectedRunRevision: revoked.run.revision });
    const terminalPage = await readList(), terminated = terminalPage.runs.find(row => row.run.id === child.run.id)!;
    assert.equal(terminated.run.status, 'cancelled'); assert.equal(terminated.run.parentCancellationRef, revoked.run.parentCancellationRef);
    assert.equal(terminated.run.stopIntentRef, revoked.run.stopIntentRef); assert.equal(terminated.run.cancelRequested, true);
    const altered = { protocolVersion: 1, ok: true, result: { ...terminalPage, runs: terminalPage.runs.map(row => row.run.id === child.run.id
      ? { ...row, run: { ...row.run, cancelRequested: false } } : row) } };
    assert.throws(() => decodeInstalledControlResponse(altered, list), /parent cancellation/);
    const stoppedWait = await f.agent.waitForStoppedChildren({ expectedRunRevision: cancel.run.revision });
    const stoppedPage = await readList(), stopped = stoppedPage.runs.find(row => row.run.id === f.runId)!;
    assert.equal((await readWaitingPresentation(app, stopped)).text, `Stopping child tasks (1):\n  ${JSON.stringify(child.run.id)}`);
    const settled = await f.agent.settleChildren({ expectedRunRevision: stoppedWait.run.revision });
    await f.agent.commitTerminalStop({ expectedRunRevision: settled.run.revision });
  } finally { await disposeFixture(f); }
});
