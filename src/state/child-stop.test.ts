import assert from 'node:assert/strict';
import test from 'node:test';
import { readParentStopRevocation } from './parent-stop-revocation.js';
import { admitChildRun, completeChildAdmissionRefusal, isChildAdmissionRefused } from './child-run-admission.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { quiescedToolCheckpoint, retireFixtureToolSelection } from './testing/tool-effects.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { readChildTerminalData } from './child-terminal.js';
import { publishInProcessChannel } from './store.js';
import { activateOfflineChild, createChildRunFixture, loadOfflineChild, offlineDelegateRequest } from './testing/child-runs.js';
import { activateFixtureWorker, disposeFixture, uuidv7 } from './testing/fixtures.js';

test('a queued ordinary child cancellation commits its own terminal allocation without a worker or root Session outcome', async () => {
  const fixture = await createChildRunFixture('child-queued-user-stop');
  try {
    const parent = fixture.store.getRun(fixture.runId), session = fixture.store.getSession(parent.sessionId);
    const child = await loadOfflineChild(fixture);
    const command = { ...await publishInProcessChannel(fixture.store), requestId: uuidv7(), expectedRunRevision: child.store.getRun(child.runId).revision };
    const cancelled = await child.agent.cancelRun(command);
    assert.equal(cancelled.run.cancelRequested, true);
    const stopped = await child.agent.commitTerminalStop({ expectedRunRevision: cancelled.run.revision });
    assert.equal(stopped.run.status, 'cancelled'); assert.equal(stopped.run.terminalReason, 'cancelled_by_user');
    const terminal = await readChildTerminalData(fixture.driver, fixture.store.artifacts, child.runId);
    assert.equal(terminal.allocation.state, 'child_terminal');
    assert.equal(terminal.terminalDetail?.reason, 'cancelled_by_user');
    assert.equal(terminal.result, undefined); assert.equal(terminal.patch, undefined);
    assert.deepEqual(canonicalJsonBytes(terminal.inclusiveBudgetUsage), Buffer.from('{"costMicros":0,"modelTokens":0,"repairAttempts":0,"toolCalls":0}'));
    assert.deepEqual(fixture.store.getRun(parent.id), parent);
    assert.deepEqual(fixture.store.getSession(session.id), session);
    const cut = await fixture.store.readRecoveryClosure(child.runId);
    assert.equal(cut.workerLaunches.length, 0); assert.equal(cut.workspaceGenerations.length, 0); assert.equal(cut.journal.length, 0);
    assert.deepEqual(await child.agent.commitTerminalStop({ expectedRunRevision: stopped.run.revision }), stopped);
    assert.deepEqual((await readChildTerminalData(fixture.driver, fixture.store.artifacts, child.runId)).allocation, terminal.allocation);
  } finally { await disposeFixture(fixture); }
});

test('a registered parent Stop only revokes its ordinary child; the child still closes its own terminal allocation', async () => {
  const fixture = await createChildRunFixture('child-parent-stop');
  try {
    const parent = fixture.store.getRun(fixture.runId), session = fixture.store.getSession(parent.sessionId);
    const child = await loadOfflineChild(fixture);
    await assert.rejects(child.agent.stopFromParent({ expectedRunRevision: fixture.store.getRun(child.runId).revision }), /registered StopIntent/);
    const cancelled = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(), expectedRunRevision: parent.revision });
    assert.equal(cancelled.run.status, 'queued');
    await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: cancelled.run.revision }), /child stop settlement/);
    const fenced = await child.agent.stopFromParent({ expectedRunRevision: fixture.store.getRun(child.runId).revision });
    assert.equal(fenced.run.cancelRequested, true, 'the cancellation dispatch index also covers a proven parent revocation');
    const ref = fenced.run.stopIntentRef!;
    assert.equal(fenced.run.parentCancellationRef, ref, 'the first winning parent observation is registered in the same child transaction');
    const intent = await fixture.store.artifacts.readCanonical<import('../runtime/stop.js').AgentStopIntent>(ref);
    assert.equal(intent.origin, 'parent_cancel');
    if (intent.origin !== 'parent_cancel') throw new Error('expected parent revocation');
    assert.equal(intent.sourceStopIntentRef, cancelled.run.stopIntentRef); assert.equal(intent.sourceRunId, parent.id);
    assert.deepEqual(fixture.store.getRun(parent.id), cancelled.run, 'child fencing does not settle or terminate its parent');
    const stopped = await child.agent.commitTerminalStop({ expectedRunRevision: fenced.run.revision });
    assert.equal(stopped.run.status, 'cancelled'); assert.equal(stopped.run.terminalReason, 'parent_cancelled');
    const terminal = await readChildTerminalData(fixture.driver, fixture.store.artifacts, child.runId);
    assert.equal(terminal.terminalDetail?.reason, 'parent_cancelled'); assert.equal(terminal.terminalDetail?.primaryEvidenceRef, cancelled.run.stopIntentRef);
    assert.equal(terminal.allocation.state, 'child_terminal');
    assert.deepEqual(fixture.store.getSession(session.id), session);
  } finally { await disposeFixture(fixture); }
});

test('a parent cancellation drains a genuine worker-free child input wait and settles its original allocation once', async () => {
  const fixture = await createChildRunFixture('child-input-parent-stop', 1, { childRequestsInput: true });
  try {
    const child = await activateOfflineChild(fixture), session = fixture.store.getSession(fixture.store.getRun(fixture.runId).sessionId);
    await batch(child, [{ name: 'request_input', input: { prompt: 'Which file should I inspect?', responseKind: 'text', maximumResponseBytes: 128 } }]);
    const selected = await child.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(child.runId).revision, leaseEpoch: child.leaseEpoch });
    assert.equal(selected.disposition, 'retirement_required');
    if (selected.disposition !== 'retirement_required') throw new Error('the original input worker must retire');
    assert.equal(selected.reason, 'input'); await retireFixtureToolSelection(child, selected);
    const pending = await child.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(child.runId).revision, leaseEpoch: child.leaseEpoch });
    assert.equal(pending.disposition, 'input_required');
    if (pending.disposition !== 'input_required') throw new Error('the exact original input must remain selected');
    const waiting = await child.agent.waitForInput({ expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef });
    assert.equal(waiting.run.waitingReason, 'input'); assert.equal(waiting.run.activeWorkerLaunchId, undefined);
    const before = await fixture.store.readRecoveryClosure(child.runId);
    const parent = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    const registered = await child.agent.stopFromParent({ expectedRunRevision: waiting.run.revision });
    assert.equal(registered.run.parentCancellationRef, registered.run.stopIntentRef);
    const stopped = await child.agent.commitTerminalStop({ expectedRunRevision: registered.run.revision });
    assert.equal(stopped.run.status, 'cancelled'); assert.equal(stopped.run.terminalReason, 'parent_cancelled');
    const after = await fixture.store.readRecoveryClosure(child.runId);
    assert.deepEqual(after.journal, before.journal, 'input cancellation cannot create a productive claim or consume a call');
    assert.equal(after.run.budgetConsumed.toolCalls, 0);
    const items = await fixture.store.artifacts.mapReads(after.items, row => fixture.store.artifacts.readCanonical<import('../kernel/types.js').ContinuationItem>(row.payloadRef));
    assert.deepEqual(items.filter(item => item.kind === 'tool_result').map(item => item.outcome), ['cancelled']);
    assert.equal(items.some(item => item.kind === 'user_input'), false);
    assert.deepEqual(fixture.store.getSession(session.id), session, 'a child terminal never adds a root Session outcome');
    const pendingChildren = await fixture.agent.waitForStoppedChildren({ expectedRunRevision: parent.run.revision });
    const settled = await fixture.agent.settleChildren({ expectedRunRevision: pendingChildren.run.revision });
    assert.equal(settled.run.budgetConsumed.toolCalls, parent.run.budgetConsumed.toolCalls);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: settled.run.revision });
    assert.equal(terminal.run.status, 'cancelled'); assert.equal(fixture.store.getSession(session.id).contextRevision, session.contextRevision + 1);
    assert.deepEqual(await fixture.agent.commitTerminalStop({ expectedRunRevision: terminal.run.revision }), terminal);
    assert.equal((await readChildTerminalData(fixture.driver, fixture.store.artifacts, child.runId)).allocation.state, 'settled');
  } finally { await disposeFixture(fixture); }
});

test('a later parent cancellation registers once beneath a real higher user winner and cannot turn an orphan into source history', async () => {
  const f = await createChildRunFixture('child-parent-cancellation-losing-observation');
  try {
    const child = await loadOfflineChild(f), cancelled = await child.agent.cancelRun({ ...await publishInProcessChannel(f.store), requestId: uuidv7(),
      expectedRunRevision: f.store.getRun(child.runId).revision }), originalWinner = cancelled.run.stopIntentRef;
    const parent = await f.agent.cancelRun({ ...await publishInProcessChannel(f.store), requestId: uuidv7(), expectedRunRevision: f.store.getRun(f.runId).revision });
    const observed = await child.agent.stopFromParent({ expectedRunRevision: cancelled.run.revision }), pointer = observed.run.parentCancellationRef!;
    assert(pointer); assert.notEqual(pointer, originalWinner); assert.equal(observed.run.stopIntentRef, originalWinner);
    const intent = await f.store.artifacts.readCanonical<import('../runtime/stop.js').AgentStopIntent>(pointer);
    if (intent.origin !== 'parent_cancel') throw new Error('expected the actual losing parent observation');
    assert.equal(intent.supersedesStopIntentRef, undefined); assert.equal(intent.sourceStopIntentRef, parent.run.stopIntentRef);
    const before = await f.store.readRecoveryClosure(child.runId);
    assert.deepEqual(await child.agent.stopFromParent({ expectedRunRevision: observed.run.revision }), observed);
    assert.deepEqual(await f.store.readRecoveryClosure(child.runId), before);
    assert.throws(() => f.driver.prepare('UPDATE runs SET parent_cancellation_ref=NULL WHERE id=?').run(child.runId), /immutable/);
    assert.throws(() => f.driver.prepare('UPDATE runs SET parent_cancellation_ref=? WHERE id=?').run(originalWinner!, child.runId), /immutable/);
    const metadata = f.driver.prepare('SELECT * FROM artifacts WHERE ref=?').get<{ref:string;media_type:string;schema_kind:string;byte_length:bigint;created_at:string}>(pointer)!;
    f.driver.prepare('DELETE FROM artifacts WHERE ref=?').run(pointer);
    try { await assert.rejects(f.store.readRecoveryClosure(child.runId), /registration metadata/); }
    finally { f.driver.prepare('INSERT INTO artifacts(ref,media_type,schema_kind,byte_length,created_at) VALUES(?,?,?,?,?)')
      .run(metadata.ref, metadata.media_type, metadata.schema_kind, metadata.byte_length, metadata.created_at); }
    // A correctly hashed orphan uses the real child and real parent source,
    // but was never entered by the original registration transaction.
    const orphan = await f.store.artifacts.publishCanonical({ ...intent, createdAt: child.store.getRun(child.runId).createdAt }, 'cliq-stop-intent-v1');
    const immutable = f.driver.prepare("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='runs_parent_cancellation_immutable'").get<{sql:string}>()!.sql;
    const replace = (ref: string) => f.driver.transaction(connection => {
      connection.exec('DROP TRIGGER runs_parent_cancellation_immutable'); connection.prepare('UPDATE runs SET parent_cancellation_ref=? WHERE id=?').run(ref, child.runId); connection.exec(immutable);
    });
    replace(orphan.ref);
    try { await assert.rejects(f.store.readRecoveryClosure(child.runId)); }
    finally { replace(pointer); }
    assert.deepEqual(await f.store.readRecoveryClosure(child.runId), before);
    const terminal = await child.agent.commitTerminalStop({ expectedRunRevision: observed.run.revision });
    assert.equal(terminal.run.terminalReason, 'cancelled_by_user'); assert.equal(terminal.run.parentCancellationRef, pointer);
    assert.equal(terminal.run.stopIntentRef, originalWinner); await f.store.readRecoveryClosure(child.runId);
    await assert.rejects(child.agent.stopFromParent({ expectedRunRevision: terminal.run.revision }));
    assert.deepEqual(f.store.getRun(child.runId), terminal.run);
  } finally { await disposeFixture(f); }
});

test('a received claimed child result survives the actual parent cancellation fence and settles the original claim once', async () => {
  const f = await createChildRunFixture('child-parent-cancel-received-original-result');
  let release = () => {}, pending: Promise<unknown> | undefined;
  const publish = f.store.artifacts.publishBytes.bind(f.store.artifacts);
  try {
    const child = await activateOfflineChild(f);
    await batch(child, [{ name: 'read', input: { path: 'a' } }, { name: 'read', input: { path: 'b' } }]);
    const prepared = await prepareTool(child), claimed = await claimTool(child, prepared), originalRef = await observation(child, claimed, { text: 'actual original received result' });
    let entered!: () => void;
    const reached = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    let holding = false;
    f.store.artifacts.publishBytes = async (bytes, media, kind) => {
      const result = await publish(bytes, media, kind);
      if (!holding && kind === 'cliq-tool-result-model-content-v1') { holding = true; entered(); await gate; }
      return result;
    };
    // Hold only a completed actual CAS return, not a process, clock or native
    // task. The original completion still owns its received observation.
    pending = child.agent.completeTool({ opId: prepared.entry.opId, attempt: 0, expectedRunRevision: prepared.run.revision, observationRef: originalRef });
    const outcome = pending.then(value => ({ value }), error => ({ error }));
    await Promise.race([reached, outcome.then(() => { throw new Error('completion did not reach its actual publication'); })]);
    await f.agent.cancelRun({ ...await publishInProcessChannel(f.store), requestId: uuidv7(), expectedRunRevision: f.store.getRun(f.runId).revision });
    const stopped = await child.agent.stopFromParent({ expectedRunRevision: f.store.getRun(child.runId).revision });
    assert(stopped.run.parentCancellationRef); assert.equal(stopped.run.stopIntentRef, stopped.run.parentCancellationRef);
    release();
    const first = await outcome;
    assert('error' in first); assert.equal((first.error as { code: string }).code, 'REVISION_CONFLICT');
    f.store.artifacts.publishBytes = publish;
    const completed = await child.agent.completeTool({ opId: prepared.entry.opId, attempt: 0,
      expectedRunRevision: stopped.run.revision, observationRef: originalRef });
    assert.equal(completed.run.budgetConsumed.toolCalls, 1); assert.equal(completed.run.parentCancellationRef, stopped.run.parentCancellationRef);
    const after = await f.store.readRecoveryClosure(child.runId), rows = after.journal.filter(row => row.opId === prepared.entry.opId);
    assert.deepEqual(rows.map(row => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
    assert.equal(rows[1]!.dispatchId, claimed.entry.dispatchId); assert.equal(rows[2]!.resultRef, originalRef);
    const proof = await quiescedToolCheckpoint(child, stopped.checkpointId);
    const terminal = await child.agent.commitTerminalStop({ expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint });
    assert.equal(terminal.run.status, 'cancelled'); assert.equal(terminal.run.terminalReason, 'parent_cancelled');
    assert.equal(terminal.run.budgetConsumed.toolCalls, 1);
    const cut = await f.store.readRecoveryClosure(child.runId), items = await f.store.artifacts.mapReads(cut.items,
      row => f.store.artifacts.readCanonical<import('../kernel/types.js').ContinuationItem>(row.payloadRef));
    assert.deepEqual(items.filter(item => item.kind === 'tool_result').map(item => item.outcome), ['executed', 'cancelled']);
    assert.deepEqual(cut.journal, after.journal); assert.equal((await readChildTerminalData(f.driver, f.store.artifacts, child.runId)).inclusiveBudgetUsage.toolCalls, 1);
  } finally { release(); await pending?.catch(() => undefined); f.store.artifacts.publishBytes = publish; await disposeFixture(f); }
});

test('a parent waits for ordinary cancelled children and settles each once before its one root terminal outcome', async () => {
  const fixture = await createChildRunFixture('parent-stop-settlement', 2);
  try {
    const initial = fixture.store.getRun(fixture.runId), session = fixture.store.getSession(initial.sessionId);
    const cancelled = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(), expectedRunRevision: initial.revision });
    const waiting = await fixture.agent.waitForStoppedChildren({ expectedRunRevision: cancelled.run.revision });
    assert.equal(waiting.run.status, 'waiting'); assert.equal(waiting.run.waitingReason, 'child');
    assert.equal(waiting.run.activeWorkerLaunchId, undefined);
    for (let index=0; index<2; index++) {
      const child = await loadOfflineChild(fixture, index);
      const stop = await child.agent.stopFromParent({ expectedRunRevision: fixture.store.getRun(child.runId).revision });
      await child.agent.commitTerminalStop({ expectedRunRevision: stop.run.revision });
      if (index === 0) assert.deepEqual(await fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision }), waiting);
      assert.deepEqual(fixture.store.getSession(session.id), session);
    }
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    fixture.driver.exec("CREATE TRIGGER fail_stop_child_settlement BEFORE UPDATE ON child_allocations WHEN NEW.state='settled' BEGIN SELECT RAISE(ABORT,'injected Stop child settlement failure'); END");
    try {
      await assert.rejects(fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision }), /injected Stop child settlement failure/);
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), cut);
    } finally { fixture.driver.exec('DROP TRIGGER fail_stop_child_settlement'); }
    const settled = await fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision });
    assert.equal(settled.run.status, 'queued'); assert.equal(settled.run.stopIntentRef, cancelled.run.stopIntentRef);
    assert.deepEqual(canonicalJsonBytes(settled.run.budgetReserved), Buffer.from('{"costMicros":0,"modelTokens":0,"repairAttempts":0,"toolCalls":0}'));
    const accounted = await fixture.store.readRecoveryClosure(fixture.runId);
    const items = await fixture.store.artifacts.mapReads(accounted.items, row => fixture.store.artifacts.readCanonical<import('../kernel/types.js').ContinuationItem>(row.payloadRef));
    assert.equal(items.filter(item => item.kind === 'child_result' && item.delivery.kind === 'stop_settlement').length, 2);
    assert.equal(items.some(item => item.kind === 'child_merge_batch'), false);
    assert.deepEqual(accounted.journal, cut.journal, 'Stop child settlement adds no execution claim or call charge');
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: settled.run.revision });
    assert.equal(terminal.run.status, 'cancelled'); assert.equal(terminal.run.terminalReason, 'cancelled_by_user');
    assert.equal(fixture.store.getSession(session.id).contextRevision, session.contextRevision + 1);
    assert.deepEqual(await fixture.agent.commitTerminalStop({ expectedRunRevision: terminal.run.revision }), terminal);
  } finally { await disposeFixture(fixture); }
});


test('a nested child retains the actual old parent revocation only through a strictly registered replacement chain', async () => {
  const fixture = await createChildRunFixture('child-stop-registration-chain', 1, { childDepth: 1 });
  try {
    const middle = await activateOfflineChild(fixture);
    await batch(middle, [{ name: 'delegate', input: offlineDelegateRequest('Inspect the nested child') }]);
    const selection = await middle.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(middle.runId).revision, leaseEpoch: middle.leaseEpoch });
    if (selection.disposition !== 'retirement_required') throw new Error('delegate must retire its original middle worker');
    await retireFixtureToolSelection(middle, selection);
    const nested = await admitChildRun(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: middle.runId, expectedRunRevision: fixture.store.getRun(middle.runId).revision, releaseKeys: fixture.signed.releaseKeys });
    const nestedFixture = { ...fixture, children: [nested] };
    const child = await loadOfflineChild(nestedFixture);
    await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(), expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    const middleStop = await middle.agent.stopFromParent({ expectedRunRevision: fixture.store.getRun(middle.runId).revision });
    const childStop = await child.agent.stopFromParent({ expectedRunRevision: fixture.store.getRun(child.runId).revision });
    const next = await middle.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(), expectedRunRevision: middleStop.run.revision });
    const current = await fixture.store.artifacts.readCanonical<import('../runtime/stop.js').AgentStopIntent>(next.run.stopIntentRef!);
    assert.equal(current.supersedesStopIntentRef, middleStop.run.stopIntentRef);
    assert.equal((await readParentStopRevocation(fixture.driver, fixture.store.artifacts, child.runId, middleStop.run.stopIntentRef)).intent.origin, 'parent_cancel');
    // A well-formed but never registered artifact is not a prior SQL winner.
    const { supersedesStopIntentRef: _prior, ...withoutPrior } = current;
    const unregistered = await fixture.store.artifacts.publishCanonical(withoutPrior, 'cliq-stop-intent-v1');
    await assert.rejects(readParentStopRevocation(fixture.driver, fixture.store.artifacts, child.runId, unregistered.ref), /registered replacement chain/);
    const actual = fixture.store.getRun(middle.runId);
    fixture.driver.prepare('UPDATE runs SET stop_intent_ref=? WHERE id=?').run(unregistered.ref, middle.runId);
    try {
      await assert.rejects(readParentStopRevocation(fixture.driver, fixture.store.artifacts, child.runId, middleStop.run.stopIntentRef), /registered replacement chain/);
    } finally { fixture.driver.prepare('UPDATE runs SET stop_intent_ref=? WHERE id=?').run(actual.stopIntentRef!, middle.runId); }
    const terminal = await child.agent.commitTerminalStop({ expectedRunRevision: childStop.run.revision });
    assert.equal(terminal.run.terminalReason, 'parent_cancelled');
    assert.equal((await readChildTerminalData(fixture.driver, fixture.store.artifacts, child.runId)).allocation.state, 'child_terminal');
  } finally { await disposeFixture(fixture); }
});


test('cancelling an existing await keeps its original wait provenance and cancels only its real provider call', async () => {
  const fixture = await createChildRunFixture('parent-stop-interrupted-await');
  try {
    Object.assign(fixture, await activateFixtureWorker(fixture, 'parent-stop-await', 30_000));
    await batch(fixture, [{ name: 'await_children', input: { childRunIds: [fixture.children[0]!.childRunId] } }]);
    const selection = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    if (selection.disposition !== 'retirement_required') throw new Error('await requires original parent retirement');
    await retireFixtureToolSelection(fixture, selection);
    const original = await fixture.agent.waitForChildren({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    const cancelled = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(), expectedRunRevision: original.run.revision });
    const selected = await fixture.agent.planStoppedChildren({ expectedRunRevision: cancelled.run.revision });
    assert.equal(selected.disposition, 'child_stop_required');
    const waiting = await fixture.agent.waitForStoppedChildren({ expectedRunRevision: cancelled.run.revision });
    const subject = await fixture.store.artifacts.readCanonical<import('../kernel/children.js').ChildWaitingSubject>(waiting.run.waitingOnRef!);
    assert.equal(subject.subject.kind, 'stop_settlement');
    if (subject.subject.kind !== 'stop_settlement') throw new Error('expected actual Stop wait');
    assert.equal(subject.subject.interruptedWaitRef, original.run.waitingOnRef);
    assert(subject.subject.awaitOrigin);
    const child = await loadOfflineChild(fixture);
    const stop = await child.agent.stopFromParent({ expectedRunRevision: fixture.store.getRun(child.runId).revision });
    await child.agent.commitTerminalStop({ expectedRunRevision: stop.run.revision });
    const settled = await fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision });
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: settled.run.revision });
    assert.equal(terminal.run.status, 'cancelled');
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    const items = await fixture.store.artifacts.mapReads(cut.items, row => fixture.store.artifacts.readCanonical<import('../kernel/types.js').ContinuationItem>(row.payloadRef));
    const origin = subject.subject.awaitOrigin!;
    const results = items.filter(item => item.kind === 'tool_result' && item.batchItemId === origin.batchItemId);
    assert.equal(results.length, 1); assert.equal(results[0]!.kind, 'tool_result');
    if (results[0]!.kind !== 'tool_result') throw new Error('expected the original provider tool result');
    assert.equal(results[0]!.outcome, 'cancelled');
    assert.equal(cut.journal.some(entry => entry.opKind === 'child_merge'), false);
    assert.equal(items.some(item => item.kind === 'child_merge_batch'), false);
  } finally { await disposeFixture(fixture); }
});


test('conservative child reservations can stop a parent without losing the original budget cause after settlement', async () => {
  // Admission now retains two full model envelopes. Consume them through two
  // ordinary model/read continuations instead of admitting a starved child.
  const ceiling = 100_000 + 3 * (32_768 + 8_192);
  const fixture = await createChildRunFixture('parent-child-budget-stop', 1, { parentBudgets: { modelTokens: ceiling } });
  try {
    Object.assign(fixture, await activateFixtureWorker(fixture, 'parent-consuming-continuation-floor', 30_000));
    for (let i = 0; i < 2; i++) {
      await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
      const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared),
        observationRef = await observation(fixture, claimed, { text: 'original read fixture result' });
      await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
        expectedRunRevision: prepared.run.revision, observationRef });
    }
    const before = fixture.store.getRun(fixture.runId);
    assert.equal(before.budgetReserved.modelTokens + before.budgetConsumed.modelTokens, ceiling);
    const stopped = await fixture.agent.stopForResourceFailure({ expectedRunRevision: before.revision });
    const intent = await fixture.store.artifacts.readCanonical<import('../runtime/stop.js').AgentStopIntent>(stopped.run.stopIntentRef!);
    assert.equal(intent.origin, 'budget');
    if (intent.origin !== 'budget') throw new Error('expected conservative budget exhaustion');
    assert.equal(intent.counter, 'modelTokens'); assert.equal(intent.reserved, before.budgetReserved.modelTokens);
    const selected = await fixture.agent.planStoppedChildren({ expectedRunRevision: stopped.run.revision });
    if (selected.disposition !== 'child_stop_required') throw new Error('actual parent worker must retire for Stop settlement');
    const proof = await quiescedToolCheckpoint(fixture, selected.checkpointId);
    const waiting = await fixture.agent.waitForStoppedChildren({ expectedRunRevision: stopped.run.revision, checkpoint: proof.checkpoint });
    const child = await loadOfflineChild(fixture);
    const revoked = await child.agent.stopFromParent({ expectedRunRevision: fixture.store.getRun(child.runId).revision });
    await child.agent.commitTerminalStop({ expectedRunRevision: revoked.run.revision });
    const settled = await fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision });
    assert.equal(settled.run.budgetReserved.modelTokens, 0);
    const retained = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(retained.run.stopIntentRef, stopped.run.stopIntentRef);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: settled.run.revision });
    assert.equal(terminal.run.status, 'failed'); assert.equal(terminal.run.terminalReason, 'budget_exhausted');
  } finally { await disposeFixture(fixture); }
});

for (const nextCall of ['await_children', 'delegate'] as const) test(`an explicit ${nextCall} with no remaining call capacity proves ordinary Stop without a free registration or false child`, async () => {
  const f = await createChildRunFixture(`child-no-capacity-${nextCall}`, 1, { parentBudgets: { toolCalls: 7 } });
  try {
    Object.assign(f, await activateFixtureWorker(f, 'parent-consuming-await-call-floor', 30_000));
    await batch(f, [{ name: 'read', input: { path: 'a' } }]);
    const read = await prepareTool(f), claimed = await claimTool(f, read), observationRef = await observation(f, claimed, { text: 'original read result' });
    await f.agent.completeTool({ opId: read.entry.opId, attempt: read.entry.attempt, expectedRunRevision: read.run.revision, observationRef });
    await batch(f, [{ name: nextCall, input: nextCall === 'await_children' ? { childRunIds: [f.children[0]!.childRunId] } : offlineDelegateRequest('No additional child may be admitted') }]);
    const retirement = await f.agent.prepareTool({ expectedRunRevision: f.store.getRun(f.runId).revision, leaseEpoch: f.leaseEpoch });
    if (retirement.disposition !== 'retirement_required') throw new Error('control attempt must retire the original parent');
    await retireFixtureToolSelection(f, retirement);
    const before = await f.store.readRecoveryClosure(f.runId);
    assert.equal(before.run.budgetConsumed.toolCalls + before.run.budgetReserved.toolCalls, 7);
    if (nextCall === 'await_children') await assert.rejects(f.agent.waitForChildren({ expectedRunRevision: before.run.revision }), { code: 'BUDGET_EXHAUSTED' });
    else {
      let refusal: unknown;
      await assert.rejects(admitChildRun(f.driver, f.store.artifacts, f.owner, { runId: f.runId, expectedRunRevision: before.run.revision,
        releaseKeys: f.signed.releaseKeys }), error => { assert(isChildAdmissionRefused(error)); refusal = error; return true; });
      await assert.rejects(completeChildAdmissionRefusal(f.driver, f.store.artifacts, f.owner, refusal), { code: 'BUDGET_EXHAUSTED' });
    }
    assert.deepEqual(await f.store.readRecoveryClosure(f.runId), before);
    const stopped = await f.agent.stopForResourceFailure({ expectedRunRevision: before.run.revision }),
      intent = await f.store.artifacts.readCanonical<import('../runtime/stop.js').AgentStopIntent>(stopped.run.stopIntentRef!);
    if (intent.origin !== 'budget') throw new Error('only complete retained budget facts can stop this call');
    assert.equal(intent.counter, 'toolCalls'); assert.equal(intent.required, 1);
    const waiting = await f.agent.waitForStoppedChildren({ expectedRunRevision: stopped.run.revision }), child = await loadOfflineChild(f),
      revoked = await child.agent.stopFromParent({ expectedRunRevision: f.store.getRun(child.runId).revision });
    await child.agent.commitTerminalStop({ expectedRunRevision: revoked.run.revision });
    const settled = await f.agent.settleChildren({ expectedRunRevision: waiting.run.revision }), terminal = await f.agent.commitTerminalStop({ expectedRunRevision: settled.run.revision });
    assert.equal(terminal.run.status, 'failed'); assert.equal(terminal.run.terminalReason, 'budget_exhausted');
    const after = await f.store.readRecoveryClosure(f.runId);
    assert.deepEqual(after.journal, before.journal); assert.equal(after.childAllocations.length, 1);
    assert.equal(after.journal.filter(row => row.opKind === 'child_await').length, 0);
  } finally { await disposeFixture(f); }
});
