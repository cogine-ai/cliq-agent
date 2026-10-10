import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { sha256Bytes } from '../kernel/identity.js';
import type { ContinuationItem, SessionContextProjection, SessionRunTerminalItem, TerminalDetail } from '../kernel/types.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { admissionKey, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { batch, prepareTool } from './testing/tool-calls.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

test('terminal stop retains prepared refund and cancellation times while its delayed publication commits and reopens at the actual seal time', async t => {
  const preparedTime = Date.now();
  let clock = preparedTime;
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('stop-delayed-terminal-publication', undefined, { mode: 'plan' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }, { name: 'read', input: { path: 'b' } }]);
    await prepareTool(fixture);
    const cancelled = await fixture.agent.cancelRun({ requestId: uuidv7(),
      expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      ...await publishInProcessChannel(fixture.store) });
    const proof = await quiescedToolCheckpoint(fixture, cancelled.checkpointId);
    const sessionBefore = fixture.store.getSession(cancelled.run.sessionId);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, cancelled.run.specRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const originalWriteFile = prototype.writeFile;
    await sample.close();
    let delayed = 0;
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(originalWriteFile, this, args);
      if (!Buffer.isBuffer(args[0]) || !args[0].toString('utf8').includes('"format":"cliq-session-context-v1"')) return;
      const projection = JSON.parse(args[0].toString('utf8')) as SessionContextProjection;
      if (projection.sessionId === sessionBefore.id && projection.throughItemSeq === sessionBefore.latestItemSeq + 1) {
        delayed += 1;
        clock += 1_000;
      }
    });
    // Offline proof covers StateStore atomicity and historical replay only;
    // delaying a real CAS write does not qualify native process retirement.
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: cancelled.run.revision, checkpoint: proof.checkpoint });
    writer.mock.restore();
    assert.equal(delayed, 1, 'the real prepared Session projection is published exactly once');
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    const committedAt = new Date(preparedTime + 1_000).toISOString();
    const stagedAt = new Date(preparedTime).toISOString();
    assert.equal(closure.latestCheckpoint.createdAt, committedAt);
    assert.equal(terminal.run.updatedAt, committedAt);
    const retainedLaunches = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try { assert.equal(readRequiredWorkerLaunch(retainedLaunches, fixture.launchId).retiredAt, committedAt); }
    finally { retainedLaunches.close(); }
    const detail = await fixture.store.artifacts.readCanonical<TerminalDetail>(terminal.run.terminalDetailRef!);
    assert.equal(detail.createdAt, stagedAt);
    const refunded = closure.journal.filter(entry => entry.errorRef === cancelled.run.stopIntentRef);
    assert.equal(refunded.length, 1);
    assert.equal(refunded[0]!.phase, 'failed');
    assert.equal(refunded[0]!.timestamp, stagedAt);
    const items = await Promise.all(closure.items.map(row => fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef)));
    assert.deepEqual(items.filter(item => item.kind === 'tool_result').map(item => [item.outcome, item.createdAt]),
      [['cancelled', stagedAt], ['cancelled', stagedAt]]);
    assert.deepEqual(terminal.run.budgetReserved, { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 });
    assert.equal(terminal.run.budgetConsumed.toolCalls, 0);
    const identity = await publishInProcessChannel(fixture.store);
    const events = await fixture.store.readControl({ protocolVersion: 1, method: 'run.attach', runId: fixture.runId, afterEventSeq: 0 }, identity);
    assert.ok(events.method === 'run.attach');
    assert.equal(events.events.at(-1)!.occurredAt, committedAt);
    const session = fixture.store.getSession(sessionBefore.id);
    assert.equal(session.updatedAt, committedAt);
    assert.equal(session.latestItemSeq, sessionBefore.latestItemSeq + 1);
    const sessionItems = await fixture.store.readControl({ protocolVersion: 1, method: 'session.get', sessionId: session.id }, identity);
    assert.ok(sessionItems.method === 'session.get');
    assert.equal(sessionItems.items.at(-1)!.createdAt, committedAt);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), closure);
    assert.deepEqual(fixture.store.getSession(session.id), session);
  } finally { t.mock.restoreAll(); await disposeFixture(fixture); }
});

test('a sealed stop refuses a changed Session cut without rebuilding, then a new public stop appends its outcome once', async t => {
  const clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('stop-sealed-session-cas', undefined, { mode: 'plan' });
  let release: (() => void) | undefined;
  let first: ReturnType<typeof fixture.agent.commitTerminalStop> | undefined;
  try {
    const { run, runSpec: spec } = await fixture.store.readRecoveryClosure(fixture.runId);
    const source = await fixture.store.artifacts.readCanonical<{ frozenIgnoreRulesRef: string }>(spec.sourceProjectionRef);
    const second = await fixture.store.admitRun({ requestId: uuidv7(), admissionKey: admissionKey('stop-sealed-session-peer'),
      sessionId: run.sessionId, expectedContextRevision: 1, workspacePath: fixture.workspace, objective: 'worker-free stopped root', allowUnverified: true,
      assemblyRef: spec.assemblyRef, policyRef: spec.policyRef, sandboxProfileRef: spec.sandboxProfileRef, verifierSpecRef: spec.verifierSpecRef,
      sourceProjectionRef: spec.sourceProjectionRef, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef,
      frozenIgnoreRulesRef: source.frozenIgnoreRulesRef, credentialGrantRefs: spec.credentialGrantRefs, budgets: spec.budgets,
      ...await publishInProcessChannel(fixture.store) });
    const peer = await fixture.store.loadAgentRun({ runId: second.run.id, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }, { name: 'read', input: { path: 'b' } }]);
    await prepareTool(fixture);
    const firstStop = await fixture.agent.cancelRun({ requestId: uuidv7(), expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      ...await publishInProcessChannel(fixture.store) });
    const secondStop = await peer.cancelRun({ requestId: uuidv7(), expectedRunRevision: second.run.revision,
      ...await publishInProcessChannel(fixture.store) });
    const proof = await quiescedToolCheckpoint(fixture, firstStop.checkpointId);
    const firstBefore = await fixture.store.readRecoveryClosure(fixture.runId);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, run.specRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const originalWriteFile = prototype.writeFile;
    await sample.close();
    let reached!: () => void;
    const blocked = new Promise<void>(resolve => { reached = resolve; });
    const resume = new Promise<void>(resolve => { release = resolve; });
    let firstTerminalRef: string | undefined, preparedProjections = 0;
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(originalWriteFile, this, args);
      if (!Buffer.isBuffer(args[0])) return;
      const bytes = args[0], text = bytes.toString('utf8');
      if (text.includes('"format":"cliq-session-run-terminal-v1"')) {
        const item = JSON.parse(text) as SessionRunTerminalItem;
        if (item.runId === fixture.runId) firstTerminalRef = sha256Bytes(bytes);
      } else if (text.includes('"format":"cliq-session-context-v1"')) {
        const projection = JSON.parse(text) as SessionContextProjection;
        if (projection.sessionId === run.sessionId && projection.segments.some(segment => segment.kind === 'raw' &&
            segment.items.some(item => item.payloadRef === firstTerminalRef))) {
          preparedProjections++;
          if (preparedProjections === 1) { reached(); await resume; }
        }
      }
    });
    const command = { expectedRunRevision: firstStop.run.revision, checkpoint: proof.checkpoint };
    first = fixture.agent.commitTerminalStop(command);
    await Promise.race([blocked, first.then(() => assert.fail('first stop finished before its actual projection-write barrier'),
      error => { throw error; })]);
    const winner = await peer.commitTerminalStop({ expectedRunRevision: secondStop.run.revision });
    assert.equal(winner.run.status, 'cancelled');
    const winnerCut = await fixture.store.readRecoveryClosure(second.run.id);
    const winnerSession = fixture.store.getSession(run.sessionId);
    assert.equal(winnerSession.latestItemSeq, 1);
    release!();
    release = undefined;
    await assert.rejects(first, { code: 'REVISION_CONFLICT' });
    writer.mock.restore();
    assert.equal(preparedProjections, 1, 'a lost sealed Session cut cannot automatically rebuild its bulk completion');
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), firstBefore,
      'refusal preserves the winning StopIntent, permanent Journal, budgets, ready Checkpoint and unretired generation');
    assert.deepEqual(await fixture.store.readRecoveryClosure(second.run.id), winnerCut);
    assert.deepEqual(fixture.store.getSession(run.sessionId), winnerSession);
    // This is a new explicit public preparation, not a replay of an effect or
    // an implicit retry inside the failed prepared completion.
    const retried = await fixture.agent.commitTerminalStop({ ...command, expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    assert.equal(retried.run.status, 'cancelled');
    assert.equal(retried.run.stopIntentRef, firstStop.run.stopIntentRef);
    assert.equal(retried.run.budgetConsumed.toolCalls, 0);
    const completedCut = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(completedCut.journal.filter(entry => entry.errorRef === firstStop.run.stopIntentRef).length, 1);
    assert.equal(completedCut.journal.filter(entry => entry.phase === 'dispatch_claimed' && entry.opKind === 'tool').length, 0);
    const session = fixture.store.getSession(run.sessionId);
    assert.equal(session.latestItemSeq, 2);
    assert.equal(session.contextRevision, 3);
    const projection = await fixture.store.artifacts.readCanonical<SessionContextProjection>(session.contextProjectionRef);
    assert.deepEqual(projection.segments.map(segment => [segment.kind, segment.fromItemSeq, segment.throughItemSeq]), [['raw', 1, 1], ['raw', 2, 2]]);
    const terminalItems = await Promise.all(projection.segments.map(segment => {
      assert.ok(segment.kind === 'raw');
      return fixture.store.artifacts.readCanonical<SessionRunTerminalItem>(segment.items[0]!.payloadRef);
    }));
    assert.deepEqual(terminalItems.map(item => item.runId), [second.run.id, fixture.runId]);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), completedCut);
    assert.deepEqual(await fixture.store.readRecoveryClosure(second.run.id), winnerCut);
    assert.deepEqual(fixture.store.getSession(run.sessionId), session);
  } finally {
    release?.();
    await first?.catch(() => {});
    t.mock.restoreAll();
    await disposeFixture(fixture);
  }
});
