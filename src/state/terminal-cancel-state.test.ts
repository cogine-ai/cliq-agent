import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { RunCancel, TerminalDetail } from '../kernel/types.js';
import { RunTerminalError } from './errors.js';
import { loadAgentStop } from './reducers/stop.js';
import { readTerminalRunMaterial } from './run-authority.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

// Existing genuine local Store/owner and offline signed fixture only. These
// tests do not claim an installed Linux journey or the five-second bound.
async function terminalFixture(label: string) {
  const fixture = await createAgentFixture(label, undefined, { mode: 'plan' });
  try {
    const command: RunCancel = { requestId: uuidv7(), expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      ...await publishInProcessChannel(fixture.store) };
    const stopped = await fixture.agent.cancelRun(command);
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      checkpoint: proof.checkpoint });
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const material = await readTerminalRunMaterial(held.driver, fixture.store.artifacts, held.owner,
      { runId: fixture.runId, operation: 'agent', releaseKeys: fixture.signed!.releaseKeys });
    const stop = loadAgentStop(held.driver, fixture.store.artifacts, held.owner, material.controlAuthority);
    return { fixture, command, stopped, terminal, held, material, stop };
  } catch (error) { await disposeFixture(fixture); throw error; }
}

test('terminal-only cancellation preserves replay and conflict precedence without changing Run or Session', async () => {
  const { fixture, command, stopped, terminal, held, material, stop } = await terminalFixture('terminal-reader-precedence');
  try {
    const channel = await publishInProcessChannel(fixture.store);
    const before = await fixture.store.readRecoveryClosure(fixture.runId), session = fixture.store.getSession(terminal.run.sessionId);
    const changes = held.driver.prepare('SELECT total_changes() AS changes').get();
    const replay = await stop.cancelTerminalRun({ ...command, ...channel }, material.session);
    assert.equal(replay.replayed, true); assert.deepEqual(replay.response, stopped.response);
    await assert.rejects(stop.cancelTerminalRun({ ...command, ...channel, expectedRunRevision: terminal.run.revision }, material.session),
      { code: 'REQUEST_ID_CONFLICT' });
    await assert.rejects(stop.cancelTerminalRun({ ...channel, requestId: uuidv7(), expectedRunRevision: terminal.run.revision - 1 }, material.session),
      { code: 'REVISION_CONFLICT' });
    await assert.rejects(stop.cancelTerminalRun({ ...channel, requestId: uuidv7(), expectedRunRevision: terminal.run.revision }, material.session),
      error => error instanceof RunTerminalError && error.code === 'STATE_TRANSITION_INVALID');
    assert.deepEqual(held.driver.prepare('SELECT total_changes() AS changes').get(), changes);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    assert.deepEqual(fixture.store.getSession(session.id), session);
  } finally { await disposeFixture(fixture); }
});

test('terminal-only replay and refusal require full fresh recovery after closed material was loaded', async () => {
  const { fixture, command, terminal, material, stop } = await terminalFixture('terminal-reader-corrupt-history');
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const channel = await publishInProcessChannel(fixture.store);
    const detail = await fixture.store.artifacts.readCanonical<TerminalDetail>(terminal.run.terminalDetailRef!);
    const bad = await fixture.store.artifacts.publishCanonical({ ...detail,
      reasonDetail: { kind: 'budget_exhausted', stopIntentRef: terminal.run.stopIntentRef } }, 'cliq-terminal-detail-v1');
    writer.prepare('UPDATE runs SET terminal_detail_ref=? WHERE id=?').run(bad.ref, fixture.runId);
    for (const request of [
      { ...command, ...channel },
      { ...command, ...channel, expectedRunRevision: terminal.run.revision },
      { ...channel, requestId: uuidv7(), expectedRunRevision: terminal.run.revision - 1 },
      { ...channel, requestId: uuidv7(), expectedRunRevision: terminal.run.revision }
    ]) await assert.rejects(stop.cancelTerminalRun(request, material.session), { code: 'RECOVERY_REQUIRED' });
    writer.prepare('UPDATE runs SET terminal_detail_ref=? WHERE id=?').run(terminal.run.terminalDetailRef!, fixture.runId);
    assert.equal((await stop.cancelTerminalRun({ ...command, ...channel }, material.session)).replayed, true);
  } finally {
    writer.prepare('UPDATE runs SET terminal_detail_ref=? WHERE id=?').run(terminal.run.terminalDetailRef!, fixture.runId);
    writer.close(); await disposeFixture(fixture);
  }
});

for (const drift of ['session', 'replay_row'] as const) test(`terminal replay detects ${drift} drift during its last authenticated channel read`, async () => {
  const { fixture, command, terminal, material, stop } = await terminalFixture('terminal-reader-drift-' + drift);
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  const read = fixture.store.artifacts.readBytes;
  const session = fixture.store.getSession(terminal.run.sessionId);
  const originalDigest = writer.prepare("SELECT request_digest FROM control_requests WHERE method='run.cancel' AND request_id=?")
    .get<{ request_digest: string }>(command.requestId)!.request_digest;
  try {
    const channel = await publishInProcessChannel(fixture.store);
    assert.notEqual(channel.channelIdentityRef, command.channelIdentityRef);
    let reads = 0, changed = false;
    fixture.store.artifacts.readBytes = async function(reference) {
      const bytes = await read.call(this, reference);
      // Each complete channel check reads its decoded identity and descriptor.
      // The sixth read is the last check after the original replay response.
      if (reference === channel.channelIdentityRef && ++reads === 6) {
        changed = true;
        if (drift === 'session') writer.prepare('UPDATE sessions SET name=? WHERE id=?').run((session.name ?? '') + ' changed', session.id);
        else writer.prepare("UPDATE control_requests SET request_digest=? WHERE method='run.cancel' AND request_id=?")
          .run(canonicalSha256({ changed: true }), command.requestId);
      }
      return bytes;
    };
    await assert.rejects(stop.cancelTerminalRun({ ...command, ...channel }, material.session), { code: 'REVISION_CONFLICT' });
    assert.equal(changed, true, 'the original replay must finish before the observed final channel drift');
    assert.equal(reads, 6);
  } finally {
    fixture.store.artifacts.readBytes = read;
    writer.prepare('UPDATE sessions SET name=? WHERE id=?').run(session.name ?? null, session.id);
    writer.prepare("UPDATE control_requests SET request_digest=? WHERE method='run.cancel' AND request_id=?")
      .run(originalDigest, command.requestId);
    writer.close(); await disposeFixture(fixture);
  }
});

test('closed terminal material refuses a live Run without changing its state', async () => {
  const fixture = await createAgentFixture('terminal-material-live-refused', undefined, { mode: 'plan' });
  try {
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(readTerminalRunMaterial(held.driver, fixture.store.artifacts, held.owner,
      { runId: fixture.runId, operation: 'agent', releaseKeys: fixture.signed!.releaseKeys }), { code: 'REVISION_CONFLICT' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
