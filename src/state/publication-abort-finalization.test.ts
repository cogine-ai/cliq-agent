// Refusal-only tests: no structural input establishes a stopped native task,
// original generation death, publication proof or terminal authority.
import assert from 'node:assert/strict';
import test from 'node:test';
import type { ArtifactCatalog } from './artifacts.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { closeOwnedPublicationAbortFinalization, prepareOwnedPublicationAbortFinalization,
  readOwnedPublicationAbortFinalization } from './publication-abort-finalization.js';
import { loadAgentStop } from './reducers/stop.js';
import { publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

test('abort finalization rejects forged execution/task/plan before SQL, CAS or caller getters', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('must not read SQL before original task brand'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('must not read CAS before original task brand'); } }) as ArtifactCatalog;
  const owner = {} as StateOwnerContext;
  const hostile = Object.defineProperty({}, 'runId', { get() { assert.fail('must not evaluate untrusted task getters'); } });
  await assert.rejects(prepareOwnedPublicationAbortFinalization(driver, artifacts, owner, {}, hostile as never), /genuine same-owner original task/);
  for (const token of [{}, hostile]) {
    assert.throws(() => readOwnedPublicationAbortFinalization(driver, owner, token as never, 'run'), /genuine original publication abort finalization/);
    assert.throws(() => closeOwnedPublicationAbortFinalization(driver, owner, token as never), /genuine original publication abort finalization/);
    const stop = loadAgentStop(driver, artifacts, owner, { run: { id: 'run' }, spec: {}, assembly: {}, principalId: 'principal',
      assertAuthority() { assert.fail('forged terminal plan must be checked before authority callback'); } } as never);
    await assert.rejects(stop.commitTerminalStop({ expectedRunRevision: 1 }, undefined, token as never), /genuine original publication abort finalization/);
  }
});

test('a genuine Agent terminal Stop cannot borrow a retained delivery projection ref or alter its Session outcome', async () => {
  const fixture = await createAgentFixture('abort-terminal-agent-no-projection', undefined, { mode: 'plan' });
  try {
    const cancelled = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    const proof = await quiescedToolCheckpoint(fixture, cancelled.checkpointId);
    await fixture.agent.commitTerminalStop({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, checkpoint: proof.checkpoint });
    const cut = await fixture.store.readRecoveryClosure(fixture.runId), session = fixture.store.getSession(cut.run.sessionId);
    const detail = await fixture.store.artifacts.readCanonical<Record<string, unknown>>(cut.run.terminalDetailRef!);
    // Real CAS bytes are merely data. They do not establish a delivery Run,
    // same native owner, root observation, claim or original retirement.
    const arbitrary = await fixture.store.artifacts.publishCanonical({ data: 'no publication authority' }, 'cliq-delivery-terminal-projection-evidence-v1');
    const substituted = await fixture.store.artifacts.publishCanonical({ ...detail,
      deliveryTerminalProjectionEvidenceRef: arbitrary.ref }, 'cliq-terminal-detail-v1');
    const driver = (fixture.store as unknown as { driver: SqliteDriver }).driver;
    try {
      driver.prepare('UPDATE runs SET terminal_detail_ref=? WHERE id=?').run(substituted.ref, fixture.runId);
      await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), /terminal stop lacks its exact original aborted publication projection/u);
    } finally { driver.prepare('UPDATE runs SET terminal_detail_ref=? WHERE id=?').run(cut.run.terminalDetailRef!, fixture.runId); }
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), cut);
    assert.deepEqual(fixture.store.getSession(cut.run.sessionId), session);
  } finally { await disposeFixture(fixture); }
});
