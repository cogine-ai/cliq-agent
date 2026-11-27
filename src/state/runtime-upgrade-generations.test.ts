import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ProcessContainmentDeathEvidenceV1 } from '../kernel/execution.js';
import type { RunSpec } from '../kernel/types.js';
import { readWorkspaceGeneration } from './repositories/workspace-generations.js';
import { assertClosedUpgradeGeneration } from './runtime-upgrade-generations.js';
import { readRuntimeUpgradeRetiredRows } from './runtime-upgrade-history.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { admissionKey, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

async function sealedFixture(label: string) {
  // Existing offline seal fixtures over real SQLite/CAS. No actual worker,
  // native death, installation or upgrade qualification is created here.
  const fixture = await createAgentFixture(label, undefined, { mode: 'accept-edits' });
  try {
    const proof = await quiescedToolCheckpoint(fixture, `${label}-checkpoint`);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const generation = before.workspaceGenerations.find(row => row.generationRef === fixture.generationRef)!;
    if (generation.phase !== 'checkpointing') assert.fail('fixture must own its checkpointing generation');
    const sealed = await fixture.store.sealWorkerGeneration({ launchId: fixture.launchId,
      expectedRunRevision: before.run.revision, expectedGenerationRowVersion: generation.rowVersion,
      quiesceId: generation.quiesceId, checkpointId: proof.snapshot.checkpointId,
      contextManifestRef: before.latestCheckpoint.contextManifestRef, workspaceStateRef: proof.workspaceStateRef,
      snapshotEvidenceRef: proof.checkpoint.snapshotEvidenceRef, snapshotEvidenceDigest: proof.snapshot.evidenceDigest,
      retirementEvidenceRef: proof.checkpoint.retirementEvidenceRef, checkpointReason: 'auto' });
    return { fixture, sealed };
  } catch (error) { await disposeFixture(fixture); throw error; }
}

async function terminal(fixture: Awaited<ReturnType<typeof createAgentFixture>>) {
  await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
    expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
  const stopped = await fixture.agent.commitTerminalStop({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
  assert.equal(stopped.run.status, 'cancelled');
  return stopped.run;
}

test('upgrade accepts an original dormant seal only after terminal quiescence and leaves its row unchanged', async () => {
  const { fixture, sealed } = await sealedFixture('upgrade-dormant-seal');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await assert.rejects(assertClosedUpgradeGeneration(driver, fixture.store.artifacts,
      fixture.store.getRun(fixture.runId), sealed.generation, new Map([[sealed.launch.launchId, sealed.launch]])), { code: 'RECOVERY_REQUIRED' });
    const run = await terminal(fixture);
    const before = readWorkspaceGeneration(driver, sealed.generation.generationId);
    await assertClosedUpgradeGeneration(driver, fixture.store.artifacts, run, sealed.generation, new Map([[sealed.launch.launchId, sealed.launch]]));
    assert.equal(before!.phase, 'sealed');
    assert.deepEqual(readWorkspaceGeneration(driver, sealed.generation.generationId), before);
    await assert.rejects(assertClosedUpgradeGeneration(driver, fixture.store.artifacts, run, sealed.generation, new Map()),
      { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(assertClosedUpgradeGeneration(driver, fixture.store.artifacts, run,
      { ...sealed.generation, phase: 'preactivated_readonly' } as typeof sealed.generation, new Map([[sealed.launch.launchId, sealed.launch]])));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('retained upgrade reads bind the same complete original worker row and never normalize a seal to retired', async () => {
  const { fixture, sealed } = await sealedFixture('upgrade-retained-seal');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const run = await terminal(fixture);
    const [runObject, launchObject, generationObject] = await Promise.all([run, sealed.launch, sealed.generation]
      .map(row => fixture.store.artifacts.publishCanonical(row, 'cliq-retained-upgrade-resource-row-v1')));
    const refs = { run_terminal: [runObject!.ref], worker_launch: [launchObject!.ref],
      workspace_generation: [generationObject!.ref], source_inspection: [] };
    await readRuntimeUpgradeRetiredRows(driver, fixture.store.artifacts, refs);
    await assert.rejects(readRuntimeUpgradeRetiredRows(driver, fixture.store.artifacts,
      { ...refs, worker_launch: [] }), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(readRuntimeUpgradeRetiredRows(driver, fixture.store.artifacts,
      { ...refs, worker_launch: [launchObject!.ref, launchObject!.ref] }), { code: 'RECOVERY_REQUIRED' });
    // A retained source is historical. A later real owner and a new queued
    // Run must not make the old resource graph equal today's whole database.
    // This is an owner/row regression, not a simulated schema upgrade.
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    const identity = await publishInProcessChannel(fixture.store);
    const spec = await fixture.store.artifacts.readCanonical<RunSpec>(run.specRef);
    const projection = await fixture.store.artifacts.readCanonical<{ frozenIgnoreRulesRef: string }>(spec.sourceProjectionRef);
    const later = await fixture.store.admitRun({ ...identity, requestId: uuidv7(), admissionKey: admissionKey('upgrade-later-run'),
      sessionId: run.sessionId, expectedContextRevision: fixture.store.getSession(run.sessionId).contextRevision,
      workspacePath: fixture.workspace, objective: 'Later work cannot invalidate the retained original source.', allowUnverified: true,
      assemblyRef: spec.assemblyRef, policyRef: spec.policyRef, sandboxProfileRef: spec.sandboxProfileRef,
      verifierSpecRef: spec.verifierSpecRef, sourceProjectionRef: spec.sourceProjectionRef,
      baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef, frozenIgnoreRulesRef: projection.frozenIgnoreRulesRef,
      credentialGrantRefs: spec.credentialGrantRefs, budgets: spec.budgets });
    assert.equal(later.run.status, 'queued');
    assert.notEqual(later.run.id, run.id);
    await readRuntimeUpgradeRetiredRows(driver, fixture.store.artifacts, refs);
    assert.deepEqual(readWorkspaceGeneration(driver, sealed.generation.generationId), sealed.generation);
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('a rehashed foreign death cannot close an otherwise exact dormant sealed upgrade source', async () => {
  const { fixture, sealed } = await sealedFixture('upgrade-substituted-seal');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  const guards = driver.prepare("SELECT name, sql FROM sqlite_master WHERE type='trigger' AND tbl_name='worker_launches' AND sql LIKE '%BEFORE UPDATE%'")
    .all<{ name: string; sql: string }>();
  let dropped = false;
  try {
    const run = await terminal(fixture);
    const death = await fixture.store.artifacts.readCanonical<ProcessContainmentDeathEvidenceV1>(sealed.launch.retirementEvidenceRef!);
    const foreign = { ...death, launchNonceDigest: 'a'.repeat(64), evidenceDigest: '' };
    foreign.evidenceDigest = digestOmitting(foreign, 'evidenceDigest');
    const artifact = await fixture.store.artifacts.publishCanonical(foreign, 'cliq-process-containment-death-evidence-v1');
    const substituted = { ...sealed.launch, retirementEvidenceRef: artifact.ref };
    // Deliberate offline storage corruption, matching the existing seal-history
    // regression. The production reader must reject rather than repair it.
    for (const guard of guards) driver.exec(`DROP TRIGGER "${guard.name.replaceAll('"', '""')}"`);
    dropped = true;
    driver.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?')
      .run(JSON.stringify(substituted), sealed.launch.launchId);
    await assert.rejects(assertClosedUpgradeGeneration(driver, fixture.store.artifacts, run, sealed.generation,
      new Map([[substituted.launchId, substituted]])));
  } finally {
    if (dropped) {
      driver.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?')
        .run(JSON.stringify(sealed.launch), sealed.launch.launchId);
      for (const guard of guards) driver.exec(guard.sql);
    }
    driver.close(); await disposeFixture(fixture);
  }
});
