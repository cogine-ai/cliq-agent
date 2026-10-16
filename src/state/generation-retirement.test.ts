import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { digestOmitting } from '../kernel/identity.js';
import type { WorkspaceGenerationRetirementEvidenceV1, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { createQueuedFixture, digest, disposeFixture, prepareFixtureGeneration } from './testing/fixtures.js';

function withDb<T>(root: string, operation: (driver: SqliteDriver) => T): T {
  const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
  try { return operation(driver); } finally { driver.close(); }
}

test('recovery refuses current preparation quarantine edges without legitimizing offline data', async () => {
  // The genuine preparation producer commits quarantine and retirement in one
  // transaction. This existing offline corruption seam creates no native proof.
  const fixture = await createQueuedFixture('preparation-quarantine-corruption');
  let original: { phase: string; row_version: bigint; row_json: string } | undefined;
  let generationId: string | undefined;
  try {
    const prepared = await prepareFixtureGeneration(fixture, 'preparation-quarantine-corruption');
    generationId = prepared.generationId;
    const before = await fixture.store.readRecoveryClosure(fixture.runId), generation = before.workspaceGenerations[0]!;
    original = withDb(fixture.stateRoot, driver => driver.prepare('SELECT phase, row_version, row_json FROM workspace_generations WHERE generation_id = ?')
      .get<{ phase: string; row_version: bigint; row_json: string }>(generation.generationId)!);
    withDb(fixture.stateRoot, driver => driver.exec('DROP TRIGGER workspace_generations_validate_update'));
    const { phase: _phase, snapshotEvidenceRef: _snapshot, snapshotEvidenceDigest: _snapshotDigest, ...base } = generation;
    const candidates = [
      { reason: 'preparation_retired', observedState: { kind: 'unverified_preparation' } },
      { reason: 'preparation_retired', observedState: { kind: 'complete_tree', treeDigest: generation.lastVerifiedTreeDigest } },
      { reason: 'materialization_failed', observedState: { kind: 'unverified_preparation' } },
      { reason: 'preactivation_failed', observedState: { kind: 'unverified_preparation' } }
    ];
    for (const candidate of candidates) {
      const quarantine = { schemaVersion: 1, format: 'cliq-workspace-generation-quarantine-evidence-v1',
        runId: fixture.runId, generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
        sourceRowVersion: generation.rowVersion, fromPhase: 'preactivated_readonly', ...candidate,
        workerLaunchId: 'absent-preparation', preparationRetirementEvidenceRef: digest('absent-preparation-retirement'),
        preparationRetirementEvidenceDigest: digest('absent-preparation-retirement-digest'), evidenceDigest: '' };
      quarantine.evidenceDigest = digestOmitting(quarantine, 'evidenceDigest');
      const artifact = await fixture.store.artifacts.publishCanonical(quarantine, quarantine.format);
      const corrupted = { ...base, phase: 'quarantined', rowVersion: generation.rowVersion + 1,
        quarantineEvidenceRef: artifact.ref, quarantineEvidenceDigest: quarantine.evidenceDigest, observedState: candidate.observedState };
      const inspect = () => withDb(fixture.stateRoot, driver => driver.prepare('SELECT * FROM workspace_generations WHERE generation_id = ?')
        .get(generation.generationId));
      withDb(fixture.stateRoot, driver => driver.prepare("UPDATE workspace_generations SET phase = 'quarantined', row_version = ?, row_json = ? WHERE generation_id = ?")
        .run(BigInt(corrupted.rowVersion), JSON.stringify(corrupted), generation.generationId));
      const row = inspect();
      await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), error =>
        error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED', `${candidate.reason}/${candidate.observedState.kind}`);
      assert.deepEqual(inspect(), row, 'inspection cannot repair or legitimize a current preparation quarantine');
      assert.deepEqual(fixture.store.getRun(fixture.runId), before.run);
    }
    withDb(fixture.stateRoot, driver => driver.prepare('UPDATE workspace_generations SET phase = ?, row_version = ?, row_json = ? WHERE generation_id = ?')
      .run(original!.phase, original!.row_version, original!.row_json, generation.generationId));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally {
    if (original && generationId) withDb(fixture.stateRoot, driver => driver.prepare('UPDATE workspace_generations SET phase = ?, row_version = ?, row_json = ? WHERE generation_id = ?')
      .run(original!.phase, original!.row_version, original!.row_json, generationId!));
    await disposeFixture(fixture);
  }
});

test('recovery inspects retired rows and refuses missing, malformed or nonzero retirement evidence without mutation', async () => {
  // This corrupts retained offline data through the existing Store fixture.
  // It creates no physical receipt and qualifies no native retirement path.
  const fixture = await createAgentFixture('retired-generation-corruption');
  let original: { phase: string; row_version: bigint; row_json: string } | undefined;
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId), generation = before.workspaceGenerations[0]!;
    original = withDb(fixture.stateRoot, driver => driver.prepare('SELECT phase, row_version, row_json FROM workspace_generations WHERE generation_id = ?')
      .get<{ phase: string; row_version: bigint; row_json: string }>(generation.generationId)!);
    withDb(fixture.stateRoot, driver => driver.exec('DROP TRIGGER workspace_generations_validate_update'));
    const evidence: WorkspaceGenerationRetirementEvidenceV1 = {
      schemaVersion: 1, format: 'cliq-workspace-generation-retirement-evidence-v1', runId: fixture.runId,
      generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
      inspectorIdentityRef: digest('not-a-native-inspector'), inspectorIdentityDigest: digest('not-an-inspector-digest'),
      observedAt: generation.updatedAt, evidenceDigest: '', fromPhase: 'quarantined',
      quarantineEvidenceRef: digest('not-a-native-quarantine'), quarantineEvidenceDigest: digest('not-a-quarantine-digest'),
      sourceQuarantinedRowVersion: generation.rowVersion, activeRunPointerCount: 0, nonretiredWorkerLaunchCount: 0,
      liveContainmentCount: 0, activeMountCount: 0, releasableBrokerClaimCount: 0
    };
    evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');
    const missing = { ref: digest('absent-retirement-proof'), evidenceDigest: evidence.evidenceDigest };
    const candidates: Array<{ ref: string; evidenceDigest: string }> = [missing];
    for (const invalid of [{ ...evidence, extraAuthority: true }, { ...evidence, liveContainmentCount: 1 }]) {
      invalid.evidenceDigest = digestOmitting(invalid, 'evidenceDigest');
      const artifact = await fixture.store.artifacts.publishCanonical(invalid, evidence.format);
      candidates.push({ ref: artifact.ref, evidenceDigest: invalid.evidenceDigest });
    }
    for (const candidate of candidates) {
      const retired: Extract<WorkspaceGenerationStateV1, { phase: 'retired' }> = {
        schemaVersion: 1, generationId: generation.generationId, runId: fixture.runId,
        generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
        rowVersion: generation.rowVersion + 1, sourceCheckpointId: generation.sourceCheckpointId,
        sourceWorkspaceStateRef: generation.sourceWorkspaceStateRef, sourceWorkspaceStateDigest: generation.sourceWorkspaceStateDigest,
        lastVerifiedTreeDigest: generation.lastVerifiedTreeDigest, updatedAt: generation.updatedAt, phase: 'retired',
        retirementEvidenceRef: candidate.ref, retirementEvidenceDigest: candidate.evidenceDigest
      };
      const inspect = () => withDb(fixture.stateRoot, driver => driver.prepare('SELECT * FROM workspace_generations WHERE generation_id = ?')
        .get(generation.generationId));
      withDb(fixture.stateRoot, driver => driver.prepare("UPDATE workspace_generations SET phase = 'retired', row_version = ?, row_json = ? WHERE generation_id = ?")
        .run(BigInt(retired.rowVersion), JSON.stringify(retired), generation.generationId));
      const corrupted = inspect();
      await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), error =>
        error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
      assert.deepEqual(inspect(), corrupted, 'inspection must not repair, delete or legitimize corrupt evidence');
      assert.deepEqual(fixture.store.getRun(fixture.runId), before.run);
    }
    withDb(fixture.stateRoot, driver => driver.prepare('UPDATE workspace_generations SET phase = ?, row_version = ?, row_json = ? WHERE generation_id = ?')
      .run(original!.phase, original!.row_version, original!.row_json, generation.generationId));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally {
    if (original) withDb(fixture.stateRoot, driver => driver.prepare('UPDATE workspace_generations SET phase = ?, row_version = ?, row_json = ? WHERE generation_id = ?')
      .run(original!.phase, original!.row_version, original!.row_json, fixture.generationId));
    await disposeFixture(fixture);
  }
});
