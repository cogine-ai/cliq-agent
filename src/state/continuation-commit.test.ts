// Real CAS bytes and SQLite writer mapping only. This bare database creates
// no StateOwner, admitted Run, native observation or publication permission.
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { PublicationPathProgressItem } from '../kernel/publication.js';
import type { ContextManifest, Run } from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { planContinuationCommit } from './continuation-commit.js';
import { readCheckpoint, ZERO_BUDGET } from './rows.js';
import { openSqliteDriver } from './sqlite-driver.js';

test('the continuation plan exposes the exact published context ref written into its real Checkpoint', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-continuation-plan-'));
  const root = path.join(home, 'objects'); await mkdir(root, { mode: 0o700 });
  const driver = openSqliteDriver(path.join(home, 'writer.sqlite'));
  try {
    driver.exec(`CREATE TABLE items (item_id TEXT, session_id TEXT, run_id TEXT, item_seq INTEGER, kind TEXT, payload_ref TEXT, created_at TEXT);
      CREATE TABLE checkpoints (id TEXT PRIMARY KEY, schema_version INTEGER, run_id TEXT, based_on_run_revision INTEGER,
        run_item_seq INTEGER, context_manifest_ref TEXT, journal_seq INTEGER, workspace_state_ref TEXT, created_at TEXT, reason TEXT);
      CREATE TABLE runs (id TEXT PRIMARY KEY, latest_checkpoint_id TEXT, frontier_ref TEXT, next_step TEXT);`);
    const ref = 'a'.repeat(64), at = '2026-10-19T00:00:00.000Z';
    const run: Run = { id: 'inert-data-run', sessionId: 'inert-session', specRef: ref, status: 'waiting', nextStep: 'delivery',
      frontierRef: ref, waitingReason: 'reconciliation', waitingOnRef: ref, revision: 7, leaseEpoch: 1,
      latestCheckpointId: 'inert-before', budgetReserved: ZERO_BUDGET, budgetConsumed: ZERO_BUDGET, repairCount: 0,
      cancelRequested: false, createdAt: at, updatedAt: at, deadlineAt: '2026-10-19T00:01:00.000Z' };
    driver.prepare('INSERT INTO runs VALUES (?,?,?,?)').run(run.id, run.latestCheckpointId, run.frontierRef!, run.nextStep);
    const context: ContextManifest = { schemaVersion: 1, format: 'cliq-context-manifest-v1', runId: run.id,
      throughItemSeq: 0, admittedContextRef: ref, assemblyRef: ref, segments: [], projectionDigest: '' };
    context.projectionDigest = digestOmitting(context, 'projectionDigest');
    const original = structuredClone(context), item: PublicationPathProgressItem = { schemaVersion: 1,
      kind: 'publication_path_progress', itemId: 'inert-progress', runId: run.id, deliveryPlanRef: ref,
      operationIndex: 0, operationId: 'inert-operation', opId: 'inert-op', attempt: 0,
      state: 'desired_committed_cleanup_pending', beforeObservationRef: ref, destinationEvidenceRef: ref, createdAt: at };
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
    const plan = planContinuationCommit(artifacts, { context, existingItems: [], items: [item],
      frontier: { schemaVersion: 1, kind: 'delivery', phase: 'merge', sourceRunResultRef: ref, capturedWorkspaceRef: ref },
      checkpointId: 'inert-after', workspaceStateRef: ref });
    assert.match(plan.contextManifestRef, /^[a-f0-9]{64}$/u);
    const published = await plan.publish();
    assert.equal(published.contextManifestRef, plan.contextManifestRef);
    const metadata = published.metadata.find(artifact => artifact.ref === plan.contextManifestRef);
    assert.ok(metadata);
    const actualContext = await artifacts.readCanonical<ContextManifest>(plan.contextManifestRef);
    assert.equal(canonicalSha256(actualContext), metadata.ref);
    assert.equal(actualContext.throughItemSeq, 1);
    assert.equal(actualContext.segments[0]!.kind, 'excluded_control');
    driver.transaction(connection => published.commit(connection, run, 3, at));
    assert.deepEqual(readCheckpoint(driver, 'inert-after'), { id: 'inert-after', schemaVersion: 1, runId: run.id,
      basedOnRunRevision: 7, runItemSeq: 1, contextManifestRef: plan.contextManifestRef, journalSeq: 3,
      workspaceStateRef: ref, createdAt: at, reason: 'auto' });
    assert.equal(driver.prepare('SELECT payload_ref FROM items').get<{ payload_ref: string }>()!.payload_ref, canonicalSha256(item));
    assert.deepEqual(context, original);
  } finally { driver.close(); await rm(home, { recursive: true, force: true }); }
});
