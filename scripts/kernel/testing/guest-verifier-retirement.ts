// Test-only association of already full-hash-read CAS and actual readonly SQL
// data. It creates no StateOwner, native death observation or seal authority.
import assert from 'node:assert/strict';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, parseCanonicalTime } from '../../../src/kernel/identity.js';
import type { ProcessContainmentDeathEvidenceV1 } from '../../../src/kernel/execution.js';
import type { Checkpoint, WorkspaceGenerationSnapshotEvidenceV1 } from '../../../src/kernel/types.js';
import type { VerifierRetirementV1 } from '../../../src/state/verifier-recovery.js';
import { validateMatchingWorkerDeath } from '../../../src/state/tool-checkpoint.js';
import type { InstalledWorkerRetirementInspection } from './installed-worker-lease.js';

export type GuestVerifierParentRetirement = Readonly<{
  worker: Pick<InstalledWorkerRetirementInspection, 'runId' | 'launchId' | 'supervisorInstanceId' | 'leaseEpoch' |
    'workspaceGenerationRef' | 'processContainmentRef' | 'retiredAt' | 'retirementEvidenceRef' | 'snapshotEvidenceRef' | 'snapshotEvidenceDigest'>;
  retirement: VerifierRetirementV1;
  snapshot: WorkspaceGenerationSnapshotEvidenceV1;
  initialDeath: ProcessContainmentDeathEvidenceV1;
  finalDeath: ProcessContainmentDeathEvidenceV1;
  checkpoint: Checkpoint;
}>;

export function assertGuestVerifierParentRetirement(input: GuestVerifierParentRetirement): void {
  const { worker, retirement, snapshot, initialDeath, finalDeath, checkpoint } = input;
  assert.equal(snapshot.purpose, 'sealed_to_checkpoint');
  if (snapshot.purpose !== 'sealed_to_checkpoint') assert.fail('verifier parent snapshot is not sealed');
  assert.equal(snapshot.evidenceDigest, digestOmitting(snapshot, 'evidenceDigest'));
  assert.equal(retirement.evidenceDigest, digestOmitting(retirement, 'evidenceDigest'));
  assert.equal(canonicalSha256(snapshot), worker.snapshotEvidenceRef);
  assert.equal(snapshot.evidenceDigest, worker.snapshotEvidenceDigest);
  assert.equal(retirement.snapshotEvidenceRef, worker.snapshotEvidenceRef);
  assert.equal(canonicalSha256(initialDeath), snapshot.quiescenceEvidenceRef);
  assert.equal(retirement.parentRetirementEvidenceRef, snapshot.quiescenceEvidenceRef);
  assert.equal(canonicalSha256(finalDeath), worker.retirementEvidenceRef);
  assert.equal(initialDeath.schemaVersion, 1); assert.equal(initialDeath.kind, 'containment_all_descendants_dead');
  assert.equal(initialDeath.evidenceDigest, digestOmitting(initialDeath, 'evidenceDigest'));
  assert.equal(initialDeath.containmentRef, worker.processContainmentRef);
  assert.deepEqual(initialDeath.owner, { kind: 'worker_activation', runId: worker.runId,
    intendedLeaseEpoch: worker.leaseEpoch, workerLaunchId: worker.launchId });
  assert.equal(initialDeath.inspectorSupervisorInstanceId, worker.supervisorInstanceId);
  validateMatchingWorkerDeath(initialDeath, finalDeath, 'guest verifier exact parent D0 and final SQL D1');
  assert.equal(snapshot.runId, worker.runId); assert.equal(retirement.runId, worker.runId); assert.equal(checkpoint.runId, worker.runId);
  assert.equal(snapshot.generationRef, worker.workspaceGenerationRef);
  assert.equal(retirement.leaseEpoch, worker.leaseEpoch);
  assert.equal(snapshot.checkpointId, checkpoint.id); assert.equal(retirement.checkpointId, checkpoint.id);
  assert.equal(snapshot.workspaceStateRef, checkpoint.workspaceStateRef); assert.equal(retirement.workspaceStateRef, checkpoint.workspaceStateRef);
  assert.equal(worker.retiredAt, checkpoint.createdAt);
  const d0 = parseCanonicalTime(initialDeath.observedAt), s = parseCanonicalTime(snapshot.observedAt),
    d1 = parseCanonicalTime(finalDeath.observedAt), c = parseCanonicalTime(checkpoint.createdAt);
  assert.ok(d0 <= s && s <= d1 && d1 <= c && c - d1 <= 5_000, 'guest verifier parent requires D0 <= S <= D1 <= C and current D1 at C');
}
