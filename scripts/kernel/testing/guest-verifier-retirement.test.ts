// Serialized association data only, not native death or an installed Run.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting } from '../../../src/kernel/identity.js';
import type { ProcessContainmentDeathEvidenceV1 } from '../../../src/kernel/execution.js';
import type { WorkspaceGenerationSnapshotEvidenceV1 } from '../../../src/kernel/types.js';
import { assertGuestVerifierParentRetirement, type GuestVerifierParentRetirement } from './guest-verifier-retirement.js';

function association() {
  const hash = 'a'.repeat(64), time = (ms: number) => new Date(Date.UTC(2026, 9, 19) + ms).toISOString();
  const initialDeath: ProcessContainmentDeathEvidenceV1 = {
    schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: hash, planRef: hash,
    sandboxLaunchSpecRef: hash, sandboxLaunchSpecDigest: hash,
    owner: { kind: 'worker_activation', runId: 'data-run', intendedLeaseEpoch: 2, workerLaunchId: 'data-worker' },
    launchNonceDigest: hash, inspectorSupervisorInstanceId: 'data-supervisor', inspectorIdentityRef: hash, inspectorIdentityDigest: hash,
    backend: { kind: 'linux', pidNamespaceReservationId: 'data-reservation', pidNamespaceId: 'data-namespace',
      cgroupPath: '/data/cgroup', cgroupId: 'data-cgroup', cgroupPopulated: 0, namespaceInitStartToken: 'data-init',
      namespaceInitDeadAndReaped: true, subreaperStartToken: 'data-subreaper', remainingTrackedDescendants: 0 },
    observedAt: time(0), evidenceDigest: ''
  };
  initialDeath.evidenceDigest = digestOmitting(initialDeath, 'evidenceDigest');
  const finalDeath = structuredClone(initialDeath); finalDeath.observedAt = time(200); finalDeath.evidenceDigest = '';
  finalDeath.evidenceDigest = digestOmitting(finalDeath, 'evidenceDigest');
  const snapshot: WorkspaceGenerationSnapshotEvidenceV1 = { schemaVersion: 1, format: 'cliq-workspace-generation-snapshot-evidence-v1',
    purpose: 'sealed_to_checkpoint', quiescenceEvidenceRef: canonicalSha256(initialDeath), runId: 'data-run', generationRef: hash,
    generationIdentityDigest: hash, checkpointId: 'data-checkpoint', workspaceStateRef: hash, workspaceStateDigest: hash,
    entriesRef: hash, treeDigest: hash, descriptorRewalkComplete: true, fileFsyncComplete: true, directoryFsyncComplete: true,
    observedAt: time(100), evidenceDigest: '' };
  snapshot.evidenceDigest = digestOmitting(snapshot, 'evidenceDigest');
  const retirement: GuestVerifierParentRetirement['retirement'] = { schemaVersion: 1, format: 'cliq-verifier-retirement-v1',
    runId: 'data-run', opId: 'data-op', attempt: 0, dispatchId: 'data-dispatch', leaseEpoch: 2, containmentRef: 'b'.repeat(64),
    deathEvidenceRef: 'c'.repeat(64), checkpointId: snapshot.checkpointId, workspaceStateRef: hash,
    snapshotEvidenceRef: canonicalSha256(snapshot), parentRetirementEvidenceRef: canonicalSha256(initialDeath),
    sourceAfterRef: hash, sourceAfterDigest: hash, evidenceDigest: '' };
  retirement.evidenceDigest = digestOmitting(retirement, 'evidenceDigest');
  return { initialDeath, finalDeath, snapshot, retirement,
    worker: { runId: 'data-run', launchId: 'data-worker', supervisorInstanceId: 'data-supervisor', leaseEpoch: 2,
      workspaceGenerationRef: hash, processContainmentRef: hash, retiredAt: time(300), retirementEvidenceRef: canonicalSha256(finalDeath),
      snapshotEvidenceRef: canonicalSha256(snapshot), snapshotEvidenceDigest: snapshot.evidenceDigest },
    checkpoint: { schemaVersion: 1, id: snapshot.checkpointId, runId: 'data-run', basedOnRunRevision: 4, runItemSeq: 2,
      contextManifestRef: hash, journalSeq: 3, workspaceStateRef: hash, createdAt: time(300), reason: 'auto' } } satisfies GuestVerifierParentRetirement;
}

test('guest verifier retains distinct D0 and final SQL D1 with the same complete death identity', () => {
  const value = association();
  assert.notEqual(value.retirement.parentRetirementEvidenceRef, value.worker.retirementEvidenceRef);
  assert.doesNotThrow(() => assertGuestVerifierParentRetirement(value));
});

function refreshRefs(value: ReturnType<typeof association>) {
  value.initialDeath.evidenceDigest = digestOmitting(value.initialDeath, 'evidenceDigest');
  value.finalDeath.evidenceDigest = digestOmitting(value.finalDeath, 'evidenceDigest');
  if (value.snapshot.purpose !== 'sealed_to_checkpoint') assert.fail('serialized fixture is sealed');
  value.snapshot.quiescenceEvidenceRef = canonicalSha256(value.initialDeath);
  value.snapshot.evidenceDigest = digestOmitting(value.snapshot, 'evidenceDigest');
  value.retirement.parentRetirementEvidenceRef = value.snapshot.quiescenceEvidenceRef;
  value.retirement.snapshotEvidenceRef = canonicalSha256(value.snapshot);
  value.retirement.evidenceDigest = digestOmitting(value.retirement, 'evidenceDigest');
  value.worker.snapshotEvidenceRef = canonicalSha256(value.snapshot);
  value.worker.snapshotEvidenceDigest = value.snapshot.evidenceDigest;
  value.worker.retirementEvidenceRef = canonicalSha256(value.finalDeath);
}

test('guest verifier association permits the same original observation and exactly five-second final freshness', () => {
  const value = association();
  value.finalDeath.observedAt = value.initialDeath.observedAt;
  value.snapshot.observedAt = value.initialDeath.observedAt;
  value.checkpoint.createdAt = new Date(Date.parse(value.finalDeath.observedAt) + 5_000).toISOString();
  value.worker.retiredAt = value.checkpoint.createdAt;
  refreshRefs(value);
  assert.equal(value.retirement.parentRetirementEvidenceRef, value.worker.retirementEvidenceRef);
  assert.doesNotThrow(() => assertGuestVerifierParentRetirement(value));
});

test('controlled stop preserves the verifier checkpoint association, not the later terminal Stop checkpoint', () => {
  const value = association();
  assert.notEqual(value.retirement.parentRetirementEvidenceRef, value.worker.retirementEvidenceRef);
  assert.doesNotThrow(() => assertGuestVerifierParentRetirement(value));
  const stopCheckpoint = { ...value.checkpoint, id: 'later-terminal-stop',
    basedOnRunRevision: value.checkpoint.basedOnRunRevision + 1,
    createdAt: new Date(Date.parse(value.checkpoint.createdAt) + 1).toISOString() };
  assert.throws(() => assertGuestVerifierParentRetirement({ ...value, checkpoint: stopCheckpoint }));
  assert.doesNotThrow(() => assertGuestVerifierParentRetirement(value), 'terminal Stop must not rewrite the original verifier association');
});

const changes: ReadonlyArray<readonly [string, (value: ReturnType<typeof association>) => void]> = [
  ['another final containment', value => { value.finalDeath.containmentRef = 'd'.repeat(64); }],
  ['another final worker', value => { value.finalDeath.owner = { kind: 'worker_activation', runId: 'data-run', intendedLeaseEpoch: 2, workerLaunchId: 'another-worker' }; }],
  ['another final inspector', value => { value.finalDeath.inspectorIdentityRef = 'd'.repeat(64); }],
  ['another final backend', value => { if (value.finalDeath.backend.kind !== 'linux') assert.fail(); value.finalDeath.backend.cgroupId = 'another-cgroup'; }],
  ['snapshot before original death', value => { value.snapshot.observedAt = new Date(Date.parse(value.initialDeath.observedAt) - 1).toISOString(); }],
  ['final death before snapshot', value => { value.finalDeath.observedAt = new Date(Date.parse(value.snapshot.observedAt) - 1).toISOString(); }],
  ['final death after commit', value => { value.finalDeath.observedAt = new Date(Date.parse(value.checkpoint.createdAt) + 1).toISOString(); }],
  ['expired final death', value => { value.checkpoint.createdAt = new Date(Date.parse(value.finalDeath.observedAt) + 5_001).toISOString(); value.worker.retiredAt = value.checkpoint.createdAt; }],
  ['another snapshot generation', value => { value.snapshot.generationRef = 'e'.repeat(64); }],
  ['another snapshot checkpoint', value => { value.snapshot.checkpointId = 'another-checkpoint'; }]
];
for (const [name, change] of changes) test(`guest verifier association rejects ${name} even with recomputed data hashes`, () => {
  const value = association(); change(value); refreshRefs(value);
  assert.throws(() => assertGuestVerifierParentRetirement(value));
});

test('guest verifier association binds every original CAS reference and semantic digest', () => {
  for (const change of [
    (value: ReturnType<typeof association>) => { value.worker.retirementEvidenceRef = 'd'.repeat(64); },
    (value: ReturnType<typeof association>) => { value.retirement.parentRetirementEvidenceRef = 'd'.repeat(64); },
    (value: ReturnType<typeof association>) => { value.worker.snapshotEvidenceRef = 'd'.repeat(64); },
    (value: ReturnType<typeof association>) => { value.worker.snapshotEvidenceDigest = 'd'.repeat(64); },
    (value: ReturnType<typeof association>) => { value.initialDeath.evidenceDigest = 'd'.repeat(64); },
    (value: ReturnType<typeof association>) => { value.finalDeath.evidenceDigest = 'd'.repeat(64); },
    (value: ReturnType<typeof association>) => { value.snapshot.evidenceDigest = 'd'.repeat(64); },
    (value: ReturnType<typeof association>) => { value.worker.retiredAt = value.initialDeath.observedAt; }
  ]) { const value = association(); change(value); assert.throws(() => assertGuestVerifierParentRetirement(value)); }
});
