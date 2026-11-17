import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { BoundWorkerLaunch, Run } from '../kernel/types.js';
import { beginPublicationLeaseReads, projectRecordedPublicationLeases, validatePublicationLeaseRenewal } from './publication-lease-read.js';

// Plain comparison data only. These snapshots create no worker, lease,
// StateOwner, execution permission or native observation.
const initial = { launchId: 'inert-launch', runId: 'inert-run', phase: 'activated', generationWriteState: 'active',
  leaseEpoch: 1, leaseVersion: 1, leaseExpiresAt: '2026-11-17T00:01:00.000Z', workerIdentityDigest: 'a'.repeat(64) } as BoundWorkerLaunch;
const run = { id: initial.runId, status: 'running', activeWorkerLaunchId: initial.launchId, leaseEpoch: 1,
  cancelRequested: false, deadlineAt: '2026-11-17T01:00:00.000Z' } as Run;

test('long publication reads recognize only complete recorded renewals and leave their snapshots immutable', () => {
  const second = { ...initial, leaseVersion: 2, leaseExpiresAt: '2026-11-17T00:01:30.000Z' };
  const latest = { ...initial, leaseVersion: 3, leaseExpiresAt: '2026-11-17T00:02:00.000Z' };
  validatePublicationLeaseRenewal(initial, second, run); validatePublicationLeaseRenewal(second, latest, run);
  const rows = new Map([initial, second, latest].map(row => [row.leaseVersion, canonicalSha256(row)]));
  const history = { initial, latest, rows }, oldCut = [Object.freeze({ ...second })];
  assert.deepEqual(projectRecordedPublicationLeases(history, latest, oldCut), [initial]);
  assert.equal(oldCut[0]!.leaseVersion, 2); assert.equal(oldCut[0]!.leaseExpiresAt, second.leaseExpiresAt);
  assert.throws(() => projectRecordedPublicationLeases(history, second, oldCut));
  assert.throws(() => projectRecordedPublicationLeases(history, { ...latest, leaseVersion: 4 }, oldCut));
  assert.throws(() => projectRecordedPublicationLeases(history, latest, [{ ...second, workerIdentityDigest: 'b'.repeat(64) }]));
  assert.throws(() => projectRecordedPublicationLeases(history, latest, [{ ...second, leaseVersion: 4 }]));
  const revoked = { ...latest, generationWriteState: 'revoking' as const };
  const revokedCut = [revoked];
  assert.equal(projectRecordedPublicationLeases(history, revoked, revokedCut), revokedCut);
  assert.equal(projectRecordedPublicationLeases(history, revoked, oldCut), oldCut);
});

test('recording cannot change worker identity, skip versions, extend the Run or survive Stop', () => {
  const next = { ...initial, leaseVersion: 2, leaseExpiresAt: '2026-11-17T00:01:30.000Z' };
  for (const changed of [{ workerIdentityDigest: 'b'.repeat(64) }, { generationWriteState: 'revoking' as const },
    { leaseEpoch: 2 }, { leaseVersion: 3 }, { leaseExpiresAt: initial.leaseExpiresAt },
    { leaseExpiresAt: '2026-11-17T01:00:00.001Z' }])
    assert.throws(() => validatePublicationLeaseRenewal(initial, { ...next, ...changed }, run));
  for (const changed of [{ cancelRequested: true }, { stopIntentRef: 'a'.repeat(64) }, { status: 'waiting' as const },
    { activeWorkerLaunchId: 'another-launch' }, { leaseEpoch: 2 }])
    assert.throws(() => validatePublicationLeaseRenewal(initial, next, { ...run, ...changed }));
});

test('matching caller rows cannot register publication lease equivalence without the genuine execution task', () => {
  const worker = Object.defineProperty({}, 'runId', { get() { throw new Error('untrusted worker getter'); } });
  assert.throws(() => beginPublicationLeaseReads(undefined as never, undefined as never, {}, worker as never, {} as never),
    /genuine same-owner in-flight execution task/);
});
