// Pure retained-data decoding only. No StateOwner, Run, native process,
// containment proof or executable capability is created by these objects.
import assert from 'node:assert/strict';
import test from 'node:test';
import type { ProcessContainment } from '../kernel/types.js';
import { decodeBuiltinProcessContainment, decodeWorkerProcessContainment } from './execution-closure.js';

const ref = 'a'.repeat(64), parentRef = 'b'.repeat(64);

// Match actualContainment's original invocation data shape, including the
// parent edge copied from the original containment plan. Decoding is not proof.
function invocation(): ProcessContainment {
  return { schemaVersion: 1, planRef: ref, sandboxLaunchSpecRef: ref, sandboxLaunchSpecDigest: ref,
    owner: { kind: 'run_invocation', runId: 'data-run', intendedLeaseEpoch: 1, workerLaunchId: 'data-worker',
      opId: 'data-op', attempt: 0, dispatchId: 'data-dispatch' },
    filesystemBinding: { kind: 'run-generation', generationRef: ref }, parentContainmentRef: parentRef,
    launchNonceDigest: ref, backend: { kind: 'linux', pidNamespaceReservationId: 'data-reservation',
      pidNamespaceId: 'pid:[data]', cgroupPath: '/cliq/data/worker/invocation', cgroupId: 'data-cgroup',
      namespaceInitStartToken: 'data-init', subreaperStartToken: 'data-subreaper' }, createdAt: '2026-10-31T00:00:00.000Z' };
}

test('invocation containment preserves the native producer parent and binds the original launch parent', () => {
  const original = invocation();
  assert.deepEqual(decodeBuiltinProcessContainment(original, parentRef), original);
  assert.deepEqual(original, invocation());
});

test('invocation containment rejects a missing, invalid or substituted parent and unknown fields', () => {
  const { parentContainmentRef: _parent, ...withoutParent } = invocation();
  for (const value of [withoutParent, { ...invocation(), parentContainmentRef: 'invalid' },
    { ...invocation(), parentContainmentRef: ref }, { ...invocation(), executionGrant: ref }])
    assert.throws(() => decodeBuiltinProcessContainment(value, parentRef), { code: 'ARTIFACT_MISMATCH' });
  assert.throws(() => decodeBuiltinProcessContainment(invocation(), 'invalid'), { code: 'ARTIFACT_MISMATCH' });
});

test('worker containment remains parentless and cannot borrow invocation ownership or extra fields', () => {
  const { parentContainmentRef: _parent, ...original } = invocation();
  const worker = { ...original, owner: { kind: 'worker_activation' as const, runId: 'data-run', intendedLeaseEpoch: 1, workerLaunchId: 'data-worker' } };
  assert.deepEqual(decodeWorkerProcessContainment(worker), worker);
  for (const value of [{ ...worker, parentContainmentRef: parentRef }, { ...worker, executionGrant: ref }, invocation()])
    assert.throws(() => decodeWorkerProcessContainment(value), { code: 'ARTIFACT_MISMATCH' });
  assert.throws(() => decodeBuiltinProcessContainment(worker, parentRef), { code: 'ARTIFACT_MISMATCH' });
});
