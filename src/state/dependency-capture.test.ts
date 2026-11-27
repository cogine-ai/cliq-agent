import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeDependencyProcessCapture, retainDependencyCapturePublication, type DependencyProcessCaptureV1 } from './dependency-capture.js';
const ref = (s: string) => canonicalSha256({ inertData: s });
function frame(): DependencyProcessCaptureV1 {
  const value: DependencyProcessCaptureV1 = { schemaVersion: 1, format: 'cliq-dependency-process-capture-v1', runId: 'run', opId: 'dependency',
    attempt: 0, dispatchId: 'dispatch', leaseEpoch: 1, requestRef: ref('request'), targetRef: ref('target'), grantRef: ref('grant'),
    sandboxLaunchSpecRef: ref('spec'), claimEvidenceRef: ref('claim'), dependencyPlanRef: ref('plan'), startedAt: '2026-10-27T00:00:00.000Z',
    endedAt: '2026-10-27T00:00:01.000Z', durationMs: 1000, stdoutRef: ref('stdout'), stdoutByteCount: 1,
    stderrRef: ref('stderr'), stderrByteCount: 2, stdoutTruncated: false, stderrTruncated: false,
    containmentRef: ref('containment'), deathEvidenceRef: ref('death'), terminationReason: 'exit', exitCode: 0, captureDigest: '' };
  value.captureDigest = digestOmitting(value, 'captureDigest'); return value;
}
test('dependency capture data remains closed, combined bounded and separate from native authority', () => {
  const input = frame(); assert.deepEqual(decodeDependencyProcessCapture(input), input);
  for (const edit of [{ format: 'cliq-builtin-tool-capture-v1' }, { attempt: 2 }, { stdoutByteCount: 67_108_864, stderrByteCount: 1 },
    { terminationReason: 'timeout' }, { endedAt: '2026-10-26T00:00:01.000Z' }, { unknown: 0 }, { captureDigest: ref('foreign') }]) {
    const value = { ...input, ...edit }; if (!Object.hasOwn(edit, 'captureDigest')) value.captureDigest = digestOmitting(value, 'captureDigest');
    assert.throws(() => decodeDependencyProcessCapture(value));
  }
  let read = 0;
  const foreign = new Proxy({}, { get() { read++; throw new Error('foreign'); }, ownKeys() { read++; throw new Error('foreign'); } });
  assert.throws(() => decodeDependencyProcessCapture(foreign));
  assert.throws(() => retainDependencyCapturePublication(undefined!, foreign as never, foreign as never, foreign as never,
    ref('claim'), foreign as never, foreign as never), /original same-claim native producer/);
  assert.equal(read, 0);
});
