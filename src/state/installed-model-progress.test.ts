import assert from 'node:assert/strict';
import { test } from 'node:test';
import { selectInstalledModelProgress, type InstalledModelProgress } from './installed-model-progress.js';

// Pure scheduling facts only. These literals cannot mint a StateOwner, native
// observation, credential, claim or permission to resend a request.
const failed: InstalledModelProgress = { phase: 'failed', disposition: undefined,
  hasDispatchClaim: false, hasSettlement: true, retry: 'ready' };

test('a settled no-claim preparation failure wakes maintenance only when the original retry policy is ready', () => {
  assert.equal(selectInstalledModelProgress(failed), 'retry');
  for (const retry of ['pending', 'backoff', 'exhausted', 'completed'] as const)
    assert.equal(selectInstalledModelProgress({ ...failed, retry }), 'retain');
  assert.equal(selectInstalledModelProgress({ ...failed, hasSettlement: false }), 'retain');
  assert.equal(selectInstalledModelProgress({ ...failed, hasDispatchClaim: true }), 'retain');
});

test('a completed unusable observation must stop while a successful candidate remains retained', () => {
  const completed: InstalledModelProgress = { phase: 'completed', disposition: 'stop_required',
    hasDispatchClaim: true, hasSettlement: true, retry: 'completed' };
  assert.equal(selectInstalledModelProgress(completed), 'stop');
  assert.equal(selectInstalledModelProgress({ ...completed, disposition: 'candidate_required' }), 'retain');
  assert.equal(selectInstalledModelProgress({ ...completed, disposition: undefined }), 'retain');
});

test('pending, permanently claimed and unknown attempts never become another dispatch from a wake hint', () => {
  for (const phase of ['prepared', 'dispatch_claimed', 'unknown', 'abandoned'] as const)
    assert.equal(selectInstalledModelProgress({ ...failed, phase }), 'retain');
  assert.equal(selectInstalledModelProgress(undefined), 'prepare');
});
