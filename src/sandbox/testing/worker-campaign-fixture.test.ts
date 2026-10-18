// Fixed signed-profile input DATA only. No filesystem capacity, native quota,
// StateOwner, process, provider or guest-verifier qualification is fabricated.
import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeSandboxProfile } from '../../state/execution-closure.js';
import { workerCampaignSandboxProfile } from './worker-campaign-fixture.js';

test('guest campaign declares its actual separate 512 MiB backing before the profile is signed', () => {
  const profile = workerCampaignSandboxProfile({ maxOpenFiles: 64 });
  assert.deepEqual(decodeSandboxProfile(profile), profile);
  assert.deepEqual(profile.resources, {
    maxProcesses: 32, memoryBytes: 268435456, cpuQuotaMicrosPerSecond: 100000, maxOpenFiles: 64,
    maxSingleFileBytes: 268435456, maxGenerationBytes: 536870912,
    maxInvocationOutputBytes: 16777216, maxIpcFrameBytes: 16777216, maxQueuedIpcBytes: 67108864
  });
});

test('ordinary campaign keeps its 256 MiB declaration and all original resource limits', () => {
  const profile = workerCampaignSandboxProfile();
  assert.deepEqual(decodeSandboxProfile(profile), profile);
  assert.deepEqual(profile.resources, {
    maxProcesses: 32, memoryBytes: 268435456, cpuQuotaMicrosPerSecond: 100000, maxOpenFiles: 128,
    maxSingleFileBytes: 16777216, maxGenerationBytes: 268435456,
    maxInvocationOutputBytes: 16777216, maxIpcFrameBytes: 16777216, maxQueuedIpcBytes: 67108864
  });
  const tampered = structuredClone(profile);
  tampered.resources.maxGenerationBytes = 536870912;
  assert.throws(() => decodeSandboxProfile(tampered), { code: 'ARTIFACT_MISMATCH' });
});
