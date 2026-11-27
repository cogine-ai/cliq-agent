// Fixed data support boundaries, not a signed runtime or execution proof.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { assertBuiltinScriptResources } from './tool-runtime-authority.js';

test('fixed Node tools reject unsupported original resources without raising caller limits', () => {
  const imageBytes = 64 * 1024 * 1024;
  const resources = Object.freeze({ ...DEFAULT_SANDBOX_RESOURCES, maxProcesses: 32, maxSingleFileBytes: imageBytes });
  assert.doesNotThrow(() => assertBuiltinScriptResources(imageBytes, resources));
  for (const change of [{ maxProcesses: 8 }, { maxProcesses: 31 }, { maxProcesses: NaN }, { maxSingleFileBytes: imageBytes - 1 },
    { maxSingleFileBytes: 268435457 }, { maxInvocationOutputBytes: 65535 }, { maxInvocationOutputBytes: 67108865 },
    { maxIpcFrameBytes: 16777215 }, { maxQueuedIpcBytes: 67108865 }]) {
    const original = Object.freeze({ ...resources, ...change });
    assert.throws(() => assertBuiltinScriptResources(imageBytes, original), /original profile/u);
    for (const key of Object.keys(change)) assert.equal(original[key as keyof typeof original], change[key as keyof typeof change]);
  }
  for (const size of [0, 268435457, NaN]) assert.throws(() => assertBuiltinScriptResources(size, resources));
  assert.equal(resources.maxSingleFileBytes, imageBytes); assert.equal(resources.maxProcesses, 32);
});
