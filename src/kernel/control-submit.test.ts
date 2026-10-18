import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULT_RUN_BUDGETS, DEFAULT_SANDBOX_RESOURCES, mergeBudgets, normalizeRunSubmitRequest } from './control-submit.js';
import { canonicalSha256 } from './canonical.js';

test('public Run defaults preserve the fixed budgets and sandbox recipe values', () => {
  assert.deepEqual(DEFAULT_RUN_BUDGETS, { wallTimeMs: 86_400_000, modelTokens: 2_000_000,
    costMicros: 10_000_000, toolCalls: 1000, repairAttempts: 2, childDepth: 2, childConcurrency: 4 });
  assert.deepEqual(DEFAULT_SANDBOX_RESOURCES, { maxProcesses: 256, memoryBytes: 4 * 1024 ** 3,
    cpuQuotaMicrosPerSecond: 400_000, maxOpenFiles: 1024, maxSingleFileBytes: 256 * 1024 ** 2,
    maxGenerationBytes: 20 * 1024 ** 3, maxInvocationOutputBytes: 16 * 1024 ** 2,
    maxIpcFrameBytes: 16 * 1024 ** 2, maxQueuedIpcBytes: 64 * 1024 ** 2 });
  assert.deepEqual(mergeBudgets({ repairAttempts: 0, childDepth: 0 }),
    { ...DEFAULT_RUN_BUDGETS, repairAttempts: 0, childDepth: 0 });
  assert.throws(() => mergeBudgets({ modelTokens: 0 }), /modelTokens is outside 1\.\.100000000/u);
  assert.throws(() => mergeBudgets({ childConcurrency: 65 }), /childConcurrency is outside 1\.\.64/u);
});

test('public submit identity retains supplied JCS values while defaults and NFC belong to the intent', () => {
  const core = { protocolVersion: 1, method: 'run.submit', requestId: '01900000-0000-7000-8000-000000000001',
    admissionKey: 'a'.repeat(22), sessionId: 'session-1', expectedContextRevision: 1, workspacePath: '/workspace',
    objective: 'e\u0301', model: { provider: 'ollama', model: 'test' }, policyMode: 'default', verifiers: [],
    dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [],
    allowUnverified: true, budgets: { repairAttempts: 0, childDepth: 0 }, maxChangedPaths: 0, maxChangedBytes: 0 };
  const requestDigest = canonicalSha256(core);
  const decoded = normalizeRunSubmitRequest({ ...core, requestDigest });
  assert.equal(decoded.originalRequestDigest, requestDigest);
  assert.equal((decoded.originalRequest as typeof core).objective, 'e\u0301');
  assert.equal(decoded.request.objective, 'é');
  assert.equal(decoded.request.budgets.repairAttempts, 0);
  assert.equal(decoded.request.budgets.childDepth, 0);
  assert.equal(decoded.request.maxChangedPaths, 0);
  assert.equal(decoded.request.maxChangedBytes, 0);
  assert.equal(decoded.request.sandboxResources.maxSingleFileBytes, 256 * 1024 ** 2);
  let accessed = false;
  const accessor = Object.defineProperty({ ...core, requestDigest }, 'objective', {
    enumerable: true, get() { accessed = true; return 'e\u0301'; }
  });
  assert.throws(() => normalizeRunSubmitRequest(accessor));
  assert.equal(accessed, false);
});
