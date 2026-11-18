import assert from 'node:assert/strict';
import test from 'node:test';
import { runSnapshot, ref, at } from '../../../src/client/testing/protocol.js';
import { pr532StopDiagnostic, runInstalledPr532Journey, PR532_CHECK } from './installed-pr532-journey.js';

// Inert retained data projected through the original production decoder.
const run = runSnapshot().run;
const contextStop = { schemaVersion: 1, runId: run.id, createdAt: at, origin: 'runtime', targetStatus: 'failed',
  reason: 'runtime_failed', runtimeSubtype: 'context_window_exhausted', contextManifestRef: ref,
  nextPromptTokens: 25000, triggerThresholdTokens: 16384, hardPromptTokens: 24576, protectedTokens: 16000, sourceInputTokenCap: 8192 };

test('PR532 failure diagnosis preserves the closed context cause and original numeric limits', () => {
  assert.deepEqual(pr532StopDiagnostic(run, contextStop), { diagnosticOnly: true, origin: 'runtime', reason: 'runtime_failed',
    runtimeSubtype: 'context_window_exhausted', nextPromptTokens: 25000, triggerThresholdTokens: 16384,
    hardPromptTokens: 24576, protectedTokens: 16000, sourceInputTokenCap: 8192 });
});

test('PR532 failure diagnosis distinguishes compaction and context-byte exhaustion', () => {
  const base = { schemaVersion: 1, runId: run.id, createdAt: at, origin: 'runtime', targetStatus: 'failed', reason: 'runtime_failed' };
  const compaction = pr532StopDiagnostic(run, { ...base, runtimeSubtype: 'context_compaction_failed', compactionPlanRef: ref,
    modelOpId: 'inert-model-op', attempt: 0 });
  assert('runtimeSubtype' in compaction); assert.equal(compaction.runtimeSubtype, 'context_compaction_failed');
  const bytes = pr532StopDiagnostic(run, { ...contextStop, nextPromptTokens: 1000, trigger: 'request_body_bytes',
    modelVisiblePromptDigest: ref, requestBodyBytes: 1048577, requestBodyLimitBytes: 1048576 });
  assert('trigger' in bytes && 'requestBodyLimitBytes' in bytes);
  assert.equal(bytes.trigger, 'request_body_bytes'); assert.equal(bytes.requestBodyLimitBytes, 1048576);
});

test('PR532 failure diagnosis refuses a foreign Run, unknown fields and invented subtypes', () => {
  for (const value of [{ ...contextStop, runId: 'foreign' }, { ...contextStop, rawError: 'untrusted body' },
    { ...contextStop, runtimeSubtype: 'invented' }, { ...contextStop, hardPromptTokens: -1 }])
    assert.throws(() => pr532StopDiagnostic(run, value), TypeError);
});

test('PR532 admission asks for the original check before exploration and retains its exact check and spend bounds', async () => {
  const captured = new Error('inert command capture');
  let calls = 0;
  const unused = async (): Promise<never> => { throw new Error('unexpected fixture operation'); };
  await assert.rejects(runInstalledPr532Journey({ workspace: '/inert/project', sessionId: 'inert-session', alias: 'inert-model',
    originalBytes: Buffer.alloc(0), testBytes: Buffer.alloc(0), lockBytes: Buffer.alloc(0),
    budgets: { wallTimeMs: 3600000, modelTokens: 32000000, costMicros: 8000000, toolCalls: 100,
      repairAttempts: 2, childDepth: 0, childConcurrency: 1 } }, {
    command: async args => {
      calls++;
      assert.equal(args[0], 'run');
      assert(args[1]!.includes('first model turn immediately with plain text, no tool calls and no edits'));
      assert.equal(args[args.indexOf('--check-node') + 1], PR532_CHECK);
      assert.equal(args[args.indexOf('--budget-tokens') + 1], '32000000');
      assert.equal(args[args.indexOf('--budget-usd') + 1], '8.000000');
      throw captured;
    },
    authorizeGitSource: async () => ({ sourceInspectionGrantId: 'inert-grant', ignoreReadGrantIds: [] }),
    send: unused, artifact: unused, retained: unused, reconnect: unused, verifyHost: unused,
    progress: () => {}, dependencyFailure: () => {}, verifierObservation: () => {}, runtimeFailure: () => {}, mark: () => {},
  }), error => error === captured);
  assert.equal(calls, 1);
});
