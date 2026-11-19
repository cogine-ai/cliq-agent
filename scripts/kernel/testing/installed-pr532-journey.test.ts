import assert from 'node:assert/strict';
import test from 'node:test';
import { runSnapshot, ref, at } from '../../../src/client/testing/protocol.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import type { ToolResultItem, ToolResultPayloadV1 } from '../../../src/kernel/types.js';
import { pr532StopDiagnostic, pr532ToolDiagnostic, pr532TaskObjective, runInstalledPr532Journey, PR532_FILE, PR532_CHECK } from './installed-pr532-journey.js';

// Inert retained data projected through the original production decoder.
const run = runSnapshot().run;
const contextStop = { schemaVersion: 1, runId: run.id, createdAt: at, origin: 'runtime', targetStatus: 'failed',
  reason: 'runtime_failed', runtimeSubtype: 'context_window_exhausted', contextManifestRef: ref,
  nextPromptTokens: 25000, triggerThresholdTokens: 16384, hardPromptTokens: 24576, protectedTokens: 16000, sourceInputTokenCap: 8192 };

test('the original task preserves complete source/check data and puts affordable-call and candidate-check guidance after it', () => {
  const originalBytes = Buffer.from('inert unfixed source'), testBytes = Buffer.from('inert original check');
  const input = { originalBytes, testBytes, modelRequestCostMicros: 330696,
    budgets: { wallTimeMs: 5400000, costMicros: 4300000, modelTokens: 32000000, toolCalls: 100,
      repairAttempts: 2, childDepth: 0, childConcurrency: 1 } };
  const objective = pr532TaskObjective(input);
  const files = [{ path: PR532_FILE, bytes: originalBytes }, { path: PR532_CHECK, bytes: testBytes }]
    .map(({ path, bytes }) => ({ path, sha256: sha256Bytes(bytes), contentUtf8: bytes.toString('utf8') }));
  const source = canonicalJsonBytes({ files }).toString('utf8');
  assert(objective.includes(source));
  assert(objective.indexOf('Finish the first model turn immediately with plain text, no tool calls and no edits') > objective.indexOf(source));
  assert(objective.indexOf('at most 13 fully charged model calls') > objective.indexOf(source));
  assert(objective.indexOf('one coherent patch') > objective.indexOf(source));
  assert(objective.endsWith('Use its actual diagnostics for any further repair.'));
  const controlled = pr532TaskObjective({ originalBytes, testBytes, budgets: input.budgets });
  assert(controlled.includes(source)); assert(!controlled.includes('fully charged model calls'));
  assert(controlled.endsWith('Use its actual diagnostics for any further repair.'));
});

test('PR532 result diagnosis retains only a bound tool name, outcome and fixed failure code', () => {
  const payload: ToolResultPayloadV1 = { schemaVersion: 1, format: 'cliq-tool-result-payload-v1', runId: run.id,
    batchItemId: 'inert-batch', callId: 'inert-call', index: 0, toolName: 'edit', modelContentRef: ref,
    modelContentDigest: ref, outcome: 'error', code: 'TOOL_EXECUTION_FAILED', diagnosticRef: ref, diagnosticDigest: ref,
    payloadDigest: '' };
  payload.payloadDigest = digestOmitting(payload, 'payloadDigest');
  const item: ToolResultItem = { schemaVersion: 1, kind: 'tool_result', itemId: 'inert-item', runId: run.id,
    batchItemId: payload.batchItemId, callId: payload.callId, index: 0, outcome: 'error',
    resultRef: canonicalSha256(payload), createdAt: at };
  assert.deepEqual(pr532ToolDiagnostic(item, payload), { toolName: 'edit', outcome: 'error', code: 'TOOL_EXECUTION_FAILED' });
  const executed: ToolResultPayloadV1 = { schemaVersion: 1, format: payload.format, runId: run.id,
    batchItemId: payload.batchItemId, callId: payload.callId, index: 0, toolName: 'edit', modelContentRef: ref,
    modelContentDigest: ref, outcome: 'executed', source: 'invocation', opId: 'inert-op', attempt: 0,
    journalResultRef: ref, journalResultDigest: ref, payloadDigest: '' };
  executed.payloadDigest = digestOmitting(executed, 'payloadDigest');
  assert.deepEqual(pr532ToolDiagnostic({ ...item, outcome: 'executed', resultRef: canonicalSha256(executed) }, executed),
    { toolName: 'edit', outcome: 'executed' });
  for (const changed of [{ ...payload, runId: 'foreign' }, { ...payload, toolName: 'untrusted-model-text' },
    { ...payload, code: 'untrusted-model-text' }]) {
    changed.payloadDigest = digestOmitting(changed, 'payloadDigest');
    assert.throws(() => pr532ToolDiagnostic({ ...item, resultRef: canonicalSha256(changed) }, changed as ToolResultPayloadV1));
  }
  assert.throws(() => pr532ToolDiagnostic(item, { ...payload, modelContentRef: 'changed' }));
});

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
  const originalBytes = Buffer.from('original unfixed source\n');
  const testBytes = Buffer.from('original assertion\n');
  const unused = async (): Promise<never> => { throw new Error('unexpected fixture operation'); };
  await assert.rejects(runInstalledPr532Journey({ workspace: '/inert/project', sessionId: 'inert-session', alias: 'inert-model',
    originalBytes, testBytes, lockBytes: Buffer.alloc(0),
    budgets: { wallTimeMs: 3600000, modelTokens: 32000000, costMicros: 12000000, toolCalls: 100,
      repairAttempts: 2, childDepth: 0, childConcurrency: 1 } }, {
    command: async args => {
      calls++;
      assert.equal(args[0], 'run');
      assert(args[1]!.includes('first model turn immediately with plain text, no tool calls and no edits'));
      const sourceSection = args[1]!.split('\nOriginal repository files:\n')[1]!;
      const originalFiles = sourceSection.split('\nEnd of original repository files.\n')[0]!;
      const context = JSON.parse(originalFiles);
      assert.deepEqual(context, { files: [
        { path: PR532_FILE, sha256: sha256Bytes(originalBytes), contentUtf8: originalBytes.toString('utf8') },
        { path: PR532_CHECK, sha256: sha256Bytes(testBytes), contentUtf8: testBytes.toString('utf8') },
      ] });
      assert.equal(args[args.indexOf('--check-node') + 1], PR532_CHECK);
      assert.equal(args[args.indexOf('--budget-tokens') + 1], '32000000');
      assert.equal(args[args.indexOf('--budget-usd') + 1], '12.000000');
      throw captured;
    },
    authorizeGitSource: async () => ({ sourceInspectionGrantId: 'inert-grant', ignoreReadGrantIds: [] }),
    send: unused, artifact: unused, retained: unused, reconnect: unused, verifyHost: unused,
    progress: () => {}, dependencyFailure: () => {}, verifierObservation: () => {}, runtimeFailure: () => {}, toolActivity: () => {}, controlRefusal: () => {}, mark: () => {},
  }), error => error === captured);
  assert.equal(calls, 1);
});
