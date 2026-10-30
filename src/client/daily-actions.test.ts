import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createInstalledControlSession } from '../control/session.js';
import { mergeBudgets } from '../kernel/control-submit.js';
import type { RunSnapshotV1 } from '../kernel/types.js';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { createClientApplication } from './application.js';
import { ClientRefusal, executeClientAction } from './actions.js';
import { parseClientInvocation, type ClientInvocationDefaults } from './commands.js';
import { at, hello, ref, runSnapshot, sessionSnapshot } from './testing/protocol.js';

const defaults: ClientInvocationDefaults = { guestToolchainManifestId: 'installed-node-toolchain', preferences: { schemaVersion: 1,
  modelSelections: [{ alias: 'deepseek', provider: 'openai-compatible', model: 'deepseek-flash', endpointRegistrationId: 'endpoint', credentialGrantId: 'credential' }],
  defaultModelAlias: 'deepseek', budgetDefaults: mergeBudgets({ costMicros: 5_000_000, toolCalls: 12 }) } };
const advanced = ['--provider', 'openai-compatible', '--model', 'real-model', '--endpoint', 'explicit-endpoint', '--credential-grant', 'explicit-credential'];

test('daily model aliases reuse only recorded ids and budget choices; explicit provider options retain original semantics', () => {
  for (const model of [[], ['--model', 'deepseek']]) {
    const value = parseClientInvocation(['run', 'Fix it', ...model, '--budget-usd', '0.123456'], '/workspace', defaults);
    assert.equal(value.kind, 'run'); if (value.kind !== 'run') return;
    assert.deepEqual(value.intent.model, { provider: 'openai-compatible', model: 'deepseek-flash',
      endpoint: { kind: 'registered', endpointRegistrationId: 'endpoint' }, modelCredentialGrantIds: ['credential'] });
    assert.equal(value.intent.budgets?.costMicros, 123456); assert.equal(value.intent.budgets?.toolCalls, 12);
    assert.equal(value.intent.policyMode, 'default');
  }
  const explicit = parseClientInvocation(['run', 'Fix it', ...advanced], '/workspace', defaults);
  assert.equal(explicit.kind, 'run'); if (explicit.kind !== 'run') return;
  assert.equal(explicit.intent.budgets, undefined);
  assert.equal(explicit.intent.model.model, 'real-model');
  for (const flags of [['--model', 'missing'], ['--model', 'deepseek', '--endpoint', 'other'],
    ['--model', 'deepseek', '--credential-grant', 'other']])
    assert.throws(() => parseClientInvocation(['run', 'Fix it', ...flags], '/workspace', defaults));
  const overridden = parseClientInvocation(['run', 'Fix it', '--options', '{"budgets":{"toolCalls":3}}'], '/workspace', defaults);
  assert.equal(overridden.kind, 'run'); if (overridden.kind === 'run') assert.equal(overridden.intent.budgets?.toolCalls, 3);
});

test('USD budgets use exact decimal micros and refuse duplicate or out-of-contract allowances', () => {
  for (const [literal, expected] of [['0.000001', 1], ['1.000001', 1000001], ['1000000', 1000000000000]] as const) {
    const result = parseClientInvocation(['run', 'Fix it', ...advanced, '--budget-usd', literal], '/workspace');
    assert.equal(result.kind, 'run'); if (result.kind === 'run') assert.equal(result.intent.budgets?.costMicros, expected);
  }
  for (const literal of ['0', '-1', '01', ' 1', '1.', '.1', '1e2', '1.0000001', '1000000.000001', '10000000', 'NaN'])
    assert.throws(() => parseClientInvocation(['run', 'Fix it', ...advanced, '--budget-usd', literal], '/workspace'));
  for (const flags of [['--budget-usd', '1', '--budget-usd', '2'],
    ['--budget-usd', '1', '--options', '{"budgets":{"costMicros":1}}'],
    ['--budget-usd', '1', '--options', '{"budgets":{"newAllowance":2}}']])
    assert.throws(() => parseClientInvocation(['run', 'Fix it', ...advanced, ...flags], '/workspace'));
});

test('explicit token budgets preserve every unmentioned limit and reject ambiguous or unsupported integers', () => {
  const original = structuredClone(defaults.preferences);
  const selected = parseClientInvocation(['run', 'Fix it', '--budget-usd', '5', '--budget-tokens', '20000000',
    '--check-node', 'check.test.mjs', '--policy', 'yolo', '--options', '{"budgets":{"wallTimeMs":60000,"repairAttempts":1}}'], '/workspace', defaults);
  assert.equal(selected.kind, 'run'); if (selected.kind !== 'run') return;
  assert.deepEqual(selected.intent.budgets, mergeBudgets({ ...defaults.preferences.budgetDefaults,
    wallTimeMs: 60000, repairAttempts: 1, modelTokens: 20_000_000, costMicros: 5_000_000 }));
  assert.deepEqual(defaults.preferences, original);
  const explicit = parseClientInvocation(['run', 'Fix it', ...advanced, '--budget-tokens', '100000000'], '/workspace', defaults);
  assert.equal(explicit.kind, 'run'); if (explicit.kind === 'run')
    assert.deepEqual(explicit.intent.budgets, mergeBudgets({ modelTokens: 100_000_000 }));
  const untouched = parseClientInvocation(['run', 'Fix it', '--budget-usd', '5'], '/workspace', defaults);
  assert.equal(untouched.kind, 'run'); if (untouched.kind === 'run')
    assert.equal(untouched.intent.budgets?.modelTokens, defaults.preferences.budgetDefaults!.modelTokens);
  for (const literal of ['0', '-1', '01', ' 20', '1.5', '1e7', '100000001', '9007199254740993'])
    assert.throws(() => parseClientInvocation(['run', 'Fix it', '--budget-tokens', literal], '/workspace', defaults));
  for (const flags of [['--budget-tokens', '2', '--budget-tokens', '3'],
    ['--budget-tokens', '2', '--options', '{"budgets":{"modelTokens":3}}']])
    assert.throws(() => parseClientInvocation(['run', 'Fix it', ...flags], '/workspace', defaults));
});

test('Node preset remains local data until real authorization, with explicit yolo and the exact fixed path profile', () => {
  const parsed = parseClientInvocation(['run', 'Fix it', '--check-node', 'test/check.mjs', '--policy', 'yolo'], '/workspace', defaults);
  assert.equal(parsed.kind, 'run'); if (parsed.kind !== 'run') return;
  assert.deepEqual(parsed.nodeCheck, { path: 'test/check.mjs', guestToolchainManifestId: 'installed-node-toolchain' });
  assert.deepEqual(parsed.intent.verifiers, []); assert.equal(parsed.intent.allowUnverified, false);
  for (const path of ['../check.mjs', '/check.mjs', '.git/check.mjs', '-check.mjs', 'check.test.js', 'test\\check.mjs', 'test//check.mjs'])
    assert.throws(() => parseClientInvocation(['run', 'Fix it', '--check-node', path, '--policy', 'yolo'], '/workspace', defaults));
  assert.throws(() => parseClientInvocation(['run', 'Fix it', '--check-node', 'check.mjs'], '/workspace', defaults));
  assert.throws(() => parseClientInvocation(['run', 'Fix it', '--check-node', 'check.mjs', '--policy', 'yolo', '--options', '{"verifiers":[]}'], '/workspace', defaults));
  assert.throws(() => parseClientInvocation(['run', 'Fix it', '--check-node', 'check.mjs', '--policy', 'yolo', '--allow-unverified'], '/workspace', defaults));
  assert.throws(() => parseClientInvocation(['run', 'Fix it', '--check-node', 'check.mjs', '--policy', 'yolo'], '/workspace', { preferences: defaults.preferences }));
});

test('syntax preflight never substitutes for actual unverified consent before sending any request', async () => {
  for (const allowed of [false, true]) {
    const fixture = consumer(); let confirmations = 0;
    try {
      const invocation = parseClientInvocation(['run', 'Fix it', '--detach'], '/workspace', defaults);
      if (allowed) {
        await executeClientAction(fixture.app, invocation, async () => { confirmations++; return true; });
        assert.deepEqual(fixture.calls.map(call => call.method), ['session.create', 'session.get', 'run.submit']);
        assert.equal(fixture.calls.at(-1)!.request.allowUnverified, true);
      } else {
        await assert.rejects(executeClientAction(fixture.app, invocation, async () => { confirmations++; return false; }));
        assert.deepEqual(fixture.calls, []);
      }
      assert.equal(confirmations, 1);
      assert.equal(invocation.kind === 'run' && invocation.intent.allowUnverified, false);
    } finally { await fixture.app.close(); }
  }
});

// Genuine protocol decoder/application composition over inert data only. This
// does not create a Session, Run, grant, installation or native execution proof.
function consumer(overrides: Record<string, unknown> = {}) {
  const calls: Array<{ method: string; request: any }> = [];
  const methods: Record<string, any> = {
    'session.create': async () => ({ protocolVersion: 1, ok: true, result: { method: 'session.create', snapshot: sessionSnapshot() } }),
    'session.get': async () => ({ protocolVersion: 1, ok: true, result: { method: 'session.get', snapshot: sessionSnapshot(), items: [], highWaterItemSeq: 0, nextItemSeq: 0 } }),
    'authorization.create': async () => ({ protocolVersion: 1, ok: true, result: { method: 'authorization.create', grant: {
      schemaVersion: 1, grantId: 'real-response-grant', state: 'active', targetKind: 'execution_identity_read', purpose: 'verifier',
      targetDigest: ref, useCount: 0, rowVersion: 1, createdAt: at, expiresAt: '2026-10-27T00:00:00.000Z' } } }),
    'run.submit': async () => ({ protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: runSnapshot() } }),
    ...overrides
  };
  for (const [method, original] of Object.entries(methods)) methods[method] = async (request: unknown) => { calls.push({ method, request }); return original(request); };
  const session = createInstalledControlSession({ hello: { ...hello, enabledFeatureIds: Object.keys(methods) }, close: async () => {}, ...methods } as unknown as InstalledSupervisorClient);
  return { app: createClientApplication(session, () => {}), calls };
}

test('a checked Run creates its Session, requests its real identity grant and only then submits the fixed verifier', async () => {
  const fixture = consumer();
  try {
    const invocation = parseClientInvocation(['run', 'Fix it', '--check-node', 'check.test.mjs', '--policy', 'yolo', '--detach'], '/workspace', defaults);
    const result = await executeClientAction(fixture.app, invocation, async () => { throw new Error('required check must not ask for unverified consent'); });
    assert.equal(result.runId, 'run'); assert.equal(result.follow, false);
    assert.deepEqual(fixture.calls.map(call => call.method), ['session.create', 'authorization.create', 'session.get', 'run.submit']);
    assert.deepEqual(fixture.calls[1]!.request.decision, { kind: 'execution_identity_read', purpose: 'verifier',
      target: { kind: 'guest_toolchain', guestToolchainManifestId: 'installed-node-toolchain', toolId: 'node' } });
    const request = fixture.calls[3]!.request;
    assert.equal(request.expectedContextRevision, 7); assert.equal(request.allowUnverified, false);
    assert.deepEqual(request.verifiers, [{ id: 'node-tests', version: '1', required: true, executable: { kind: 'toolchain', toolId: 'node' },
      argv: ['--test', '--test-concurrency=1', 'check.test.mjs'].map(value => ({ kind: 'non_secret_literal', value })),
      cwd: '.', env: {}, writableEphemeralPaths: [], identityReadGrantId: 'real-response-grant', timeoutMs: 10000, retries: 0, outputLimitBytes: 65536 }]);
  } finally { await fixture.app.close(); }
});

test('a refused or uncertain identity-grant response ends the action without admission or replacement', async () => {
  for (const uncertain of [false, true]) {
    const fixture = consumer({ 'authorization.create': async () => {
      if (uncertain) throw new Error('original grant response lost');
      return { protocolVersion: 1, ok: false, method: 'authorization.create', error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'authorization.required' } };
    } });
    try {
      const invocation = parseClientInvocation(['run', 'Fix it', '--check-node', 'check.mjs', '--policy', 'yolo'], '/workspace', defaults);
      await assert.rejects(executeClientAction(fixture.app, invocation));
      assert.deepEqual(fixture.calls.map(call => call.method), ['session.create', 'authorization.create']);
      assert.equal(fixture.app.pendingRequest?.method, uncertain ? 'authorization.create' : undefined);
    } finally { await fixture.app.close(); }
  }
});

function attached(snapshot: RunSnapshotV1) {
  return { protocolVersion: 1, ok: true, result: { method: 'run.attach', snapshot,
    earliestRetainedEventSeq: 1, latestRetainedEventSeq: 1, highWaterEventSeq: 1, nextEventSeq: 1,
    events: [{ schemaVersion: 1, kind: 'progress', runId: 'run', eventSeq: 1, observedRunRevision: 1, phase: 'agent', occurredAt: at }] } };
}
test('result --wait follows the original Run then exposes the exact immutable result request for existing review', async () => {
  const { frontierRef: _frontier, ...run } = runSnapshot().run;
  const terminal: RunSnapshotV1 = { ...runSnapshot(), run: { ...run, revision: 2, status: 'completed_unverified', nextStep: null,
    terminalReason: 'no_required_verifier', resultRef: ref } };
  const fixture = consumer({ 'run.attach': async () => attached(terminal), 'run.result': async () => ({ protocolVersion: 1, ok: true,
    result: { method: 'run.result', runId: 'run', result: { schemaVersion: 1, ref, digest: ref, sizeBytes: 10, mediaType: 'application/json' }, verificationClosureRef: ref } }) });
  try {
    const result = await executeClientAction(fixture.app, parseClientInvocation(['result', 'run', '--wait'], '/workspace'));
    assert.equal(result.follow, false); assert.equal(result.exitCode, 0);
    assert.deepEqual(result.presentationRequest, { protocolVersion: 1, method: 'run.result', runId: 'run' });
    assert.deepEqual(fixture.calls.map(call => call.method), ['run.attach', 'run.result']);
  } finally { await fixture.app.close(); }
});

test('result --wait stops at a real wait/refusal without approving, probing, cancelling or hiding attach failure', async () => {
  for (const atWait of [false, true]) {
    const waiting: RunSnapshotV1 = { ...runSnapshot(), run: { ...runSnapshot().run, revision: 2, status: 'waiting', waitingReason: 'input', waitingOnRef: ref } };
    const fixture = consumer({ 'run.attach': async () => atWait ? attached(waiting) : { protocolVersion: 1, ok: false, method: 'run.attach',
      error: { schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } },
    'run.result': async () => ({ protocolVersion: 1, ok: false, method: 'run.result', error: { schemaVersion: 1, code: 'RESULT_UNAVAILABLE',
      messageCode: 'run.result_unavailable', runId: 'run', retryable: true, status: 'waiting', currentRevision: 2 } }) });
    try {
      await assert.rejects(executeClientAction(fixture.app, parseClientInvocation(['result', 'run', '--wait'], '/workspace')),
        (error: unknown) => error instanceof ClientRefusal && error.code === (atWait ? 'RESULT_UNAVAILABLE' : 'NOT_FOUND'));
      assert.deepEqual(fixture.calls.map(call => call.method), atWait ? ['run.attach', 'run.result'] : ['run.attach']);
    } finally { await fixture.app.close(); }
  }
});
