import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { normalizeRunApplyRequest, runApplyIntentDigest } from './control-apply.js';

const core = { protocolVersion: 1 as const, method: 'run.apply' as const,
  requestId: '01900000-0000-7000-8000-000000000001', admissionKey: 'a'.repeat(32),
  sourceRunId: 'owned-source-run', expectedRunResultRef: 'a'.repeat(64) };
const request = (value: Record<string, unknown> = core) => ({ ...value, requestDigest: canonicalSha256(value) });

test('delivery request identity keeps original bytes while only bounded wall/tool defaults enter its intent', () => {
  const normalized = normalizeRunApplyRequest(request());
  assert.deepEqual(normalized.originalRequest, request());
  assert.equal(normalized.originalRequestDigest, request().requestDigest);
  assert.deepEqual(normalized.request.budgets, { wallTimeMs: 86400000, toolCalls: 1000 });
  assert.deepEqual(normalized.request.verifierExecutionGrantIds, []);
  const explicit = normalizeRunApplyRequest(request({ ...core, requestId: '01900000-0000-7000-8000-000000000002',
    budgets: { toolCalls: 1000, wallTimeMs: 86400000 }, verifierExecutionGrantIds: [] }));
  assert.notEqual(normalized.originalRequestDigest, explicit.originalRequestDigest);
  assert.equal(runApplyIntentDigest('principal', normalized.request), runApplyIntentDigest('principal', explicit.request));
  assert(Object.isFrozen(normalized.request) && Object.isFrozen(normalized.request.budgets));
});

test('delivery normalization never lets caller paths, refs, consent or productive budgets become admission authority', () => {
  for (const [key, value] of Object.entries({ workspacePath: '/tmp/work', objective: 'replacement', operation: 'delivery',
    capturedWorkspaceRef: 'b'.repeat(64), workspaceStateRef: 'c'.repeat(64), allowUnverified: true,
    policyMode: 'yolo', sourceRunResultRef: 'd'.repeat(64) })) {
    assert.throws(() => normalizeRunApplyRequest(request({ ...core, [key]: value })));
  }
  for (const budgets of [{ modelTokens: 1 }, { costMicros: 0 }, { repairAttempts: 0 }, { childDepth: 0 },
    { childConcurrency: 0 }, { wallTimeMs: 999 }, { wallTimeMs: 2592000001 }, { toolCalls: 0 },
    { toolCalls: 1000001 }, { toolCalls: 1.5 }, { wallTimeMs: true }]) {
    assert.throws(() => normalizeRunApplyRequest(request({ ...core, budgets })));
  }
  for (const expectedRunResultRef of ['A'.repeat(64), 'a'.repeat(43), '', 'a'.repeat(65)])
    assert.throws(() => normalizeRunApplyRequest(request({ ...core, expectedRunResultRef })));
  assert.throws(() => normalizeRunApplyRequest({ ...request(), requestDigest: 'b'.repeat(64) }));
});

test('delivery verifier grants are exact unique bounded data and retain normalized intent separately from wire identity', () => {
  const grants = ['exact-one', 'exact-two'];
  const normalized = normalizeRunApplyRequest(request({ ...core, sourceRunId: 'source-cafe\u0301', verifierExecutionGrantIds: grants }));
  assert.equal(normalized.request.sourceRunId, 'source-caf\u00e9');
  assert.deepEqual(normalized.request.verifierExecutionGrantIds, grants);
  grants.push('later-mutation'); assert.equal(normalized.request.verifierExecutionGrantIds.length, 2);
  for (const verifierExecutionGrantIds of [['duplicate', 'duplicate'], Array.from({ length: 33 }, (_, i) => `grant-${i}`),
    [''], ['a'.repeat(129)], ['contains\0nul'], new Array(1)])
    assert.throws(() => normalizeRunApplyRequest(request({ ...core, verifierExecutionGrantIds })));
});

test('delivery request decoding rejects hidden/accessor/symbol authority without evaluating it', () => {
  let invoked = 0;
  const hidden = request(); Object.defineProperty(hidden, 'workspacePath', { value: '/not-allowed', enumerable: false });
  assert.throws(() => normalizeRunApplyRequest(hidden));
  const accessor = request(); Object.defineProperty(accessor, 'sourceRunId', { get() { invoked++; return core.sourceRunId; }, enumerable: true });
  assert.throws(() => normalizeRunApplyRequest(accessor)); assert.equal(invoked, 0);
  assert.throws(() => normalizeRunApplyRequest({ ...request(), [Symbol('authority')]: true }));
  const grants: unknown[] = []; Object.defineProperty(grants, 0, { get() { invoked++; return 'grant'; }, enumerable: true });
  assert.throws(() => normalizeRunApplyRequest({ ...request(), verifierExecutionGrantIds: grants })); assert.equal(invoked, 0);
});

test('fresh Delivery source consent contains only unique grant locators in exact wire order', () => {
  const sourceReadGrantIds = ['first', 'second'];
  const decoded = normalizeRunApplyRequest(request({ ...core, sourceReadGrantIds }));
  assert.deepEqual(decoded.request.sourceReadGrantIds, sourceReadGrantIds);
  sourceReadGrantIds.reverse();
  assert.deepEqual(decoded.request.sourceReadGrantIds, ['first', 'second']);
  assert.notEqual(runApplyIntentDigest('principal', decoded.request), runApplyIntentDigest('principal',
    normalizeRunApplyRequest(request({ ...core, sourceReadGrantIds })).request));
  for (const ids of [['same', 'same'], [''], ['a'.repeat(129)], new Array(1),
    Array.from({ length: 129 }, (_, i) => `grant-${i}`), [{ path: 'caller-selected', grantId: 'first' }]]) {
    assert.throws(() => normalizeRunApplyRequest(request({ ...core, sourceReadGrantIds: ids })));
  }
  assert.throws(() => normalizeRunApplyRequest(request({ ...core, sourceReadGrantIds: ['same'], ignoreReadGrantIds: ['same'] })));
});
