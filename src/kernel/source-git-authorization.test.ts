import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { DEFAULT_SANDBOX_RESOURCES } from './control-submit.js';
import { decodeAuthorizationCreateRequest, decodeInstalledControlRequest } from './control-wire.js';
import { normalizeRunApplyRequest } from './control-apply.js';

const core = { protocolVersion: 1, method: 'authorization.create', requestId: '01900000-0000-7000-8000-000000000001',
  decision: { kind: 'source_git_inspection', purpose: 'source_inspection', target: {
    sessionId: 'own-session', expectedWorkspaceIdentityDigest: 'a'.repeat(64),
    scope: 'in_root_git_metadata_and_objects', recipe: 'cliq-source-git-inspection-v1',
    retention: 'ephemeral_raw_reachable_only', resourceCeiling: { ...DEFAULT_SANDBOX_RESOURCES }
  } } };
const request = (value: unknown = core) => ({ ...value as object, requestDigest: canonicalSha256(value) });

test('source Git consent has an exact authenticated creation codec, distinct from source and tool permission', () => {
  const input = request();
  const result = decodeAuthorizationCreateRequest(input);
  assert.deepEqual(result, input);
  assert.deepEqual(decodeInstalledControlRequest(input), result);
  assert(Object.isFrozen(result));
  for (const change of [
    { kind: 'read_scope' }, { purpose: 'source' },
    { target: { ...core.decision.target, scope: 'workspace' } },
    { target: { ...core.decision.target, retention: 'durable_raw' } },
    { target: { ...core.decision.target, recipe: 'caller-selected' } },
    { target: { ...core.decision.target, remoteUrl: 'https://untrusted.invalid' } },
    { target: { ...core.decision.target, resourceCeiling: {} } },
    { target: { ...core.decision.target, resourceCeiling: { ...DEFAULT_SANDBOX_RESOURCES, maxOpenFiles: 8193 } } },
    { target: { ...core.decision.target, expectedWorkspaceIdentityDigest: true } }
  ]) assert.throws(() => decodeAuthorizationCreateRequest(request({ ...core, decision: { ...core.decision, ...change } })),
    TypeError, 'a foreign scope/recipe/resource cannot borrow inspection consent');
  assert.throws(() => decodeAuthorizationCreateRequest({ ...input, requestDigest: 'b'.repeat(64) }), TypeError);
});

test('source Git creation rejects accessors and proxies before executing their traps', () => {
  let accessed = 0;
  const input = request();
  const getter = { ...input };
  Object.defineProperty(getter, 'decision', { enumerable: true, get() { accessed++; return core.decision; } });
  assert.throws(() => decodeAuthorizationCreateRequest(getter), TypeError);
  const proxy = new Proxy(input, { ownKeys() { accessed++; return Reflect.ownKeys(input); },
    getPrototypeOf() { accessed++; return Object.prototype; }, get() { accessed++; return undefined; } });
  assert.throws(() => decodeAuthorizationCreateRequest(proxy), TypeError);
  assert.equal(accessed, 0);
});

test('independent source read consent fixes one canonical selector, not a Git recipe or automatic include permission', () => {
  for (const path of ['.git/info/exclude', '.gitignore', 'nested/.gitignore', 'ordinary/file.txt']) {
    const value = request({ ...core, decision: { kind: 'read_scope', purpose: 'source', target: {
      sessionId: 'own-session', expectedWorkspaceIdentityDigest: 'a'.repeat(64), path, scope: 'entry' } } });
    assert.deepEqual(decodeAuthorizationCreateRequest(value), value);
    assert.deepEqual(decodeInstalledControlRequest(value), value);
  }
  for (const target of [ { path: '../outside', scope: 'entry' }, { path: '/outside', scope: 'entry' },
    { path: '.git/config', scope: 'entry' }, { path: '.GIT/info/exclude', scope: 'entry' },
    { path: '.git/info/exclude', scope: 'subtree' }, { path: 'nested/.git/objects', scope: 'entry' },
    { path: 'file.txt', scope: 'all' }, { path: 'file.txt', scope: 'entry', authority: true },
    { path: 'file.txt', scope: 'entry', expectedDigest: true } ]) {
    const value = request({ ...core, decision: { kind: 'read_scope', purpose: 'source', target: {
      sessionId: 'own-session', expectedWorkspaceIdentityDigest: 'a'.repeat(64), ...target } } });
    assert.throws(() => decodeAuthorizationCreateRequest(value), TypeError);
  }
});

test('capture ignore-rule grants are independently bounded ids, never inline read authority', () => {
  const ignored = ['read-rules-one', 'read-rules-two'];
  const sourceInspectionRequest = (change: object) => request({ protocolVersion: 1, method: 'run.submit', requestId: core.requestId,
    admissionKey: 'own-submit-aaaaaaaaaaaaaaaa', sessionId: 'own-session', expectedContextRevision: 1, workspacePath: '/workspace', objective: 'inspect own fixture',
    model: { provider: 'ollama', model: 'local' }, policyMode: 'default', verifiers: [], dependency: { mode: 'none' },
    sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: true, ...change });
  const submit = sourceInspectionRequest({ ignoreReadGrantIds: ignored });
  const decoded = decodeInstalledControlRequest(submit);
  assert.equal(decoded.method, 'run.submit');
  if (decoded.method !== 'run.submit') assert.fail('own submit fixture');
  assert.deepEqual(decoded.ignoreReadGrantIds, ignored);
  const applyCore = { protocolVersion: 1, method: 'run.apply', requestId: core.requestId,
    admissionKey: 'own-apply-aaaaaaaaaaaaaaaa', sourceRunId: 'own-source', expectedRunResultRef: 'a'.repeat(64), ignoreReadGrantIds: ignored };
  assert.deepEqual(normalizeRunApplyRequest(request(applyCore)).request.ignoreReadGrantIds, ignored);
  for (const value of [['duplicate', 'duplicate'], Array.from({ length: 129 }, (_, i) => `grant-${i}`),
    [true], { grantId: 'inline' }, undefined]) {
    assert.throws(() => decodeInstalledControlRequest(sourceInspectionRequest({ ignoreReadGrantIds: value })), TypeError);
    assert.throws(() => normalizeRunApplyRequest(request({ ...applyCore, ignoreReadGrantIds: value })), TypeError);
  }
});
