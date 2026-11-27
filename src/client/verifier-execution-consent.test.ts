import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { clientMutation, decodeInstalledControlRequest, decodeInstalledControlResponse } from '../sdk/index.js';

// Actual SDK/wire data consumers only. These inert DTOs are neither registered
// authorization nor evidence of identity inspection, native execution or an
// accepted Run; only the owning authenticated server may create such facts.
const decision = () => ({ kind: 'verifier_execution', verifierId: 'node-tests', verifierRequestDigest: canonicalSha256('inert exact verifier request core'),
  executionIdentityGrantId: 'inert-identity-grant', maxCandidateGenerations: 1, maxAttemptsPerCandidate: 1 });
function request(changed: Record<string, unknown> = {}) {
  const result = clientMutation({ method: 'authorization.create', decision: { ...decision(), ...changed } });
  assert(result.method === 'authorization.create' && result.decision.kind === 'verifier_execution'); return result;
}
function summary() {
  return { schemaVersion: 1, grantId: 'inert-derived-execution-grant', state: 'active', targetKind: 'verifier_execution', purpose: 'verifier',
    targetDigest: canonicalSha256('inert resolved target'), useCount: 0, rowVersion: 1,
    createdAt: '2026-10-26T00:00:00.000Z', expiresAt: '2026-10-26T01:00:00.000Z' };
}
const response = (grant: Record<string, unknown>) => ({ protocolVersion: 1, ok: true,
  result: { method: 'authorization.create', grant } });

test('SDK preserves the explicit verifier execution request and its exact immutable wire identity', () => {
  const original = decision(), value = clientMutation({ method: 'authorization.create', decision: original, ttlMs: 60_000 });
  assert(value.method === 'authorization.create' && value.decision.kind === 'verifier_execution');
  assert.deepEqual(value.decision, original); assert.equal(value.ttlMs, 60_000);
  const { requestDigest, ...core } = value;
  assert.equal(requestDigest, canonicalSha256(core));
  assert.deepEqual(decodeInstalledControlRequest(JSON.parse(canonicalJsonBytes(value).toString('utf8'))), value);
  original.executionIdentityGrantId = 'changed-client-data'; original.verifierRequestDigest = 'b'.repeat(64);
  assert.equal(value.decision.executionIdentityGrantId, 'inert-identity-grant');
  assert.equal(value.decision.verifierRequestDigest, decision().verifierRequestDigest);
  assert(Object.isFrozen(value)); assert(Object.isFrozen(value.decision));
  assert.throws(() => decodeInstalledControlRequest({ ...value, decision: { ...value.decision, executionIdentityGrantId: 'other-identity' } }));
  assert.throws(() => decodeInstalledControlRequest({ ...value, requestDigest: 'b'.repeat(64) }));
});

test('verifier execution accepts only the bounded integer candidate and per-candidate attempt ceilings', () => {
  for (let candidates = 1; candidates <= 6; candidates++) for (let attempts = 1; attempts <= 4; attempts++) {
    const value = request({ maxCandidateGenerations: candidates, maxAttemptsPerCandidate: attempts });
    assert(value.decision.kind === 'verifier_execution');
    assert.equal(value.decision.maxCandidateGenerations, candidates); assert.equal(value.decision.maxAttemptsPerCandidate, attempts);
  }
  for (const value of [0, -1, 7, 1.5, '1', null, Number.MAX_SAFE_INTEGER])
    assert.throws(() => request({ maxCandidateGenerations: value }));
  for (const value of [0, -1, 5, 1.5, '1', null, Number.MAX_SAFE_INTEGER])
    assert.throws(() => request({ maxAttemptsPerCandidate: value }));
});

test('execution consent rejects missing, alternate or malformed identity/request fields before any server operation', () => {
  for (const key of Object.keys(decision())) {
    const incomplete: Record<string, unknown> = decision(); delete incomplete[key];
    assert.throws(() => clientMutation({ method: 'authorization.create', decision: incomplete }));
  }
  for (const changed of [{ verifierId: '' }, { verifierId: 'x'.repeat(129) }, { executionIdentityGrantId: '' },
    { executionIdentityGrantId: 1 }, { verifierRequestDigest: 'A'.repeat(64) }, { verifierRequestDigest: 'a'.repeat(63) },
    { verifierRequestDigest: 'not-a-content-digest' }, { verifierRequestCoreDigest: 'a'.repeat(64) }])
    assert.throws(() => request(changed));
});

test('verifier execution has no implicit purpose, target, permissions or caller authority fields', () => {
  for (const extra of [{ purpose: 'verifier' }, { target: { kind: 'guest_toolchain', toolId: 'node' } },
    { permission: 'allow' }, { permissions: ['exec'] }, { allow: true }, { principalId: 'caller' }, { runId: 'caller-selected-run' },
    { templateRef: 'a'.repeat(64) }, { operationGrantRef: 'a'.repeat(64) }]) {
    assert.throws(() => request(extra));
    assert.throws(() => clientMutation({ method: 'authorization.create', decision: decision(), ...extra }));
  }
});

test('execution creation accepts only the exact redacted active verifier_execution summary', () => {
  const value = request(), original = response(summary());
  assert.deepEqual(decodeInstalledControlResponse(original, value), original);
  for (const changed of [{ targetKind: 'execution_identity_read' }, { purpose: 'mcp_stdio' }, { purpose: 'source' },
    { targetKind: 'verifier_execution', purpose: 'dependency_install_scripts' }, { state: 'consumed', useCount: 1, rowVersion: 2,
      consumedAt: '2026-10-26T00:00:00.001Z' }, { useCount: 1 }, { rowVersion: 2 }, { permission: 'allow' },
    { target: { executionIdentityGrantId: 'not-an-exposed-target' } }, { secret: 'not-a-public-field' }])
    assert.throws(() => decodeInstalledControlResponse(response({ ...summary(), ...changed }), value));
});

test('the original identity-read request remains distinct and cannot receive an execution summary', () => {
  const original = clientMutation({ method: 'authorization.create', decision: { kind: 'execution_identity_read', purpose: 'verifier',
    target: { kind: 'guest_toolchain', guestToolchainManifestId: 'inert-installed-node', toolId: 'node' } } });
  assert(original.method === 'authorization.create' && original.decision.kind === 'execution_identity_read');
  const identityResponse = response({ ...summary(), grantId: 'inert-identity-grant', targetKind: 'execution_identity_read' });
  assert.deepEqual(decodeInstalledControlRequest(original), original);
  assert.deepEqual(decodeInstalledControlResponse(identityResponse, original), identityResponse);
  assert.throws(() => decodeInstalledControlResponse(response(summary()), original));
  assert.throws(() => decodeInstalledControlResponse(identityResponse, request()));
  assert.throws(() => clientMutation({ method: 'authorization.create', decision: { ...original.decision, permission: 'execute' } }));
});
