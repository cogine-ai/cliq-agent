import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { identityHash } from './identity.js';
import { decodeMcpRecoveryAdapterManifest, decodeMcpRecoveryPredicate, decodeMcpRecoveryProfile,
  decodeMcpRetryRiskConsent, decodeMcpRetrySafetyAssertion, evaluateMcpRecoveryPredicates,
  injectMcpIdempotencyKey, mcpProfileSigningIdentityDigest, mcpRetryRequestFromAssertion,
  mcpServerExecutionIdentityDigest } from './mcp-recovery.js';
import type { McpResolvedTransportV1 } from './mcp.js';

const ref = (name: string) => canonicalSha256(name);
const stamped = <T extends object>(core: T, member: string) => ({ ...core, [member]: canonicalSha256(core) });
const transport = (runtimeBundleRef: string, argv = 'fixed'): Extract<McpResolvedTransportV1, {kind: 'stdio'}> => ({ kind: 'stdio',
  executionIdentityGrantId: 'original-grant', executionIdentityConsumptionReceiptRef: ref('consumption'), executionIdentityConsumptionReceiptDigest: ref('consumption-data'),
  executable: { kind: 'runtime_bundle', runtimeBundleRef, executableId: 'fixed-server', executionPath: '/runtime/mcp-server', executableDigest: ref('server') },
  argv: [{ kind: 'non_secret_literal', value: argv }] });
const predicate = (expression: unknown) => stamped({ schemaVersion: 1, format: 'cliq-mcp-recovery-predicate-v1', expression }, 'predicateDigest');
const profile = () => stamped({ profileId: 'p1', profileSigningIdentityDigest: mcpProfileSigningIdentityDigest(transport(ref('outer'))),
  serverToolName: 'effect', initializeDigest: ref('initialize'), capabilityDigest: ref('capability'), probedToolsListDigest: ref('list'), effectToolInterfaceDigest: ref('effect'),
  statusOperationName: 'status', statusOperationSemantics: 'signed_read_only_status_query', statusToolInterfaceDigest: ref('status'),
  statusInputSchemaDigest: ref('input-schema'), statusOutputSchemaDigest: ref('output-schema'), staticArgumentsRef: ref('static'), staticArgumentsDigest: ref('static'),
  completedPredicateRef: ref('completed'), completedPredicateDigest: ref('completed-data'), failedPredicateRef: ref('failed'), failedPredicateDigest: ref('failed-data') }, 'profileDigest');

test('MCP retry consent preserves exact duplicate risk, original request/channel and closed fields', () => {
  const request = { kind: 'retry', acknowledgeDuplicateEffectRisk: true, idempotencyKeyJsonPointer: '/request/key' };
  const identity = { ownerPrincipalId: 'principal', registrationId: 'registration', serverToolName: 'effect', recoveryRequestDigest: canonicalSha256(request) };
  const consentCore = { schemaVersion: 1, format: 'cliq-mcp-retry-risk-consent-v1', ...identity,
    acknowledgedRisk: 'prior_attempt_may_have_succeeded_and_retry_may_duplicate_effect', channelIdentityRef: ref('channel'),
    channelIdentityDigest: ref('channel-data'), createdAt: '2026-11-03T00:00:00.000Z' };
  const assertionCore = { schemaVersion: 1, format: 'cliq-mcp-retry-safety-assertion-v1', ...identity,
    assertion: 'no_server_safety_claim_duplicate_effect_remains_possible', idempotencyKeyJsonPointer: '/request/key' };
  const consent = decodeMcpRetryRiskConsent(stamped(consentCore, 'consentDigest'));
  const assertion = decodeMcpRetrySafetyAssertion(stamped(assertionCore, 'assertionDigest'));
  assert.equal(consent.recoveryRequestDigest, assertion.recoveryRequestDigest);
  assert.deepEqual(mcpRetryRequestFromAssertion(assertion), request);
  assert.throws(() => decodeMcpRetryRiskConsent(stamped({ ...consentCore, acknowledgedRisk: 'server_is_idempotent' }, 'consentDigest')));
  assert.throws(() => decodeMcpRetrySafetyAssertion(stamped({ ...assertionCore, retrySafe: true }, 'assertionDigest')));
  assert.throws(() => mcpRetryRequestFromAssertion(decodeMcpRetrySafetyAssertion(stamped({ ...assertionCore, recoveryRequestDigest: ref('another-request') }, 'assertionDigest'))));
});
test('MCP profile signing identity has no outer Bundle cycle while full execution identity retains it', () => {
  const before = transport(ref('before')), after = transport(ref('after'));
  assert.equal(mcpProfileSigningIdentityDigest(before), mcpProfileSigningIdentityDigest(after));
  assert.notEqual(mcpServerExecutionIdentityDigest(before), mcpServerExecutionIdentityDigest(after));
  assert.notEqual(mcpProfileSigningIdentityDigest(before), mcpProfileSigningIdentityDigest(transport(ref('before'), 'changed')));
  assert.notEqual(mcpProfileSigningIdentityDigest(before), mcpProfileSigningIdentityDigest({ ...before,
    executable: { ...before.executable, executableDigest: ref('replacement') } }));
  const checked = decodeMcpRecoveryProfile(profile());
  assert.equal(checked.profileSigningIdentityDigest, mcpProfileSigningIdentityDigest(before));
  const { profileSigningIdentityDigest: _removed, profileDigest: _digest, ...rest } = profile();
  assert.throws(() => decodeMcpRecoveryProfile(stamped({ ...rest, serverExecutionIdentityDigest: ref('old-cyclic-field') }, 'profileDigest')));
});
test('MCP status profiles require a distinct operation, distinct predicates and byte-sorted unique tuples', () => {
  const { profileDigest: _digest, ...core } = profile();
  assert.throws(() => decodeMcpRecoveryProfile(stamped({ ...core, statusOperationName: 'effect' }, 'profileDigest')));
  assert.throws(() => decodeMcpRecoveryProfile(stamped({ ...core, failedPredicateDigest: core.completedPredicateDigest }, 'profileDigest')));
  const manifest = (profiles: unknown[]) => {
    const core = { schemaVersion: 1, format: 'cliq-mcp-recovery-adapter-v1', adapterId: 'adapter', entryId: 'recovery-executable', version: '1',
      executableDigest: ref('adapter'), protocol: 'cliq-mcp-reconcile-v1', profiles, publisherKeyId: 'release-key' };
    return { ...core, adapterDigest: canonicalSha256(core), signature: `${'A'.repeat(86)}==` };
  };
  assert.equal(decodeMcpRecoveryAdapterManifest(manifest([profile()])).profiles.length, 1);
  assert.throws(() => decodeMcpRecoveryAdapterManifest(manifest([profile(), stamped({ ...core, profileId: 'p2' }, 'profileDigest')])));
  assert.throws(() => decodeMcpRecoveryAdapterManifest({ ...manifest([profile()]), runtimeBundleRef: ref('cycle') }));
});
test('MCP predicate IR is bounded, closed, scalar and never treats ambiguous/schema-invalid status as resolved', () => {
  const completed = predicate({ op: 'equals', jsonPointer: '/state', value: 'complete' }), failed = predicate({ op: 'equals', jsonPointer: '/state', value: 'failed' });
  assert.equal(evaluateMcpRecoveryPredicates({ completed, failed, response: { state: 'complete' }, schemaValid: true }), 'completed');
  assert.equal(evaluateMcpRecoveryPredicates({ completed, failed, response: { state: 'failed' }, schemaValid: true }), 'failed');
  assert.equal(evaluateMcpRecoveryPredicates({ completed, failed, response: { state: 'waiting' }, schemaValid: true }), 'unresolved');
  assert.equal(evaluateMcpRecoveryPredicates({ completed, failed, response: { state: 'complete' }, schemaValid: false }), 'unresolved');
  assert.equal(evaluateMcpRecoveryPredicates({ completed, failed: predicate({ op: 'exists', jsonPointer: '/state' }), response: { state: 'complete' }, schemaValid: true }), 'unresolved');
  for (const expression of [{ op: 'script', code: 'return true' }, { op: 'and', operands: [] }, { op: 'equals', jsonPointer: '/', value: 0.5 },
    { op: 'exists', jsonPointer: '/~2' }, { op: 'or', operands: Array.from({ length: 64 }, () => ({ op: 'exists', jsonPointer: '' })) }])
    assert.throws(() => decodeMcpRecoveryPredicate(predicate(expression)));
  let expression: unknown = { op: 'exists', jsonPointer: '' };
  for (let count = 0; count < 8; count++) expression = { op: 'and', operands: [expression] };
  assert.throws(() => decodeMcpRecoveryPredicate(predicate(expression)));
});
test('MCP stable-key injection copies only the authorized leaf and never appends, creates parents or follows inherited properties', () => {
  const original = { request: { key: 'model-value', untouched: true }, array: [{ key: '' }] }, key = identityHash('cliq-mcp-tool-idempotency-v1', 'run', 'op', ref('registry'), 'effect');
  assert.deepEqual(injectMcpIdempotencyKey(original, '/request/key', key), { request: { key, untouched: true }, array: [{ key: '' }] });
  assert.equal(original.request.key, 'model-value');
  for (const invalid of [ref('an-artifact-is-not-a-call-id'), '', 'A'.repeat(42), 'A'.repeat(44), `${'A'.repeat(42)}B`, `${key}=`])
    assert.throws(() => injectMcpIdempotencyKey(original, '/request/key', invalid));
  assert.equal((injectMcpIdempotencyKey(original, '/array/0/key', key).array as Array<{key: string}>)[0]?.key, key);
  for (const pointer of ['', '/absent/key', '/array/-', '/array/01', '/toString/key']) assert.throws(() => injectMcpIdempotencyKey(original, pointer, key));
  const escaped = injectMcpIdempotencyKey({ 'a/b': { '~key': '' } }, '/a~1b/~0key', key);
  assert.deepEqual(escaped, { 'a/b': { '~key': key } });
  const own = injectMcpIdempotencyKey({}, '/__proto__', key);
  assert.equal(Object.hasOwn(own, '__proto__'), true); assert.equal(Object.getPrototypeOf(own), Object.prototype);
  assert.equal(Object.getPrototypeOf({}), Object.prototype);
});
