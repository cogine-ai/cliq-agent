// Pure closed-data regressions. These fixtures are not original registrations,
// authenticated consent, native resources, claims or terminal authority.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting } from './identity.js';
import { decodeManualAbandonAttestation, decodeManualInvocationWait, decodeMcpMutationRequest,
  decodeMcpRegistryRevision, decodeMcpResolvedTransport, mcpRegistrySummary, normalizeMcpLifecycle,
  decodeAdminOperation, decodeAdminProbeClosureEvidence, decodeAdminProbeError, decodeAdminProbePayloadCore,
  decodeMcpAdminProbeResult, decodeMcpAdminProbeTarget, decodeMcpRegistrationReceipt } from './mcp.js';

const ref = (text: string) => canonicalSha256(text);
const requestId = '01900000-0000-7000-8000-000000000001';
const at = '2026-10-31T12:00:00.000Z';
const mutation = (extra: Record<string, unknown> = {}) => {
  const core = { protocolVersion: 1, method: 'mcp.register', requestId, registrationId: 'owned-service',
    target: { kind: 'streamable_http', endpointRegistrationId: 'owned-endpoint', credentialGrantIds: [] },
    assertStatelessPerCall: true, toolRecovery: {}, ...extra };
  return { ...core, requestDigest: canonicalSha256(core) };
};
function registry() {
  const input = ref('input schema bytes'), raw = { name: 'owned-effect', version: 'mcp-tool-interface-v1',
    description: 'Owned external operation', access: 'exec', inputSchemaRef: input, inputSchemaDigest: input, interfaceDigest: '' };
  raw.interfaceDigest = digestOmitting(raw, 'interfaceDigest');
  const tool = { ...raw, version: 'mcp-tool-contract-v1', recovery: { kind: 'manual' }, toolContractDigest: '' };
  tool.toolContractDigest = digestOmitting(tool, 'toolContractDigest');
  const value = { schemaVersion: 1, format: 'cliq-mcp-registry-v1', registrationId: 'owned-service', registryRevision: 1,
    ownerPrincipalId: 'owned-principal', transport: { kind: 'streamable_http', endpointRegistrationRef: ref('endpoint'),
      endpointIdentityDigest: ref('endpoint identity'), tlsPolicyDigest: ref('TLS policy'), credentialGrantRefs: [ref('credential')] },
    initializeDigest: ref('initialize projection'), capabilityDigest: ref('capability projection'), probedToolsListDigest: canonicalSha256([raw]),
    toolsListDigest: canonicalSha256([tool]), stateModel: 'stateless_per_call', tools: [tool],
    lifecycle: { launchTimeoutMs: 30000, callTimeoutMs: 600000, maxLaunchesPerCall: 2 },
    registrationReceiptRef: ref('receipt'), manifestDigest: '', createdAt: at };
  value.manifestDigest = digestOmitting(value, 'manifestDigest');
  return value;
}

test('MCP explicit registration and copy-only refresh preserve exact public request digests', () => {
  const request = mutation(); assert.deepEqual(decodeMcpMutationRequest(request), request);
  const core = { protocolVersion: 1, method: 'mcp.refresh', requestId, registrationId: 'owned-service', expectedRegistryRevision: 3 };
  assert.deepEqual(decodeMcpMutationRequest({ ...core, requestDigest: canonicalSha256(core) }), { ...core, requestDigest: canonicalSha256(core) });
  for (const extra of [{ target: request.target }, { credentialGrantIds: [] }, { toolRecovery: {} }, { lifecycle: {} }]) {
    const changed = { ...core, ...extra }; assert.throws(() => decodeMcpMutationRequest({ ...changed, requestDigest: canonicalSha256(changed) }));
  }
  assert.throws(() => decodeMcpMutationRequest({ ...request, registrationId: 'another-service' }));
  assert.throws(() => decodeMcpMutationRequest(mutation({ assertStatelessPerCall: false })));
});

test('MCP public bounds retain all 128 non-secret arguments and 32 credential ids', () => {
  const stdio = (argv: unknown[]) => mutation({ target: { kind: 'stdio', executionIdentityGrantId: 'read-identity', argv } });
  const literal = (value: string) => ({ kind: 'non_secret_literal', value });
  assert.doesNotThrow(() => decodeMcpMutationRequest(stdio(Array.from({ length: 128 }, () => literal('x')))));
  assert.doesNotThrow(() => decodeMcpMutationRequest(stdio([literal('x'.repeat(8192)), literal('y'.repeat(8192))])));
  assert.throws(() => decodeMcpMutationRequest(stdio(Array.from({ length: 129 }, () => literal('x')))));
  assert.throws(() => decodeMcpMutationRequest(stdio([literal('x'.repeat(8193))])));
  for (const value of ['a\0b', '\ud800', 'e\u0301']) assert.throws(() => decodeMcpMutationRequest(stdio([literal(value)])));
  const credentials = Array.from({ length: 32 }, (_, index) => `credential-${index}`);
  const http = (ids: string[]) => mutation({ target: { kind: 'streamable_http', endpointRegistrationId: 'endpoint', credentialGrantIds: ids } });
  assert.doesNotThrow(() => decodeMcpMutationRequest(http(credentials)));
  assert.throws(() => decodeMcpMutationRequest(http([...credentials, 'extra'])));
  assert.throws(() => decodeMcpMutationRequest(http(['same', 'same'])));
});

test('MCP lifecycle defaults and endpoint identities cannot be widened or supplied as raw URLs', () => {
  assert.deepEqual(normalizeMcpLifecycle(), { launchTimeoutMs: 30000, callTimeoutMs: 600000, maxLaunchesPerCall: 2 });
  assert.deepEqual(normalizeMcpLifecycle({ launchTimeoutMs: 1000, callTimeoutMs: 3600000, maxLaunchesPerCall: 3 }),
    { launchTimeoutMs: 1000, callTimeoutMs: 3600000, maxLaunchesPerCall: 3 });
  for (const value of [{ launchTimeoutMs: 999 }, { launchTimeoutMs: 300001 }, { callTimeoutMs: 3600001 },
    { maxLaunchesPerCall: 0 }, { maxLaunchesPerCall: 4 }, { retry: true }]) assert.throws(() => normalizeMcpLifecycle(value));
  assert.throws(() => decodeMcpMutationRequest(mutation({ target: { kind: 'streamable_http', url: 'https://unregistered.invalid/mcp', credentialGrantIds: [] } })));
});

test('MCP recovery data requires exact risk consent and cannot turn annotations into permission', () => {
  assert.doesNotThrow(() => decodeMcpMutationRequest(mutation({ toolRecovery: { 'owned-effect': { kind: 'manual' } } })));
  assert.doesNotThrow(() => decodeMcpMutationRequest(mutation({ toolRecovery: { 'owned-effect': { kind: 'retry', acknowledgeDuplicateEffectRisk: true,
    idempotencyKeyJsonPointer: '/escaped~1key/~0name' } } })));
  for (const recovery of [{ kind: 'retry', acknowledgeDuplicateEffectRisk: false }, { kind: 'retry' },
    { kind: 'manual', readOnlyHint: true }, { kind: 'reconcile', bundledAdapterId: 'adapter', idempotencyKeyJsonPointer: 'relative' },
    { kind: 'reconcile', bundledAdapterId: 'adapter', idempotencyKeyJsonPointer: '/bad~2escape' }])
    assert.throws(() => decodeMcpMutationRequest(mutation({ toolRecovery: { 'owned-effect': recovery } })));
});

test('a complete registry rehashes its original interface and final contract without exposing transport details in summaries', () => {
  const value = registry(), decoded = decodeMcpRegistryRevision(value), summary = mcpRegistrySummary(decoded);
  assert.deepEqual(decoded, value); assert(Object.isFrozen(decoded)); assert(Object.isFrozen(decoded.tools));
  assert.deepEqual(summary, { schemaVersion: 1, registrationId: value.registrationId, registryRevision: 1, transport: 'streamable_http',
    stateModel: 'stateless_per_call', toolCount: 1, toolsListDigest: value.toolsListDigest, manifestDigest: value.manifestDigest,
    registrationReceiptRef: value.registrationReceiptRef, createdAt: at });
  for (const key of ['endpointRegistrationRef', 'credentialGrantRefs', 'argv', 'ownerPrincipalId']) assert(!Object.hasOwn(summary, key));
});

test('registry omission digests cannot conceal schema, recovery, ordering or original discovery changes', () => {
  const mutations: Array<(value: any) => void> = [
    value => { value.tools[0].inputSchemaDigest = ref('different'); },
    value => { value.tools[0].recovery = { kind: 'retry' }; },
    value => { value.tools[0].access = 'read'; },
    value => { value.tools[0].outputSchemaRef = ref('incomplete output'); },
    value => { value.tools[0].description = 'replaced original description'; },
    value => { value.tools.push(value.tools[0]); },
    value => { value.probedToolsListDigest = ref('replaced original discovery'); },
    value => { value.transport.cookieJar = true; },
    value => { value.stateModel = 'persistent_session'; },
  ];
  for (const mutate of mutations) {
    const value = registry(); mutate(value); value.manifestDigest = digestOmitting(value, 'manifestDigest');
    assert.throws(() => decodeMcpRegistryRevision(value));
  }
});

test('retained stdio data forbids host paths, mixed executable identities and credential-bearing argv', () => {
  const value = { kind: 'stdio', executionIdentityGrantId: 'read-identity', executionIdentityConsumptionReceiptRef: ref('receipt'),
    executionIdentityConsumptionReceiptDigest: ref('receipt digest'), executable: { kind: 'guest_toolchain', toolchainManifestRef: ref('guest'),
      toolId: 'node', executionPath: '/usr/bin/node', executableDigest: ref('executable') }, argv: [{ kind: 'non_secret_literal', value: '--version' }] };
  assert.deepEqual(decodeMcpResolvedTransport(value), value);
  for (const executable of [{ ...value.executable, executionPath: '/usr/../bin/node' }, { ...value.executable, kind: 'host' },
    { ...value.executable, runtimeBundleRef: ref('mixed') }]) assert.throws(() => decodeMcpResolvedTransport({ ...value, executable }));
  assert.throws(() => decodeMcpResolvedTransport({ ...value, argv: [{ kind: 'secret', value: 'never a secret field' }] }));
});

test('manual-only wait rejects worker/publication/status-probe substitution and any probe nonce', () => {
  const value = { schemaVersion: 1, kind: 'reconciliation', runId: 'owned-run', createdFromRevision: 7, createdAt: at,
    frontierRef: ref('original frontier'), subject: { kind: 'invocation', recovery: 'manual', opKind: 'mcp', opId: 'original-op', attempt: 0 },
    probeState: { phase: 'manual_only', automaticProbeCount: 0, userProbeCount: 0 } };
  assert.deepEqual(decodeManualInvocationWait(value), value);
  for (const subject of [{ ...value.subject, kind: 'worker_death' }, { ...value.subject, kind: 'publication_path' },
    { ...value.subject, recovery: 'mcp_reconcile' }, { ...value.subject, opKind: 'model' }])
    assert.throws(() => decodeManualInvocationWait({ ...value, subject }));
  assert.throws(() => decodeManualInvocationWait({ ...value, probeState: { ...value.probeState, automaticProbeCount: 1 } }));
  assert.throws(() => decodeManualInvocationWait({ ...value, probeState: { ...value.probeState, probeNonceDigest: ref('nonce') } }));
});

test('manual attestation retains exact original ambiguity and risk rather than a caller-selected outcome', () => {
  const value = { schemaVersion: 1, format: 'cliq-manual-abandon-attestation-v1', principalId: 'owned-principal', channelIdentityRef: ref('channel'),
    channelIdentityDigest: ref('channel digest'), requestId, requestDigest: ref('public request'), runId: 'owned-run', waitingSubjectRef: ref('wait'),
    frontierRef: ref('frontier'), opId: 'original-op', attempt: 0, unknownJournalSeq: 9, operationRequestRef: ref('operation'),
    operationRequestDigest: ref('operation digest'), targetRef: ref('target'), targetDigest: ref('target digest'),
    ambiguityEvidenceRef: ref('ambiguity'), ambiguityEvidenceDigest: ref('ambiguity digest'),
    acknowledgedRisk: 'effect_may_have_occurred_result_will_not_be_used_and_run_will_stop', createdAt: at, attestationDigest: '' };
  value.attestationDigest = digestOmitting(value, 'attestationDigest');
  assert.deepEqual(decodeManualAbandonAttestation(value), value);
  assert.throws(() => decodeManualAbandonAttestation({ ...value, targetRef: ref('another target') }));
  for (const change of [{ acknowledgeExactRisk: true }, { acknowledgedRisk: 'effect_did_not_occur' }, { resultRef: ref('fabricated result') }]) {
    const changed = { ...value, ...change }; changed.attestationDigest = digestOmitting(changed, 'attestationDigest');
    assert.throws(() => decodeManualAbandonAttestation(changed));
  }
});

test('MCP decoders never execute proxy traps or accessors and preserve original JSON depth/node limits', () => {
  let reads = 0;
  const proxy = new Proxy(mutation(), { get() { reads++; throw new Error('must not read'); } });
  assert.throws(() => decodeMcpMutationRequest(proxy));
  const value = mutation(); Object.defineProperty(value, 'target', { enumerable: true, get() { reads++; return {}; } });
  assert.throws(() => decodeMcpMutationRequest(value)); assert.equal(reads, 0);
  assert.throws(() => decodeMcpMutationRequest(mutation({ toolRecovery: Object.fromEntries(Array.from({ length: 129 }, (_, index) => [`tool-${index}`, { kind: 'manual' }])) })));
  let nested: unknown = {};
  for (let index = 0; index < 33; index++) nested = { next: nested };
  assert.throws(() => decodeMcpMutationRequest(nested));
  assert.throws(() => decodeMcpMutationRequest({ entries: Array.from({ length: 10001 }, () => 0) }));
});

const signedData = <T extends Record<string, unknown>>(value: T, key: string): T => ({ ...value, [key]: digestOmitting(value, key) });
function adminData() {
  return { schemaVersion: 1, adminOperationId: 'data-admin', principalId: 'owned-principal', method: 'mcp.register', requestId,
    requestDigest: ref('public request'), attempt: 1, maxAttempts: 3, deadlineAt: '2026-10-31T12:00:30.000Z',
    targetRef: ref('target bytes'), targetDigest: ref('target omission digest'), probePayloadCoreRef: ref('core bytes'),
    probePayloadCoreDigest: ref('core omission digest'), supervisorInstanceId: 'data-owner', plannedContainmentRef: ref('plan bytes'),
    plannedContainmentDigest: ref('plan omission digest'), sandboxLaunchSpecRef: ref('spec bytes'), sandboxLaunchSpecDigest: ref('spec omission digest'),
    rowVersion: 1, createdAt: at };
}
const releasedData = () => ({ state: 'released', probeRequestDigest: ref('probe request'), dispatchId: 'data-dispatch',
  claimedAt: '2026-10-31T12:00:01.000Z', releasedAt: '2026-10-31T12:00:02.000Z' });

test('admin target and static recipe keep Run authority and final recovery contracts structurally absent', () => {
  const core = signedData({ schemaVersion: 1, format: 'cliq-admin-probe-payload-core-v1', probeKind: 'mcp_streamable_http',
    runtimeBundleRef: ref('bundle'), runtimeBundleManifestDigest: ref('bundle manifest'), adapterExecutableId: 'mcp-adapter',
    adapterVersion: 'v1', adapterExecutableDigest: ref('adapter bytes'), protocolRecipe: 'mcp-initialize-capabilities-tools-list-v1',
    maximumResponseBytes: 1048576, payloadCoreDigest: '' }, 'payloadCoreDigest');
  assert.deepEqual(decodeAdminProbePayloadCore(core), core);
  for (const extra of [{ dispatchId: 'not static' }, { credentialGrantRefs: [] }, { maximumResponseBytes: 1048577 }, { runId: 'not an admin owner' }])
    assert.throws(() => decodeAdminProbePayloadCore(signedData({ ...core, ...extra }, 'payloadCoreDigest')));
  const value = signedData({ schemaVersion: 1, format: 'cliq-mcp-admin-probe-target-v1', ownerPrincipalId: 'owned-principal',
    originalRequestRef: ref('original public request'), channelIdentityRef: ref('original channel'), channelIdentityDigest: ref('original channel identity'),
    registrationId: 'owned-service', method: 'mcp.register', resolvedTransport: registry().transport, assertStatelessPerCall: true,
    requestedToolRecovery: [{ toolName: 'owned-effect', recovery: { kind: 'retry', explicitRiskConsentRef: ref('consent'),
      explicitRiskConsentDigest: ref('consent omission'), safetyAssertionRef: ref('assertion'), safetyAssertionDigest: ref('assertion omission'),
      idempotencyKeyJsonPointer: '/id' } }], lifecycle: registry().lifecycle, requestCoreDigest: ref('request core'), targetDigest: '', createdAt: at }, 'targetDigest');
  assert.deepEqual(decodeMcpAdminProbeTarget(value), value);
  for (const recovery of [{ kind: 'retry', acknowledgeDuplicateEffectRisk: true }, { ...value.requestedToolRecovery[0]!.recovery,
    idempotencyKeyInjection: { jsonPointer: '/id' } }, { kind: 'reconcile', adapterRef: ref('premature selected adapter') }])
    assert.throws(() => decodeMcpAdminProbeTarget(signedData({ ...value, requestedToolRecovery: [{ toolName: 'owned-effect', recovery }] }, 'targetDigest')));
  assert.throws(() => decodeMcpAdminProbeTarget(signedData({ ...value, expectedRegistryRevision: 1 }, 'targetDigest')));
  const refresh = signedData({ ...value, method: 'mcp.refresh', expectedRegistryRevision: 1, sourceRegistryRevisionRef: ref('old immutable revision') }, 'targetDigest');
  assert.deepEqual(decodeMcpAdminProbeTarget(refresh), refresh);
  assert.throws(() => decodeMcpAdminProbeTarget(signedData({ ...value, method: 'mcp.refresh' }, 'targetDigest')));
});

test('closed admin phases retain permanent released state, immutable deadlines and exact three-attempt backoff', () => {
  const prepared = { ...adminData(), phase: 'prepared' }; assert.deepEqual(decodeAdminOperation(prepared), prepared);
  const active = { ...adminData(), phase: 'active', processContainmentRef: ref('containment'),
    leaseExpiresAt: '2026-10-31T12:00:29.000Z', probeDispatch: releasedData() };
  assert.deepEqual(decodeAdminOperation(active), active);
  const completed = { ...adminData(), phase: 'completed', processContainmentRef: ref('containment'), probeDispatch: releasedData(),
    resultRef: ref('result'), resultDigest: ref('result omission'), evidenceRef: ref('closure'), evidenceDigest: ref('closure omission'),
    controlResponseRef: ref('response'), controlResponseDigest: ref('response omission'), finishedAt: '2026-10-31T12:00:03.000Z' };
  assert.deepEqual(decodeAdminOperation(completed), completed);
  for (const changed of [{ ...prepared, runId: 'forbidden' }, { ...prepared, probeDispatch: { state: 'blocked' } },
    { ...active, leaseExpiresAt: '2026-10-31T12:00:30.001Z' }, { ...active, probeDispatch: { ...releasedData(), releasedAt: '2026-10-31T12:00:30.000Z' } },
    { ...completed, probeDispatch: { state: 'blocked' } }, { ...completed, errorRef: ref('mixed error') }, { ...completed, attempt: 4 }])
    assert.throws(() => decodeAdminOperation(changed));
  const failure = { ...adminData(), phase: 'failed', failureDisposition: 'retryable_recovery', evidenceRef: ref('closure'),
    evidenceDigest: ref('closure omission'), errorRef: ref('error'), errorDigest: ref('error omission'), finishedAt: '2026-10-31T12:00:03.000Z',
    retryNotBeforeAt: '2026-10-31T12:00:04.000Z' };
  assert.deepEqual(decodeAdminOperation(failure), failure);
  assert.doesNotThrow(() => decodeAdminOperation({ ...failure, attempt: 2, retryNotBeforeAt: '2026-10-31T12:00:08.000Z' }));
  for (const extra of [{ attempt: 3 }, { retryNotBeforeAt: '2026-10-31T12:00:03.999Z' }, { controlResponseRef: ref('premature public response') },
    { processContainmentRef: ref('without original dispatch state') }]) assert.throws(() => decodeAdminOperation({ ...failure, ...extra }));
});

test('admin result and closure bytes cannot substitute an early final contract, no-spawn fact or deterministic error', () => {
  const { recovery: _recovery, toolContractDigest: _contract, ...raw } = registry().tools[0]!;
  const normalizedTools = [{ ...raw, version: 'mcp-tool-interface-v1' }];
  const result = signedData({ schemaVersion: 1, format: 'cliq-mcp-admin-probe-result-v1', adminOperationId: 'data-admin', attempt: 1,
    dispatchId: 'data-dispatch', probeRequestDigest: ref('probe request'), targetRef: ref('target'), targetDigest: ref('target omission'),
    probePayloadCoreRef: ref('core'), probePayloadCoreDigest: ref('core omission'), processContainmentRef: ref('containment'),
    initializeResponseRef: ref('genuine init bytes'), initializeResponseDigest: ref('genuine init bytes'),
    capabilityResponseRef: ref('genuine init bytes'), capabilityResponseDigest: ref('genuine init bytes'),
    toolsListResponseRef: ref('genuine list bytes'), toolsListResponseDigest: ref('genuine list bytes'),
    initializeDigest: ref('init projection'), capabilityDigest: ref('capability projection'), normalizedTools,
    probedToolsListDigest: canonicalSha256(normalizedTools), completedAt: at, resultDigest: '' }, 'resultDigest');
  assert.deepEqual(decodeMcpAdminProbeResult(result), result);
  assert.throws(() => decodeMcpAdminProbeResult(signedData({ ...result, normalizedTools: registry().tools }, 'resultDigest')));
  const closure = signedData({ schemaVersion: 1, format: 'cliq-admin-probe-closure-evidence-v1', adminOperationId: 'data-admin', attempt: 1,
    targetRef: ref('target'), targetDigest: ref('target omission'), plannedContainmentRef: ref('plan'), plannedContainmentDigest: ref('plan omission'),
    sandboxLaunchSpecRef: ref('spec'), sandboxLaunchSpecDigest: ref('spec omission'), inspectorIdentityRef: ref('inspector'),
    inspectorIdentityDigest: ref('inspector omission'), observedAt: at, closureKind: 'no_spawn', noSpawnEvidenceRef: ref('named evidence'),
    noSpawnEvidenceDigest: ref('named omission'), evidenceDigest: '' }, 'evidenceDigest');
  assert.deepEqual(decodeAdminProbeClosureEvidence(closure), closure);
  for (const extra of [{ processContainmentRef: ref('cannot rename spawn') }, { dispatchId: 'cannot claim no I/O' }, { deathEvidenceRef: ref('mixed proof') },
    { nativeCleanupDigest: ref('orphan cleanup digest') }, { nativeLifecycleRef: ref('partial original birth') },
    { nativeCleanupRef: ref('cleanup'), nativeCleanupDigest: ref('cleanup') }])
    assert.throws(() => decodeAdminProbeClosureEvidence(signedData({ ...closure, ...extra }, 'evidenceDigest')));
  const error = signedData({ schemaVersion: 1, format: 'cliq-admin-probe-error-v1', adminOperationId: 'data-admin', attempt: 1,
    targetRef: ref('target'), targetDigest: ref('target omission'), closureEvidenceRef: ref('closure'), closureEvidenceDigest: ref('closure omission'),
    diagnosticRef: ref('redacted diagnostic'), diagnosticDigest: ref('redacted diagnostic'), createdAt: at, errorDigest: '',
    code: 'transport_failed_no_effect', deterministicRejection: false }, 'errorDigest');
  assert.deepEqual(decodeAdminProbeError(error), error);
  for (const extra of [{ deterministicRejection: true }, { code: 'timeout_is_death' }, { nativeClosed: true }])
    assert.throws(() => decodeAdminProbeError(signedData({ ...error, ...extra }, 'errorDigest')));
});

test('receipt data has an acyclic registry-core digest and never includes later response or registry manifest', () => {
  const value = signedData({ schemaVersion: 1, format: 'cliq-mcp-registration-receipt-v1', registrationId: 'owned-service', registryRevision: 1,
    ownerPrincipalId: 'owned-principal', requestDigest: ref('public request'), adminOperationId: 'data-admin', adminAttempt: 1,
    dispatchId: 'data-dispatch', probeRequestDigest: ref('probe request'), adminProbeTargetRef: ref('target'), adminProbeTargetDigest: ref('target omission'),
    probeResultRef: ref('result'), probeResultDigest: ref('result omission'), probeClosureEvidenceRef: ref('closure'),
    probeClosureEvidenceDigest: ref('closure omission'), initializeDigest: ref('init'), capabilityDigest: ref('capabilities'),
    probedToolsListDigest: ref('raw tools'), toolsListDigest: ref('final tools'), registryCoreDigest: ref('receipt-free core'),
    createdAt: at, receiptDigest: '' }, 'receiptDigest');
  assert.deepEqual(decodeMcpRegistrationReceipt(value), value);
  for (const extra of [{ manifestDigest: ref('hash cycle') }, { controlResponseRef: ref('hash cycle') }, { registryRevision: 0 }])
    assert.throws(() => decodeMcpRegistrationReceipt(signedData({ ...value, ...extra }, 'receiptDigest')));
});
