// Closed registry/manifest data only. No registration, signed installation,
// consent authentication, native claim, status outcome or retry permission.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeMcpRegistryRevision, type McpRecoveryContractV1 } from '../kernel/mcp.js';
import { mcpSelectionCredentialRefs } from './mcp-admission.js';
import { combineMcpToolManifest } from './mcp-registration.js';

const ref = canonicalSha256;
function registry(recovery: McpRecoveryContractV1, stdio: boolean) {
  const raw = { name: 'effect', version: 'mcp-tool-interface-v1', description: 'Owned effect', access: 'exec',
    inputSchemaRef: ref('input'), inputSchemaDigest: ref('input'), interfaceDigest: '' };
  raw.interfaceDigest = digestOmitting(raw, 'interfaceDigest');
  const core = { ...raw, version: 'mcp-tool-contract-v1', recovery }, tool = { ...core, toolContractDigest: ref(core) };
  const value = { schemaVersion: 1, format: 'cliq-mcp-registry-v1', registrationId: 'owned', registryRevision: 1, ownerPrincipalId: 'principal',
    transport: stdio ? { kind: 'stdio', executionIdentityGrantId: 'original-grant', executionIdentityConsumptionReceiptRef: ref('consumption'),
      executionIdentityConsumptionReceiptDigest: ref('consumption-data'), executable: { kind: 'runtime_bundle', runtimeBundleRef: ref('original-bundle'),
        executableId: 'original-server', executableDigest: ref('original-server-bytes'), executionPath: '/runtime/mcp-server' }, argv: [] }
      : { kind: 'streamable_http', endpointRegistrationRef: ref('endpoint'), endpointIdentityDigest: ref('endpoint-data'),
        tlsPolicyDigest: ref('tls'), credentialGrantRefs: [ref('credential')] },
    initializeDigest: ref('initialize'), capabilityDigest: ref('capabilities'), probedToolsListDigest: ref([raw]), toolsListDigest: ref([tool]),
    stateModel: 'stateless_per_call', tools: [tool], lifecycle: { launchTimeoutMs: 30_000, callTimeoutMs: 600_000, maxLaunchesPerCall: 2 },
    registrationReceiptRef: ref('original-registration'), createdAt: '2026-11-04T00:00:00.000Z' };
  return decodeMcpRegistryRevision({ ...value, manifestDigest: ref(value) });
}
const retry: McpRecoveryContractV1 = { kind: 'retry', explicitRiskConsentRef: ref('consent'), explicitRiskConsentDigest: ref('consent-data'),
  safetyAssertionRef: ref('assertion'), safetyAssertionDigest: ref('assertion-data'), idempotencyKeyInjection: { jsonPointer: '/key' } };
const reconcile: McpRecoveryContractV1 = { kind: 'reconcile', adapterRef: ref('adapter'), adapterDigest: ref('adapter-data'), profileId: 'exact-profile',
  profileDigest: ref('profile'), idempotencyKeyInjection: { jsonPointer: '/key' }, statusRequestTemplateRef: ref('template'), statusRequestTemplateDigest: ref('template-data'),
  completedPredicateRef: ref('completed'), completedPredicateDigest: ref('completed-data'), failedPredicateRef: ref('failed'), failedPredicateDigest: ref('failed-data') };

test('frozen combined tools derive the exact manual, retry or reconcile replay class from each closed original contract', () => {
  const empty = { schemaVersion: 1 as const, format: 'cliq-tool-contracts-v1' as const, entries: [], manifestDigest: '' };
  empty.manifestDigest = digestOmitting(empty, 'manifestDigest');
  for (const recovery of [{ kind: 'manual' } as const, retry, reconcile]) {
    const selected = registry(recovery, true), reference = ref(selected);
    const combined = combineMcpToolManifest(empty, [{ ref: reference, registry: selected }]);
    assert.equal(combined.entries.length, 1); assert.equal(combined.entries[0]?.replayClass, recovery.kind);
    assert.deepEqual(combined.entries[0]?.execution, { kind: 'mcp', registrationId: selected.registrationId,
      registryRevisionRef: reference, registryManifestDigest: selected.manifestDigest, serverToolName: 'effect',
      toolContractDigest: selected.tools[0]?.toolContractDigest });
    assert.deepEqual(selected.tools[0]?.recovery, recovery);
    assert.throws(() => combineMcpToolManifest(empty, [{ ref: ref('replacement'), registry: selected }]));
  }
});

test('credential selection preserves HTTP manual/retry and rejects signed stdio reconciliation on an HTTP transport', () => {
  for (const recovery of [{ kind: 'manual' } as const, retry]) {
    assert.deepEqual(mcpSelectionCredentialRefs([{ registry: registry(recovery, false) }]), [ref('credential')]);
    assert.deepEqual(mcpSelectionCredentialRefs([{ registry: registry(recovery, true) }]), []);
  }
  assert.deepEqual(mcpSelectionCredentialRefs([{ registry: registry(reconcile, true) }]), []);
  assert.throws(() => mcpSelectionCredentialRefs([{ registry: registry(reconcile, false) }]), { code: 'UNSUPPORTED_PLATFORM' });
  const http = registry(retry, false), transport = http.transport;
  if (transport.kind !== 'streamable_http') assert.fail('fixture must retain HTTP');
  assert.throws(() => mcpSelectionCredentialRefs([{ registry: { ...http, transport: { ...transport,
    credentialGrantRefs: [ref('credential'), ref('other-credential')] } } }]), { code: 'UNSUPPORTED_PLATFORM' });
});
