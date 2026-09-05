import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { RunAssemblyV1 } from '../kernel/types.js';
import { digestOmitting } from '../kernel/identity.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { validateRunAssembly } from './run-assembly.js';
import { ref, reseal, testFixture, normalInput } from './testing/fixtures.js';

test('validateRunAssembly closes model authority across capability, pricing, tools, retry, and context', () => {
  const input = testFixture();
  const result = validateRunAssembly(input);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  const prepared = result.model.prepare(normalInput(input));
  assert.equal(prepared.request.provider, 'openai');
  assert.equal(prepared.request.negotiatedMode, 'native-tools');
  assert.equal(prepared.request.maximumOutputTokens, 4096);
  assert.equal(prepared.request.reservation.inputTokens, 32768);
});

test('validateRunAssembly rejects a one-field capability or pricing substitution after a valid reseal', () => {
  const capability = testFixture();
  capability.assembly.provider.negotiation.mode = 'text-only';
  capability.assembly.provider.negotiation.exposedToolNames = [];
  reseal(capability);
  assert.deepEqual(validateRunAssembly(capability), {
    ok: false,
    code: 'MODEL_CAPABILITY_UNKNOWN',
    reason: 'capability_authority_invalid'
  });

  const pricing = testFixture();
  assert.equal(pricing.assembly.provider.pricing.kind, 'trusted_price_table');
  if (pricing.assembly.provider.pricing.kind !== 'trusted_price_table') return;
  pricing.assembly.provider.pricing.priceTableDigest = ref(99);
  reseal(pricing);
  assert.deepEqual(validateRunAssembly(pricing), {
    ok: false,
    code: 'MODEL_COST_UNKNOWN',
    reason: 'pricing_authority_invalid'
  });
});

test('validateRunAssembly enforces exact credential union and tool/retry authority', () => {
  const credentials = testFixture();
  credentials.runSpecCredentialGrantRefs.pop();
  assert.deepEqual(validateRunAssembly(credentials), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'credential_union_mismatch'
  });

  const tools = testFixture();
  tools.assembly.provider.negotiation.exposedToolNames = ['other'];
  reseal(tools);
  assert.deepEqual(validateRunAssembly(tools), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'tool_authority_mismatch'
  });

  const retry = testFixture();
  retry.assembly.retry.model.postAttemptDelaysMs = [500, 2000];
  retry.assembly.retry.model.maxZeroByteTransportRetriesPerAttempt = 1 as 0;
  reseal(retry);
  assert.deepEqual(validateRunAssembly(retry), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'retry_policy_invalid'
  });

  const toolRetry = testFixture();
  toolRetry.assembly.retry.tools[0]!.maxDispatchedAttempts = 2 as 3;
  reseal(toolRetry);
  assert.deepEqual(validateRunAssembly(toolRetry), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'retry_policy_invalid'
  });
});

test('validateRunAssembly enforces context equations, transitive references, and signed adapter identity', () => {
  const context = testFixture();
  context.assembly.context.triggerThresholdTokens += 1;
  reseal(context);
  assert.deepEqual(validateRunAssembly(context), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'context_equations_invalid'
  });

  const reference = testFixture();
  reference.material.verifyReference = ({ kind }) => kind !== 'system_prompt';
  assert.deepEqual(validateRunAssembly(reference), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'assembly_reference_invalid'
  });

  const adapter = testFixture();
  adapter.material.verifyProviderAdapter = () => false;
  assert.deepEqual(validateRunAssembly(adapter), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'provider_authority_mismatch'
  });

  const endpoint = testFixture();
  endpoint.assembly.provider.endpoint = {
    ...endpoint.assembly.provider.endpoint,
    endpointRegistrationRef: ref(88)
  } as Extract<RunAssemblyV1['provider']['endpoint'], { kind: 'registered' }>;
  reseal(endpoint);
  assert.deepEqual(validateRunAssembly(endpoint), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'provider_authority_mismatch'
  });
});

test('validateRunAssembly requires a verified guest toolchain for macOS and paired guest identities on either backend', () => {
  for (const [backend, guestRef, guestDigest, accepted] of [
    ['macos_vm', undefined, undefined, false],
    ['macos_vm', ref(80), undefined, false],
    ['macos_vm', undefined, ref(81), false],
    ['macos_vm', ref(80), ref(81), true],
    ['linux_namespace', undefined, undefined, true],
    ['linux_namespace', ref(80), undefined, false],
    ['linux_namespace', undefined, ref(81), false],
    ['linux_namespace', ref(80), ref(81), true]
  ] as const) {
    const input = testFixture();
    input.assembly.runtime.sandboxBackend = backend;
    if (guestRef !== undefined) input.assembly.runtime.guestToolchainManifestRef = guestRef;
    if (guestDigest !== undefined) input.assembly.runtime.guestToolchainManifestDigest = guestDigest;
    reseal(input);
    const label = `${backend}, guestRef=${guestRef}, guestDigest=${guestDigest}`;
    const result = validateRunAssembly(input);
    if (!accepted) {
      assert.deepEqual(result, { ok: false, code: 'RUN_ASSEMBLY_INVALID', reason: 'assembly_schema_invalid' }, label);
      continue;
    }
    assert.equal(result.ok, true, label);
    if (guestRef !== undefined) {
      input.material.verifyReference = ({ kind }) => kind !== 'guest_toolchain_manifest';
      assert.deepEqual(
        validateRunAssembly(input),
        { ok: false, code: 'RUN_ASSEMBLY_INVALID', reason: 'assembly_reference_invalid' },
        label
      );
    }
  }
});

test('validateRunAssembly rejects unknown fields and stale artifact identity', () => {
  const extended = testFixture();
  (extended.assembly as RunAssemblyV1 & { hidden?: boolean }).hidden = true;
  assert.deepEqual(validateRunAssembly(extended), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'assembly_schema_invalid'
  });

  const stale = testFixture();
  stale.assembly.createdAt = '2026-09-04T00:00:00.000Z';
  assert.deepEqual(validateRunAssembly(stale), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'assembly_digest_mismatch'
  });

  const unsortedServers = testFixture();
  unsortedServers.assembly.mcpServers = [
    { registrationId: 'server-b', registryRevisionRef: ref(50), registryRevision: 1, manifestDigest: ref(51) },
    { registrationId: 'server-a', registryRevisionRef: ref(52), registryRevision: 1, manifestDigest: ref(53) }
  ];
  reseal(unsortedServers);
  assert.deepEqual(validateRunAssembly(unsortedServers), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'assembly_schema_invalid'
  });
});

test('verified source and provenance still have to name the same retained bundle and local service', () => {
  const remote = testFixture();
  remote.assembly.runtime.runtimeBundleRef = ref(999);
  reseal(remote);
  assert.deepEqual(validateRunAssembly(remote), {
    ok: false,
    code: 'MODEL_CAPABILITY_UNKNOWN',
    reason: 'capability_authority_invalid'
  });
  const local = testFixture('ollama');
  const material = local.material.localProvenance!;
  material.value.serviceSpecRef = ref(999);
  material.value.provenanceDigest = digestOmitting(material.value, 'provenanceDigest');
  material.ref = planCanonicalArtifact(material.value, material.value.format).ref;
  assert.equal(local.assembly.provider.endpoint.kind, 'local_zero_cost');
  if (local.assembly.provider.endpoint.kind !== 'local_zero_cost') return;
  local.assembly.provider.endpoint.localProvenanceRef = material.ref;
  local.assembly.provider.pricing.provenanceRef = material.ref;
  local.material.verifyProviderEndpoint = () => true;
  reseal(local);
  assert.deepEqual(validateRunAssembly(local), {
    ok: false,
    code: 'RUN_ASSEMBLY_INVALID',
    reason: 'provider_authority_mismatch'
  });
});

test('managed-local provenance must bind the exact admitted capability evidence after resealing', () => {
  for (const field of ['capabilityEvidenceRef', 'capabilityDigest'] as const) {
    const input = testFixture('ollama');
    assert.equal(validateRunAssembly(input).ok, true);
    const material = input.material.localProvenance!;
    material.value[field] = ref(999);
    material.value.provenanceDigest = digestOmitting(material.value, 'provenanceDigest');
    material.ref = planCanonicalArtifact(material.value, material.value.format).ref;
    assert.equal(input.assembly.provider.endpoint.kind, 'local_zero_cost');
    input.assembly.provider.endpoint.localProvenanceRef = material.ref;
    input.assembly.provider.pricing.provenanceRef = material.ref;
    input.material.verifyProviderEndpoint = ({ endpoint }) =>
      endpoint.kind === 'local_zero_cost' && endpoint.localProvenanceRef === material.ref;
    reseal(input);
    assert.deepEqual(
      validateRunAssembly(input),
      { ok: false, code: 'RUN_ASSEMBLY_INVALID', reason: 'provider_authority_mismatch' },
      field
    );
  }
});
