import { canonicalJsonBytes, normalizeCanonicalText } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import type { ArtifactRef, ReplayClass, RunAssemblyV1 } from '../kernel/types.js';
import {
  negotiateModelCapabilities,
  type ModelCapabilityEvidenceV1,
  type NormalizedModelCapabilityClaimsV1
} from './capabilities.js';
import {
  validateModelPricing,
  type LocalZeroCostProvenanceV1,
  createModelRequestReservation,
  type ModelPriceTableV1
} from './pricing.js';
import {
  compactionEnvelopeEstimate,
  MISSING_TOOL_NAME,
  type CompactionPromptEnvelopeMaterial,
  type ModelAttemptAuthority,
  type NormalPromptProjectionV1
} from './request.js';
import { immutableSnapshot } from './immutable.js';
import { createModelSession, type ModelSession } from './model-session.js';

export type RunAssemblyReferenceKind =
  | 'mcp_registry_revision'
  | 'tool_contract_manifest'
  | 'system_prompt'
  | 'workspace_instructions'
  | 'skill_manifest'
  | 'runtime_bundle'
  | 'guest_toolchain_manifest'
  | 'compaction_prompt_envelope';

export type RunAssemblyToolAuthority = Omit<NormalPromptProjectionV1['tools'][number], 'index'> & {
  replayClass: ReplayClass;
};

export type RunAssemblyValidationMaterial = {
  capabilityEvidence: { ref: ArtifactRef; value: ModelCapabilityEvidenceV1 };
  resolveVerifiedCapabilityClaims: (
    source: ModelCapabilityEvidenceV1['source']
  ) => NormalizedModelCapabilityClaimsV1 | null;
  localProvenance?: { ref: ArtifactRef; value: LocalZeroCostProvenanceV1 };
  priceTable?: { ref: ArtifactRef; value: ModelPriceTableV1 };
  verifyLocalZeroCostAuthority: (provenance: LocalZeroCostProvenanceV1) => boolean;
  resolvePriceTableAuthority: (table: ModelPriceTableV1) => ArtifactRef | null;
  compactionEnvelope: CompactionPromptEnvelopeMaterial;
  /** Resolve the exact signed manifest and schema closure, not independent entries beside a verified root. */
  resolveVerifiedTools: (reference: RunAssemblyV1['tools']) => RunAssemblyToolAuthority[] | null;
  additionalCredentialGrantRefs: ArtifactRef[];
  verifyReference: (reference: { kind: RunAssemblyReferenceKind; ref: ArtifactRef; digest: string }) => boolean;
  verifyProviderAdapter: (input: {
    adapter: RunAssemblyV1['provider']['adapter'];
    runtimeBundleRef: ArtifactRef;
    runtimeBundleManifestDigest: string;
  }) => boolean;
  verifyProviderEndpoint: (input: {
    provider: RunAssemblyV1['provider']['name'];
    model: string;
    endpoint: RunAssemblyV1['provider']['endpoint'];
    credentialGrantRefs: ArtifactRef[];
    capabilitySource: ModelCapabilityEvidenceV1['source'];
  }) => boolean;
};

export type ValidateRunAssemblyInput = {
  assemblyRef: ArtifactRef;
  assembly: RunAssemblyV1;
  admittedAt: string;
  deadlineAt: string;
  maxRunCostMicros: number;
  runSpecCredentialGrantRefs: ArtifactRef[];
  material: RunAssemblyValidationMaterial;
};

export type RunAssemblyValidationFailure =
  | 'assembly_schema_invalid'
  | 'assembly_digest_mismatch'
  | 'assembly_reference_invalid'
  | 'provider_authority_mismatch'
  | 'capability_authority_invalid'
  | 'pricing_authority_invalid'
  | 'credential_union_mismatch'
  | 'tool_authority_mismatch'
  | 'retry_policy_invalid'
  | 'context_equations_invalid'
  | 'runtime_authority_invalid';

export type ValidateRunAssemblyResult =
  | { ok: true; model: ModelSession }
  | {
      ok: false;
      code: 'RUN_ASSEMBLY_INVALID' | 'MODEL_CAPABILITY_UNKNOWN' | 'MODEL_COST_UNKNOWN';
      reason: RunAssemblyValidationFailure;
    };

const ASSEMBLY_KEYS = [
  'schemaVersion',
  'format',
  'provider',
  'mcpServers',
  'tools',
  'instructions',
  'runtime',
  'retry',
  'context',
  'assemblyDigest',
  'createdAt'
] as const;
const PROVIDER_KEYS = [
  'name',
  'model',
  'endpoint',
  'credentialGrantRefs',
  'adapter',
  'negotiation',
  'pricing'
] as const;
const LOCAL_ENDPOINT_KEYS = ['kind', 'identityDigest', 'localProvenanceRef'] as const;
const REGISTERED_ENDPOINT_KEYS = [
  'kind',
  'registrationKind',
  'endpointRegistrationRef',
  'endpointIdentityDigest',
  'tlsPolicyDigest'
] as const;
const ADAPTER_KEYS = ['adapterId', 'version', 'codeDigest'] as const;
const NEGOTIATION_KEYS = [
  'mode',
  'capabilityEvidenceRef',
  'capabilityDigest',
  'nativeToolCalling',
  'streaming',
  'trustedUsageEvidence',
  'contextLimitTokens',
  'maxOutputTokens',
  'exposedToolNames'
] as const;
const MCP_KEYS = ['registrationId', 'registryRevisionRef', 'registryRevision', 'manifestDigest'] as const;
const TOOLS_KEYS = ['manifestRef', 'manifestDigest'] as const;
const INSTRUCTION_KEYS = [
  'systemPromptRef',
  'systemPromptDigest',
  'workspaceInstructionsRef',
  'workspaceInstructionsDigest',
  'skills'
] as const;
const SKILL_KEYS = ['skillId', 'manifestRef', 'manifestDigest'] as const;
const RUNTIME_REQUIRED_KEYS = [
  'runtimeBundleRef',
  'runtimeBundleManifestDigest',
  'workerExecutableId',
  'workerExecutableDigest',
  'sandboxBackend'
] as const;
const RUNTIME_GUEST_KEYS = ['guestToolchainManifestRef', 'guestToolchainManifestDigest'] as const;
const RETRY_KEYS = ['model', 'tools'] as const;
const MODEL_RETRY_KEYS = [
  'maxDispatchedAttempts',
  'maxZeroByteTransportRetriesPerAttempt',
  'postAttemptDelaysMs'
] as const;
const TOOL_RETRY_KEYS = ['toolName', 'replayClass', 'maxDispatchedAttempts', 'postAttemptDelaysMs'] as const;
const TOOL_AUTHORITY_ENTRY_KEYS = [
  'name',
  'replayClass',
  'description',
  'inputSchemaRef',
  'inputSchemaDigest',
  'inputSchema'
] as const;
const CONTEXT_KEYS = [
  'compactionPromptEnvelopeRef',
  'compactionPromptEnvelopeDigest',
  'contextLimitTokens',
  'reservedOutputTokens',
  'hardPromptTokens',
  'triggerThresholdTokens',
  'protectedRecentTokens',
  'summaryTokenCap',
  'compactionEnvelopeTokens',
  'sourceInputTokenCap',
  'maxSummaryBytes'
] as const;
const PROVIDERS = new Set(['openai', 'anthropic', 'openrouter', 'openai-compatible', 'zhipu', 'ollama']);
const MODES = new Set(['native-tools', 'text-only']);
const REPLAY_CLASSES = new Set<ReplayClass>(['retry', 'workspace-rollback-retry', 'reconcile', 'manual']);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = []
): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

function isNonempty(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > 512) return false;
  try {
    return normalizeCanonicalText(value) === value;
  } catch {
    return false;
  }
}

function isSafeInteger(value: unknown, minimum = 0): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum;
}

function isRef(value: unknown): value is ArtifactRef {
  if (typeof value !== 'string') return false;
  try {
    assertArtifactRef(value);
    return true;
  } catch {
    return false;
  }
}

function sameJcs(left: unknown, right: unknown): boolean {
  try {
    return canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
  } catch {
    return false;
  }
}

function strictlySortedUniqueRefs(values: unknown): values is ArtifactRef[] {
  return (
    Array.isArray(values) &&
    values.every(isRef) &&
    values.every((value, index) => index === 0 || value > values[index - 1]!)
  );
}

function sameStringSequence(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function byteCompare(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function endpointIdentityDigest(assembly: RunAssemblyV1): string {
  return assembly.provider.endpoint.kind === 'local_zero_cost'
    ? assembly.provider.endpoint.identityDigest
    : assembly.provider.endpoint.endpointIdentityDigest;
}

function fail(
  reason: RunAssemblyValidationFailure,
  code: 'RUN_ASSEMBLY_INVALID' | 'MODEL_CAPABILITY_UNKNOWN' | 'MODEL_COST_UNKNOWN' = 'RUN_ASSEMBLY_INVALID'
): ValidateRunAssemblyResult {
  return { ok: false, code, reason };
}

function validateClosedShape(assembly: RunAssemblyV1): boolean {
  if (!isRecord(assembly) || !exactKeys(assembly, ASSEMBLY_KEYS)) return false;
  if (assembly.schemaVersion !== 1 || assembly.format !== 'cliq-run-assembly-v1') return false;
  if (!isRecord(assembly.provider) || !exactKeys(assembly.provider, PROVIDER_KEYS)) return false;
  const provider = assembly.provider;
  if (!PROVIDERS.has(provider.name) || !isNonempty(provider.model)) return false;
  if (!isRecord(provider.endpoint) || typeof provider.endpoint.kind !== 'string') return false;
  if (provider.endpoint.kind === 'local_zero_cost') {
    if (
      !exactKeys(provider.endpoint, LOCAL_ENDPOINT_KEYS) ||
      !isRef(provider.endpoint.identityDigest) ||
      !isRef(provider.endpoint.localProvenanceRef)
    )
      return false;
  } else if (
    provider.endpoint.kind !== 'registered' ||
    !exactKeys(provider.endpoint, REGISTERED_ENDPOINT_KEYS) ||
    !['bundled_default', 'user'].includes(provider.endpoint.registrationKind) ||
    !isRef(provider.endpoint.endpointRegistrationRef) ||
    !isRef(provider.endpoint.endpointIdentityDigest) ||
    !isRef(provider.endpoint.tlsPolicyDigest)
  )
    return false;
  if (!strictlySortedUniqueRefs(provider.credentialGrantRefs)) return false;
  if (
    !isRecord(provider.adapter) ||
    !exactKeys(provider.adapter, ADAPTER_KEYS) ||
    !isNonempty(provider.adapter.adapterId) ||
    !isNonempty(provider.adapter.version) ||
    !isRef(provider.adapter.codeDigest)
  )
    return false;
  if (!isRecord(provider.negotiation) || !exactKeys(provider.negotiation, NEGOTIATION_KEYS)) return false;
  const negotiation = provider.negotiation;
  if (
    !MODES.has(negotiation.mode) ||
    !isRef(negotiation.capabilityEvidenceRef) ||
    !isRef(negotiation.capabilityDigest) ||
    typeof negotiation.nativeToolCalling !== 'boolean' ||
    typeof negotiation.streaming !== 'boolean' ||
    typeof negotiation.trustedUsageEvidence !== 'boolean' ||
    !isSafeInteger(negotiation.contextLimitTokens, 1) ||
    !isSafeInteger(negotiation.maxOutputTokens, 1) ||
    !Array.isArray(negotiation.exposedToolNames) ||
    negotiation.exposedToolNames.some((name) => !isNonempty(name)) ||
    new Set(negotiation.exposedToolNames).size !== negotiation.exposedToolNames.length
  )
    return false;

  if (!Array.isArray(assembly.mcpServers)) return false;
  const registrations = new Set<string>();
  for (const server of assembly.mcpServers) {
    if (
      !isRecord(server) ||
      !exactKeys(server, MCP_KEYS) ||
      !isNonempty(server.registrationId) ||
      registrations.has(server.registrationId) ||
      !isRef(server.registryRevisionRef) ||
      !isSafeInteger(server.registryRevision, 1) ||
      !isRef(server.manifestDigest)
    )
      return false;
    const previous = assembly.mcpServers[registrations.size - 1];
    if (previous !== undefined && byteCompare(previous.registrationId, server.registrationId) >= 0) return false;
    registrations.add(server.registrationId);
  }
  if (
    !isRecord(assembly.tools) ||
    !exactKeys(assembly.tools, TOOLS_KEYS) ||
    !isRef(assembly.tools.manifestRef) ||
    !isRef(assembly.tools.manifestDigest)
  )
    return false;
  if (!isRecord(assembly.instructions) || !exactKeys(assembly.instructions, INSTRUCTION_KEYS)) return false;
  const instructions = assembly.instructions;
  if (
    !isRef(instructions.systemPromptRef) ||
    !isRef(instructions.systemPromptDigest) ||
    !isRef(instructions.workspaceInstructionsRef) ||
    !isRef(instructions.workspaceInstructionsDigest) ||
    !Array.isArray(instructions.skills)
  )
    return false;
  const skillIds = new Set<string>();
  for (const skill of instructions.skills) {
    if (
      !isRecord(skill) ||
      !exactKeys(skill, SKILL_KEYS) ||
      !isNonempty(skill.skillId) ||
      skillIds.has(skill.skillId) ||
      !isRef(skill.manifestRef) ||
      !isRef(skill.manifestDigest)
    )
      return false;
    skillIds.add(skill.skillId);
  }
  if (!isRecord(assembly.runtime) || !exactKeys(assembly.runtime, RUNTIME_REQUIRED_KEYS, RUNTIME_GUEST_KEYS))
    return false;
  const runtime = assembly.runtime;
  if (
    !isRef(runtime.runtimeBundleRef) ||
    !isRef(runtime.runtimeBundleManifestDigest) ||
    !isNonempty(runtime.workerExecutableId) ||
    !isRef(runtime.workerExecutableDigest) ||
    !['macos_vm', 'linux_namespace'].includes(runtime.sandboxBackend)
  )
    return false;
  const hasGuestRef = runtime.guestToolchainManifestRef !== undefined;
  const hasGuestDigest = runtime.guestToolchainManifestDigest !== undefined;
  if (hasGuestRef !== hasGuestDigest) return false;
  if (hasGuestRef && (!isRef(runtime.guestToolchainManifestRef) || !isRef(runtime.guestToolchainManifestDigest)))
    return false;
  if (runtime.sandboxBackend === 'macos_vm' && !hasGuestRef) return false;
  if (
    !isRecord(assembly.retry) ||
    !exactKeys(assembly.retry, RETRY_KEYS) ||
    !isRecord(assembly.retry.model) ||
    !exactKeys(assembly.retry.model, MODEL_RETRY_KEYS) ||
    !Array.isArray(assembly.retry.tools)
  )
    return false;
  if (!isRecord(assembly.context) || !exactKeys(assembly.context, CONTEXT_KEYS)) return false;
  const context = assembly.context;
  if (
    !isRef(context.compactionPromptEnvelopeRef) ||
    !isRef(context.compactionPromptEnvelopeDigest) ||
    !isSafeInteger(context.contextLimitTokens, 1) ||
    !isSafeInteger(context.reservedOutputTokens, 1) ||
    !isSafeInteger(context.hardPromptTokens, 1) ||
    !isSafeInteger(context.triggerThresholdTokens, 1) ||
    !isSafeInteger(context.protectedRecentTokens, 1) ||
    !isSafeInteger(context.summaryTokenCap, 1) ||
    !isSafeInteger(context.compactionEnvelopeTokens) ||
    !isSafeInteger(context.sourceInputTokenCap, 1) ||
    context.maxSummaryBytes !== 262_144 ||
    !isRef(assembly.assemblyDigest) ||
    !isNonempty(assembly.createdAt)
  )
    return false;
  return true;
}

function verifyReference(
  material: RunAssemblyValidationMaterial,
  kind: RunAssemblyReferenceKind,
  ref: ArtifactRef,
  digest: string
): boolean {
  try {
    return material.verifyReference({ kind, ref, digest });
  } catch {
    return false;
  }
}

function validateReferences(assembly: RunAssemblyV1, material: RunAssemblyValidationMaterial): boolean {
  if (
    !verifyReference(material, 'tool_contract_manifest', assembly.tools.manifestRef, assembly.tools.manifestDigest) ||
    !verifyReference(
      material,
      'system_prompt',
      assembly.instructions.systemPromptRef,
      assembly.instructions.systemPromptDigest
    ) ||
    !verifyReference(
      material,
      'workspace_instructions',
      assembly.instructions.workspaceInstructionsRef,
      assembly.instructions.workspaceInstructionsDigest
    ) ||
    !verifyReference(
      material,
      'runtime_bundle',
      assembly.runtime.runtimeBundleRef,
      assembly.runtime.runtimeBundleManifestDigest
    ) ||
    !verifyReference(
      material,
      'compaction_prompt_envelope',
      assembly.context.compactionPromptEnvelopeRef,
      assembly.context.compactionPromptEnvelopeDigest
    )
  )
    return false;
  for (const server of assembly.mcpServers) {
    if (!verifyReference(material, 'mcp_registry_revision', server.registryRevisionRef, server.manifestDigest))
      return false;
  }
  for (const skill of assembly.instructions.skills) {
    if (!verifyReference(material, 'skill_manifest', skill.manifestRef, skill.manifestDigest)) return false;
  }
  if (
    assembly.runtime.guestToolchainManifestRef !== undefined &&
    !verifyReference(
      material,
      'guest_toolchain_manifest',
      assembly.runtime.guestToolchainManifestRef,
      assembly.runtime.guestToolchainManifestDigest!
    )
  )
    return false;
  return true;
}

function expectedToolRetry(entry: { name: string; replayClass: ReplayClass }): RunAssemblyV1['retry']['tools'][number] {
  if (entry.replayClass === 'retry') {
    return {
      toolName: entry.name,
      replayClass: 'retry',
      maxDispatchedAttempts: 3,
      postAttemptDelaysMs: [500, 2000]
    };
  }
  if (entry.replayClass === 'workspace-rollback-retry') {
    return {
      toolName: entry.name,
      replayClass: 'workspace-rollback-retry',
      maxDispatchedAttempts: 2,
      postAttemptDelaysMs: [500]
    };
  }
  return {
    toolName: entry.name,
    replayClass: entry.replayClass,
    maxDispatchedAttempts: 1,
    postAttemptDelaysMs: []
  };
}

function validateToolAuthority(assembly: RunAssemblyV1, tools: RunAssemblyToolAuthority[]): boolean {
  const names = new Set<string>();
  for (const [index, entry] of tools.entries()) {
    if (
      !isRecord(entry) ||
      !exactKeys(entry, TOOL_AUTHORITY_ENTRY_KEYS) ||
      !isNonempty(entry.name) ||
      entry.name === MISSING_TOOL_NAME ||
      !isRef(entry.inputSchemaRef) ||
      !isRef(entry.inputSchemaDigest) ||
      typeof entry.description !== 'string' ||
      names.has(entry.name) ||
      !REPLAY_CLASSES.has(entry.replayClass) ||
      (index > 0 && byteCompare(tools[index - 1]!.name, entry.name) >= 0)
    )
      return false;
    assertBoundedJsonValue(entry.inputSchema, 'tool input schema');
    canonicalJsonBytes(entry.inputSchema);
    names.add(entry.name);
  }
  const exposed = assembly.provider.negotiation.exposedToolNames;
  const expectedExposed = assembly.provider.negotiation.mode === 'text-only' ? [] : tools.map((entry) => entry.name);
  return sameStringSequence(exposed, expectedExposed);
}

function validateRetryPolicy(assembly: RunAssemblyV1, tools: RunAssemblyToolAuthority[]): boolean {
  if (
    assembly.retry.model.maxDispatchedAttempts !== 3 ||
    assembly.retry.model.maxZeroByteTransportRetriesPerAttempt !== 0 ||
    !sameJcs(assembly.retry.model.postAttemptDelaysMs, [500, 2000]) ||
    assembly.retry.tools.length !== tools.length
  )
    return false;
  return assembly.retry.tools.every((policy, index) => {
    if (!isRecord(policy) || !exactKeys(policy, TOOL_RETRY_KEYS)) return false;
    return sameJcs(policy, expectedToolRetry(tools[index]!));
  });
}

function validateContext(assembly: RunAssemblyV1, material: RunAssemblyValidationMaterial): boolean {
  const context = assembly.context;
  const c = context.contextLimitTokens;
  const o = context.reservedOutputTokens;
  const h = c - o;
  const t = Math.min(Number((7n * BigInt(c)) / 10n), h - 8192);
  const r = Math.min(32_768, Math.floor(c / 4));
  const s = Math.min(8192, Math.floor(c / 8));
  const k = compactionEnvelopeEstimate(material.compactionEnvelope);
  const p = Math.min(Math.floor(c / 2), c - s - k);
  return (
    c >= 32_768 &&
    o >= 1 &&
    o <= Math.floor(c / 4) &&
    h - 8192 >= 16_384 &&
    p >= 4096 &&
    context.hardPromptTokens === h &&
    context.triggerThresholdTokens === t &&
    context.protectedRecentTokens === r &&
    context.summaryTokenCap === s &&
    context.compactionEnvelopeTokens === k &&
    context.sourceInputTokenCap === p &&
    assembly.provider.negotiation.contextLimitTokens === c &&
    o <= assembly.provider.negotiation.maxOutputTokens &&
    s <= assembly.provider.negotiation.maxOutputTokens &&
    assembly.context.compactionPromptEnvelopeRef === material.compactionEnvelope.ref &&
    assembly.context.compactionPromptEnvelopeDigest === material.compactionEnvelope.value.envelopeDigest
  );
}

export function validateRunAssembly(original: ValidateRunAssemblyInput): ValidateRunAssemblyResult {
  try {
    const { material: originalMaterial, ...data } = original;
    const {
      resolveVerifiedCapabilityClaims,
      verifyLocalZeroCostAuthority,
      resolvePriceTableAuthority,
      verifyReference,
      verifyProviderAdapter,
      verifyProviderEndpoint,
      resolveVerifiedTools,
      ...materialData
    } = originalMaterial;
    const input = {
      ...immutableSnapshot(data),
      material: {
        ...immutableSnapshot(materialData),
        resolveVerifiedCapabilityClaims,
        verifyLocalZeroCostAuthority,
        resolvePriceTableAuthority,
        verifyReference,
        verifyProviderAdapter,
        verifyProviderEndpoint,
        resolveVerifiedTools
      }
    };
    assertArtifactRef(input.assemblyRef);
    const admittedAt = parseCanonicalTime(input.admittedAt);
    const deadlineAt = parseCanonicalTime(input.deadlineAt);
    if (deadlineAt < admittedAt || !isSafeInteger(input.maxRunCostMicros)) return fail('assembly_schema_invalid');
    if (!validateClosedShape(input.assembly)) return fail('assembly_schema_invalid');
    if (parseCanonicalTime(input.assembly.createdAt) > admittedAt) return fail('assembly_schema_invalid');
    if (
      digestOmitting(input.assembly, 'assemblyDigest') !== input.assembly.assemblyDigest ||
      planCanonicalArtifact(input.assembly, input.assembly.format).ref !== input.assemblyRef
    )
      return fail('assembly_digest_mismatch');
    if (!validateReferences(input.assembly, input.material)) return fail('assembly_reference_invalid');

    const assembly = input.assembly;
    const material = input.material;
    const provider = assembly.provider;
    const capabilitySource = material.capabilityEvidence.value.source;
    if (
      capabilitySource.kind === 'signed_catalog' &&
      capabilitySource.runtimeBundleRef !== assembly.runtime.runtimeBundleRef
    ) {
      return fail('capability_authority_invalid', 'MODEL_CAPABILITY_UNKNOWN');
    }
    const endpointDigest = endpointIdentityDigest(assembly);
    let adapterVerified = false;
    try {
      adapterVerified = material.verifyProviderAdapter({
        adapter: provider.adapter,
        runtimeBundleRef: assembly.runtime.runtimeBundleRef,
        runtimeBundleManifestDigest: assembly.runtime.runtimeBundleManifestDigest
      });
    } catch {
      adapterVerified = false;
    }
    if (!adapterVerified) return fail('provider_authority_mismatch');

    let endpointVerified = false;
    try {
      endpointVerified = material.verifyProviderEndpoint({
        provider: provider.name,
        model: provider.model,
        endpoint: provider.endpoint,
        credentialGrantRefs: [...provider.credentialGrantRefs],
        capabilitySource: material.capabilityEvidence.value.source
      });
    } catch {
      endpointVerified = false;
    }
    if (!endpointVerified) return fail('provider_authority_mismatch');

    const capability = negotiateModelCapabilities({
      provider: provider.name,
      model: provider.model,
      endpointIdentityDigest: endpointDigest,
      adapter: provider.adapter,
      admittedAt: input.admittedAt,
      deadlineAt: input.deadlineAt,
      streamingRequested: provider.negotiation.streaming,
      evidence: material.capabilityEvidence,
      resolveVerifiedSourceClaims: material.resolveVerifiedCapabilityClaims
    });
    if (!capability.ok) return fail('capability_authority_invalid', 'MODEL_CAPABILITY_UNKNOWN');
    const negotiated = capability.negotiation;
    if (
      provider.negotiation.capabilityEvidenceRef !== negotiated.evidenceRef ||
      provider.negotiation.capabilityDigest !== negotiated.evidenceDigest ||
      provider.negotiation.mode !== negotiated.mode ||
      provider.negotiation.streaming !== negotiated.streaming ||
      provider.negotiation.nativeToolCalling !== negotiated.nativeToolCalling ||
      provider.negotiation.trustedUsageEvidence !== negotiated.trustedUsageEvidence ||
      provider.negotiation.contextLimitTokens !== negotiated.contextLimitTokens ||
      provider.negotiation.maxOutputTokens !== negotiated.maxOutputTokens
    )
      return fail('capability_authority_invalid', 'MODEL_CAPABILITY_UNKNOWN');

    const pricing = validateModelPricing({
      provider: provider.name,
      model: provider.model,
      endpointIdentityDigest: endpointDigest,
      credentialGrantRefs: provider.credentialGrantRefs,
      admittedAt: input.admittedAt,
      deadlineAt: input.deadlineAt,
      maxRunCostMicros: input.maxRunCostMicros,
      bound: provider.pricing,
      ...(material.localProvenance === undefined ? {} : { localProvenance: material.localProvenance }),
      ...(material.priceTable === undefined ? {} : { priceTable: material.priceTable }),
      verifyLocalZeroCostAuthority: material.verifyLocalZeroCostAuthority,
      resolvePriceTableAuthority: material.resolvePriceTableAuthority
    });
    if (!pricing.ok) return fail('pricing_authority_invalid', 'MODEL_COST_UNKNOWN');
    if (
      (provider.endpoint.kind === 'local_zero_cost' &&
        (provider.name !== 'ollama' ||
          provider.credentialGrantRefs.length !== 0 ||
          provider.endpoint.localProvenanceRef !== provider.pricing.provenanceRef ||
          material.capabilityEvidence.value.source.kind !== 'managed_local' ||
          material.localProvenance?.value.capabilityEvidenceRef !== provider.negotiation.capabilityEvidenceRef ||
          material.localProvenance.value.capabilityDigest !== provider.negotiation.capabilityDigest ||
          material.localProvenance.value.serviceSpecRef !==
            material.capabilityEvidence.value.source.localInferenceServiceSpecRef ||
          material.localProvenance.value.serviceSpecDigest !==
            material.capabilityEvidence.value.source.localInferenceServiceSpecDigest)) ||
      (provider.endpoint.kind === 'registered' &&
        (provider.name === 'ollama' ||
          provider.credentialGrantRefs.length === 0 ||
          (material.capabilityEvidence.value.source.kind === 'registered_endpoint_negotiation' &&
            material.capabilityEvidence.value.source.endpointRegistrationRef !==
              provider.endpoint.endpointRegistrationRef)))
    )
      return fail('provider_authority_mismatch');

    if (!strictlySortedUniqueRefs(input.runSpecCredentialGrantRefs)) {
      return fail('credential_union_mismatch');
    }
    if (!strictlySortedUniqueRefs(material.additionalCredentialGrantRefs)) {
      return fail('credential_union_mismatch');
    }
    const expectedCredentialRefs = [
      ...new Set([...provider.credentialGrantRefs, ...material.additionalCredentialGrantRefs])
    ].sort();
    if (!sameStringSequence(input.runSpecCredentialGrantRefs, expectedCredentialRefs)) {
      return fail('credential_union_mismatch');
    }

    const resolvedTools = material.resolveVerifiedTools(assembly.tools);
    if (resolvedTools === null) return fail('tool_authority_mismatch');
    const tools = immutableSnapshot(resolvedTools);
    if (!validateToolAuthority(assembly, tools)) return fail('tool_authority_mismatch');
    if (!validateRetryPolicy(assembly, tools)) return fail('retry_policy_invalid');
    if (!validateContext(assembly, material)) return fail('context_equations_invalid');

    const authority: ModelAttemptAuthority = {
      assemblyRef: input.assemblyRef,
      assemblyDigest: assembly.assemblyDigest,
      provider: provider.name,
      model: provider.model,
      negotiatedMode: provider.negotiation.mode,
      streaming: provider.negotiation.streaming,
      contextLimitTokens: provider.negotiation.contextLimitTokens,
      maximumOutputTokens: assembly.context.reservedOutputTokens,
      maximumCompactionOutputTokens: assembly.context.summaryTokenCap,
      exposedTools:
        provider.negotiation.mode === 'text-only'
          ? []
          : tools.map(({ replayClass: _, ...tool }, index) => ({ index, ...tool })),
      pricing: pricing.pricing,
      compactionEnvelope: material.compactionEnvelope
    };
    try {
      createModelRequestReservation(
        authority.contextLimitTokens,
        Math.max(authority.maximumOutputTokens, authority.maximumCompactionOutputTokens),
        authority.pricing
      );
    } catch {
      return fail('pricing_authority_invalid', 'MODEL_COST_UNKNOWN');
    }
    return { ok: true, model: createModelSession(authority) };
  } catch {
    return fail('assembly_schema_invalid');
  }
}
