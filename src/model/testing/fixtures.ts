import { canonicalSha256 } from '../../kernel/canonical.js';
import { planCanonicalArtifact } from '../../kernel/artifact-plan.js';
import type { ProviderName, RunAssemblyV1 } from '../../kernel/types.js';
import type { ModelTextV1 } from '../../protocol/agent-ir.js';
import type { ModelCapabilityEvidenceV1, NormalizedModelCapabilityClaimsV1 } from '../capabilities.js';
import { priceTableDigest, type ModelPriceTableV1, type LocalZeroCostProvenanceV1 } from '../pricing.js';
import {
  compactionEnvelopeEstimate,
  type CompactionPromptEnvelopeMaterial,
  type CompactionPromptEnvelopeV1,
  type NormalPromptProjectionV1
} from '../request.js';
import type { ValidateRunAssemblyInput, RunAssemblyToolAuthority } from '../run-assembly.js';

export function ref(index: number): string {
  return index.toString(16).padStart(64, '0');
}
function seal<T extends object, K extends string>(value: T, key: K): T & Record<K, string> {
  return { ...value, [key]: canonicalSha256(value) } as T & Record<K, string>;
}
function modelText(value: string): { ref: string; value: ModelTextV1 } {
  const withoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-model-text-v1' as const,
    utf8: value,
    byteCount: Buffer.byteLength(value)
  };
  const text: ModelTextV1 = { ...withoutDigest, textDigest: canonicalSha256(withoutDigest) };
  return { ref: planCanonicalArtifact(text, text.format).ref, value: text };
}

function compactionEnvelope(): CompactionPromptEnvelopeMaterial {
  const systemInstruction = modelText('Summarize faithfully.');
  const userPrefix = modelText('Summarize this context:\n\n');
  const userSuffix = modelText('\n\nReturn Markdown only.');
  const withoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-compaction-prompt-envelope-v1' as const,
    systemInstructionRef: systemInstruction.ref,
    systemInstructionDigest: systemInstruction.value.textDigest,
    userPrefixRef: userPrefix.ref,
    userPrefixDigest: userPrefix.value.textDigest,
    sourcePlaceholder: '{{CLIQ_SOURCE_CONTEXT_UTF8}}' as const,
    userSuffixRef: userSuffix.ref,
    userSuffixDigest: userSuffix.value.textDigest,
    resultContract: {
      toolsAllowed: false as const,
      requiredStopReason: 'end' as const,
      mediaType: 'text/markdown; charset=utf-8' as const,
      summaryFormat: 'cliq-context-summary-markdown-v1' as const
    }
  };
  const value: CompactionPromptEnvelopeV1 = {
    ...withoutDigest,
    envelopeDigest: canonicalSha256(withoutDigest)
  };
  return {
    ref: planCanonicalArtifact(value, value.format).ref,
    value,
    systemInstruction,
    userPrefix,
    userSuffix
  };
}

export function testFixture(provider: ProviderName = 'openai', nativeToolCalling = true): ValidateRunAssemblyInput {
  const model = 'model-1';
  const localEndpoint = { scheme: 'http' as const, host: '127.0.0.1' as const, port: 11434 };
  const endpointIdentityDigest = provider === 'ollama' ? canonicalSha256(localEndpoint) : ref(1);
  const adapter = { adapterId: provider + '-kernel-v1', version: '1.0.0', codeDigest: ref(2) };
  const claims: NormalizedModelCapabilityClaimsV1 = {
    nativeToolCalling,
    streaming: true,
    trustedUsageEvidence: false,
    contextLimitTokens: 32768,
    maxOutputTokens: 8192
  };
  const capability: ModelCapabilityEvidenceV1 = seal(
    {
      schemaVersion: 1,
      format: 'cliq-model-capability-evidence-v1',
      provider,
      model,
      endpointIdentityDigest,
      adapter,
      source:
        provider === 'ollama'
          ? {
              kind: 'managed_local',
              localInferenceServiceSpecRef: ref(70),
              localInferenceServiceSpecDigest: ref(71),
              localModelManifestRef: ref(72),
              localModelManifestDigest: ref(73)
            }
          : { kind: 'signed_catalog', runtimeBundleRef: ref(34), catalogEntryRef: ref(4), catalogEntryDigest: ref(5) },
      ...claims,
      observedAt: '2026-09-05T00:00:00.000Z',
      validThrough: '2026-09-07T00:00:00.000Z'
    } as Omit<ModelCapabilityEvidenceV1, 'evidenceDigest'>,
    'evidenceDigest'
  );
  const capabilityRef = planCanonicalArtifact(capability, capability.format).ref;
  const table: ModelPriceTableV1 = {
    schemaVersion: 1,
    format: 'cliq-model-price-table-v1',
    signerKeyId: 'release-key-1',
    signatureAlgorithm: 'ed25519',
    signatureRef: ref(6),
    provider,
    model,
    endpointIdentityDigest,
    currency: 'USD',
    unit: 'micros_per_million_tokens',
    prices: { input: 1000000, output: 2000000, cacheRead: 500000, cacheWrite: 1500000 },
    requestTokenCeiling: { inputTokens: 32768, outputTokens: 8192, cacheReadTokens: 32768, cacheWriteTokens: 32768 },
    validFrom: '2026-09-05T00:00:00.000Z',
    validThrough: '2026-09-07T00:00:00.000Z',
    tableDigest: ''
  };
  table.tableDigest = priceTableDigest(table);
  const tableRef = planCanonicalArtifact(table, table.format).ref;
  const provenance: LocalZeroCostProvenanceV1 = seal(
    {
      schemaVersion: 1,
      format: 'cliq-local-zero-cost-v1',
      ownerPrincipalId: 'owner',
      provider: 'ollama',
      model,
      serviceSpecRef: ref(70),
      serviceSpecDigest: ref(71),
      stableServiceIdentityDigest: ref(74),
      endpoint: localEndpoint,
      endpointIdentityDigest,
      boundaryEvidenceRef: ref(75),
      boundaryEvidenceDigest: ref(76),
      capabilityEvidenceRef: capabilityRef,
      capabilityDigest: capability.evidenceDigest,
      createdAt: '2026-09-05T00:00:00.000Z',
      validThrough: '2026-09-07T00:00:00.000Z'
    } as Omit<LocalZeroCostProvenanceV1, 'provenanceDigest'>,
    'provenanceDigest'
  );
  const localRef = planCanonicalArtifact(provenance, provenance.format).ref;
  const schema = {
    type: 'object',
    additionalProperties: false,
    required: ['path'],
    properties: { path: { type: 'string' } }
  };
  const tools: RunAssemblyToolAuthority[] = [
    {
      name: 'read_file',
      description: 'Read a file.',
      replayClass: 'retry',
      inputSchemaRef: canonicalSha256(schema),
      inputSchemaDigest: canonicalSha256(schema),
      inputSchema: schema
    }
  ];
  const manifest = seal(
    { schemaVersion: 1, format: 'cliq-tool-contract-manifest-v1', entries: tools },
    'manifestDigest'
  );
  const toolManifestRef = planCanonicalArtifact(manifest, manifest.format).ref;
  const envelope = compactionEnvelope();
  const k = compactionEnvelopeEstimate(envelope);
  const assembly: RunAssemblyV1 = seal(
    {
      schemaVersion: 1,
      format: 'cliq-run-assembly-v1',
      provider: {
        name: provider,
        model,
        endpoint:
          provider === 'ollama'
            ? { kind: 'local_zero_cost', identityDigest: endpointIdentityDigest, localProvenanceRef: localRef }
            : {
                kind: 'registered',
                registrationKind: 'user',
                endpointRegistrationRef: ref(16),
                endpointIdentityDigest,
                tlsPolicyDigest: ref(17)
              },
        credentialGrantRefs: provider === 'ollama' ? [] : [ref(20)],
        adapter,
        negotiation: {
          mode: nativeToolCalling ? 'native-tools' : 'text-only',
          capabilityEvidenceRef: capabilityRef,
          capabilityDigest: capability.evidenceDigest,
          ...claims,
          exposedToolNames: nativeToolCalling ? ['read_file'] : []
        },
        pricing:
          provider === 'ollama'
            ? { kind: 'zero_cost', maxRunCostMicros: 0, provenanceRef: localRef }
            : {
                kind: 'trusted_price_table',
                priceTableRef: tableRef,
                priceTableDigest: table.tableDigest,
                calculationAlgorithm: 'cliq-price-ceil-v1',
                maxRunCostMicros: 10000000,
                validThrough: table.validThrough,
                provenanceRef: ref(7)
              }
      },
      mcpServers: [],
      tools: { manifestRef: toolManifestRef, manifestDigest: manifest.manifestDigest },
      instructions: {
        systemPromptRef: ref(30),
        systemPromptDigest: ref(31),
        workspaceInstructionsRef: ref(32),
        workspaceInstructionsDigest: ref(33),
        skills: []
      },
      runtime: {
        runtimeBundleRef: ref(34),
        runtimeBundleManifestDigest: ref(35),
        workerExecutableId: 'worker-v1',
        workerExecutableDigest: ref(36),
        sandboxBackend: 'linux_namespace'
      },
      retry: {
        model: { maxDispatchedAttempts: 3, maxZeroByteTransportRetriesPerAttempt: 0, postAttemptDelaysMs: [500, 2000] },
        tools: [
          { toolName: 'read_file', replayClass: 'retry', maxDispatchedAttempts: 3, postAttemptDelaysMs: [500, 2000] }
        ]
      },
      context: {
        compactionPromptEnvelopeRef: envelope.ref,
        compactionPromptEnvelopeDigest: envelope.value.envelopeDigest,
        contextLimitTokens: 32768,
        reservedOutputTokens: 4096,
        hardPromptTokens: 28672,
        triggerThresholdTokens: 20480,
        protectedRecentTokens: 8192,
        summaryTokenCap: 4096,
        compactionEnvelopeTokens: k,
        sourceInputTokenCap: Math.min(16384, 32768 - 4096 - k),
        maxSummaryBytes: 262144
      },
      createdAt: '2026-09-05T00:00:00.000Z'
    } as Omit<RunAssemblyV1, 'assemblyDigest'>,
    'assemblyDigest'
  );
  const additionalCredentialGrantRefs = [ref(21)];
  return {
    assemblyRef: planCanonicalArtifact(assembly, assembly.format).ref,
    assembly,
    admittedAt: '2026-09-05T00:00:01.000Z',
    deadlineAt: '2026-09-06T00:00:00.000Z',
    maxRunCostMicros: provider === 'ollama' ? 0 : 10000000,
    runSpecCredentialGrantRefs: [...assembly.provider.credentialGrantRefs, ...additionalCredentialGrantRefs].sort(),
    material: {
      capabilityEvidence: { ref: capabilityRef, value: capability },
      resolveVerifiedCapabilityClaims: () => ({ ...claims }),
      ...(provider === 'ollama'
        ? { localProvenance: { ref: localRef, value: provenance } }
        : { priceTable: { ref: tableRef, value: table } }),
      verifyLocalZeroCostAuthority: () => true,
      resolvePriceTableAuthority: () => ref(7),
      compactionEnvelope: envelope,
      additionalCredentialGrantRefs,
      resolveVerifiedTools: (reference) =>
        reference.manifestRef === toolManifestRef &&
        reference.manifestDigest === manifest.manifestDigest &&
        planCanonicalArtifact(manifest, manifest.format).ref === toolManifestRef
          ? manifest.entries
          : null,
      verifyReference: () => true,
      verifyProviderAdapter: () => true,
      verifyProviderEndpoint: ({ endpoint }) =>
        endpoint.kind === 'local_zero_cost'
          ? endpoint.localProvenanceRef === localRef
          : endpoint.endpointRegistrationRef === ref(16) && endpoint.endpointIdentityDigest === endpointIdentityDigest
    }
  };
}

export function reseal(input: ValidateRunAssemblyInput): void {
  const { assemblyDigest: _, ...value } = input.assembly;
  input.assembly.assemblyDigest = canonicalSha256(value);
  input.assemblyRef = planCanonicalArtifact(input.assembly, input.assembly.format).ref;
}
export function normalInput(input: ValidateRunAssemblyInput, extra: NormalPromptProjectionV1['messages'] = []) {
  const projection: NormalPromptProjectionV1 = seal(
    {
      schemaVersion: 1,
      format: 'cliq-normal-prompt-projection-v1',
      runId: 'run-1',
      basedOnRunRevision: 1,
      frontierDigest: ref(91),
      runSpecRef: ref(92),
      assemblyRef: input.assemblyRef,
      assemblyDigest: input.assembly.assemblyDigest,
      contextManifestRef: ref(93),
      contextManifestDigest: ref(94),
      messages: [
        {
          index: 0,
          role: 'system',
          sourceKind: 'assembly_instructions',
          sourceId: input.assemblyRef,
          contentUtf8: 'Use tools carefully.'
        },
        { index: 1, role: 'user', sourceKind: 'run_objective', sourceId: 'objective', contentUtf8: 'Read the file.' },
        ...extra
      ],
      tools:
        input.assembly.provider.negotiation.mode === 'text-only'
          ? []
          : input.material
              .resolveVerifiedTools(input.assembly.tools)!
              .map(({ replayClass: _, ...tool }, index) => ({ index, ...tool }))
    } as Omit<NormalPromptProjectionV1, 'projectionDigest'>,
    'projectionDigest'
  );
  return {
    kind: 'normal' as const,
    invocation: { runId: 'run-1', opId: 'model-1', attempt: 1 },
    projection,
    projectionRef: planCanonicalArtifact(projection, projection.format).ref
  };
}
