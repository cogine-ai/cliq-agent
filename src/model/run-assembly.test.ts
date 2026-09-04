import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import type { RunAssemblyV1 } from '../kernel/types.js';
import type { ModelCapabilityEvidenceV1, NormalizedModelCapabilityClaimsV1 } from './capabilities.js';
import { priceTableDigest, type ModelPriceTableV1 } from './pricing.js';
import {
  MODEL_VISIBLE_PROMPT_FORMAT,
  serializeNativeRequestV1,
  type PromptSerializationProfileV1,
  type ProviderNativeRequestProfileV1
} from './request.js';
import {
  validateRunAssembly,
  type RunAssemblyValidationMaterial,
  type ValidateRunAssemblyInput
} from './run-assembly.js';
import type {
  TokenizerMergeRanksV1,
  TokenizerProfileV1,
  TokenizerVocabularyV1
} from './tokenizer.js';

function ref(index: number): string {
  return index.toString(16).padStart(64, '0');
}

const CLAIMS: NormalizedModelCapabilityClaimsV1 = {
  nativeToolCalling: true,
  constrainedOutput: true,
  streaming: true,
  trustedUsageEvidence: false,
  contextLimitTokens: 32_768,
  maxOutputTokens: 8_192
};

function testFixture(): ValidateRunAssemblyInput {
  const endpointIdentityDigest = ref(1);
  const adapter = { adapterId: 'openai-kernel-v1', version: '1.0.0', codeDigest: ref(2) };
  const capabilityWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-model-capability-evidence-v1' as const,
    provider: 'openai' as const,
    model: 'model-1',
    endpointIdentityDigest,
    adapter,
    source: {
      kind: 'signed_catalog' as const,
      runtimeBundleRef: ref(3),
      catalogEntryRef: ref(4),
      catalogEntryDigest: ref(5)
    },
    ...CLAIMS,
    observedAt: '2026-09-05T00:00:00.000Z',
    validThrough: '2026-09-07T00:00:00.000Z'
  };
  const capability: ModelCapabilityEvidenceV1 = {
    ...capabilityWithoutDigest,
    evidenceDigest: canonicalSha256(capabilityWithoutDigest)
  };
  const capabilityRef = planCanonicalArtifact(capability, capability.format).ref;

  const priceWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-model-price-table-v1' as const,
    signerKeyId: 'release-key-1',
    signatureAlgorithm: 'ed25519' as const,
    signatureRef: ref(6),
    provider: 'openai' as const,
    model: 'model-1',
    endpointIdentityDigest,
    currency: 'USD' as const,
    unit: 'micros_per_million_tokens' as const,
    prices: { input: 1_000_000, output: 2_000_000, cacheRead: 500_000, cacheWrite: 1_500_000 },
    validFrom: '2026-09-05T00:00:00.000Z',
    validThrough: '2026-09-07T00:00:00.000Z'
  };
  const priceTable = {
    ...priceWithoutDigest,
    tableDigest: priceTableDigest({ ...priceWithoutDigest, tableDigest: '' })
  } satisfies ModelPriceTableV1;
  const priceTableRef = planCanonicalArtifact(priceTable, priceTable.format).ref;
  const priceProvenanceRef = ref(7);

  const visibleSources = Array.from({ length: 7 }, (_, index) =>
    canonicalJsonBytes({
      format: MODEL_VISIBLE_PROMPT_FORMAT,
      messages: [
        { role: 'system', contentUtf8: 'Use tools carefully.' },
        { role: 'user', contentUtf8: `Read the file (${index}).` }
      ],
      tools: [
        {
          index: 0,
          name: 'read_file',
          description: 'Read a file.',
          inputSchema: {
            type: 'object',
            additionalProperties: false,
            required: ['path'],
            properties: { path: { type: 'string' } }
          }
        }
      ],
      responseContract: { mode: 'native-tools', toolCallsAllowed: true }
    }).toString('utf8')
  );
  const compactionSource = canonicalJsonBytes({
    format: 'cliq-compaction-prompt-v1',
    messages: [
      { role: 'system', contentUtf8: 'Summarize faithfully.' },
      { role: 'user', contentUtf8: 'Source context.' }
    ],
    tools: [],
    responseContract: {
      toolsAllowed: false,
      requiredStopReason: 'end',
      mediaType: 'text/markdown; charset=utf-8',
      summaryFormat: 'cliq-context-summary-markdown-v1'
    }
  }).toString('utf8');
  const promptPrefix = '<prompt>';
  const promptSuffix = '</prompt>';
  const compactionPrefix = '<compact>';
  const compactionSuffix = '</compact>';
  const renderedPrompts = visibleSources.map((source) => Buffer.from(`${promptPrefix}${source}${promptSuffix}`));
  const compactionRendered = Buffer.from(`${compactionPrefix}${compactionSource}${compactionSuffix}`);
  const promptWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-prompt-serialization-profile-v1' as const,
    provider: 'openai' as const,
    model: 'model-1',
    algorithm: 'cliq-jcs-framed-chat-v1' as const,
    normalPrefixUtf8: promptPrefix,
    normalSuffixUtf8: promptSuffix,
    compactionPrefixUtf8: compactionPrefix,
    compactionSuffixUtf8: compactionSuffix,
    goldenVectors: [
      ...visibleSources.map((source, index) => ({
        payloadJcsUtf8: source,
        renderedBytesBase64url: renderedPrompts[index]!.toString('base64url')
      })),
      {
        payloadJcsUtf8: compactionSource,
        renderedBytesBase64url: compactionRendered.toString('base64url')
      }
    ]
  };
  const promptProfile: PromptSerializationProfileV1 = {
    ...promptWithoutDigest,
    profileDigest: canonicalSha256(promptWithoutDigest)
  };
  const promptProfileRef = planCanonicalArtifact(promptProfile, promptProfile.format).ref;

  const vocabularyWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-byte-bpe-vocabulary-v1' as const,
    tokens: Array.from({ length: 256 }, (_, tokenId) => ({
      tokenId,
      bytesBase64url: Buffer.from([tokenId]).toString('base64url')
    }))
  };
  const vocabulary: TokenizerVocabularyV1 = {
    ...vocabularyWithoutDigest,
    vocabularyDigest: canonicalSha256(vocabularyWithoutDigest)
  };
  const vocabularyRef = planCanonicalArtifact(vocabulary, vocabulary.format).ref;
  const mergeWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-byte-bpe-merge-ranks-v1' as const,
    merges: []
  };
  const mergeRanks: TokenizerMergeRanksV1 = {
    ...mergeWithoutDigest,
    mergeRanksDigest: canonicalSha256(mergeWithoutDigest)
  };
  const mergeRanksRef = planCanonicalArtifact(mergeRanks, mergeRanks.format).ref;
  const tokenizerWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-tokenizer-profile-v1' as const,
    provider: 'openai' as const,
    model: 'model-1',
    algorithm: 'cliq-byte-bpe-v1' as const,
    vocabularyRef,
    vocabularyDigest: vocabulary.vocabularyDigest,
    mergeRanksRef,
    mergeRanksDigest: mergeRanks.mergeRanksDigest,
    specialTokenPolicy: 'disabled_profile_framing_only' as const,
    goldenVectors: [
      ...renderedPrompts.map((normalRendered) => ({
        renderedBytesBase64url: normalRendered.toString('base64url'),
        tokenIds: [...normalRendered]
      })),
      {
        renderedBytesBase64url: compactionRendered.toString('base64url'),
        tokenIds: [...compactionRendered]
      }
    ]
  };
  const tokenizerProfile: TokenizerProfileV1 = {
    ...tokenizerWithoutDigest,
    profileDigest: canonicalSha256(tokenizerWithoutDigest)
  };
  const tokenizerProfileRef = planCanonicalArtifact(tokenizerProfile, tokenizerProfile.format).ref;

  const serializedNormal = visibleSources.map((source) =>
    serializeNativeRequestV1({
      algorithm: 'cliq-openai-chat-completions-json-v1',
      requestKind: 'normal',
      provider: 'openai',
      model: 'model-1',
      negotiatedMode: 'native-tools',
      maximumOutputTokens: 4096,
      sourceJcsUtf8: source
    })
  );
  const serializedCompaction = serializeNativeRequestV1({
    algorithm: 'cliq-openai-chat-completions-json-v1',
    requestKind: 'compaction',
    provider: 'openai',
    model: 'model-1',
    negotiatedMode: 'text-only',
    maximumOutputTokens: 4096,
    sourceJcsUtf8: compactionSource
  });
  const nativeWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-provider-native-request-profile-v1' as const,
    provider: 'openai' as const,
    model: 'model-1',
    algorithm: 'cliq-openai-chat-completions-json-v1' as const,
    requestPath: '/chat/completions',
    mediaType: 'application/json' as const,
    goldenVectors: [
      ...visibleSources.map((source, index) => ({
        requestKind: 'normal' as const,
        negotiatedMode: 'native-tools' as const,
        maximumOutputTokens: 4096,
        sourceJcsUtf8: source,
        bodyBytesBase64url: Buffer.from(serializedNormal[index]!.bodyBytes).toString('base64url'),
        inputTokenCount: renderedPrompts[index]!.byteLength
      })),
      {
        requestKind: 'compaction' as const,
        negotiatedMode: 'text-only' as const,
        maximumOutputTokens: 4096,
        sourceJcsUtf8: compactionSource,
        bodyBytesBase64url: Buffer.from(serializedCompaction.bodyBytes).toString('base64url'),
        inputTokenCount: compactionRendered.byteLength
      }
    ]
  };
  const nativeProfile: ProviderNativeRequestProfileV1 = {
    ...nativeWithoutDigest,
    profileDigest: canonicalSha256(nativeWithoutDigest)
  };
  const nativeProfileRef = planCanonicalArtifact(nativeProfile, nativeProfile.format).ref;

  const promptManifestRef = ref(10);
  const promptManifestDigest = ref(11);
  const tokenizerManifestRef = ref(12);
  const tokenizerManifestDigest = ref(13);
  const toolManifestRef = ref(14);
  const toolManifestDigest = ref(15);
  const providerCredentialRef = ref(20);
  const additionalCredentialRef = ref(21);
  const c = 32_768;
  const o = 4096;
  const h = c - o;
  const k = 100;
  const assemblyWithoutDigest: Omit<RunAssemblyV1, 'assemblyDigest'> = {
    schemaVersion: 1 as const,
    format: 'cliq-run-assembly-v1' as const,
    provider: {
      name: 'openai' as const,
      model: 'model-1',
      endpoint: {
        kind: 'registered' as const,
        registrationKind: 'user' as const,
        endpointRegistrationRef: ref(16),
        endpointIdentityDigest,
        tlsPolicyDigest: ref(17)
      },
      credentialGrantRefs: [providerCredentialRef],
      adapter,
      nativeRequestProfileRef: nativeProfileRef,
      nativeRequestProfileDigest: nativeProfile.profileDigest,
      negotiation: {
        mode: 'native-tools' as const,
        capabilityEvidenceRef: capabilityRef,
        capabilityDigest: capability.evidenceDigest,
        ...CLAIMS,
        exposedToolNames: ['read_file']
      },
      pricing: {
        kind: 'trusted_price_table' as const,
        priceTableRef,
        priceTableDigest: priceTable.tableDigest,
        calculationAlgorithm: 'cliq-price-ceil-v1' as const,
        maxRunCostMicros: 10_000_000,
        validThrough: priceTable.validThrough,
        provenanceRef: priceProvenanceRef
      }
    },
    mcpServers: [],
    tools: { manifestRef: toolManifestRef, manifestDigest: toolManifestDigest },
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
      sandboxBackend: 'linux_namespace' as const
    },
    retry: {
      model: {
        maxDispatchedAttempts: 3 as const,
        maxZeroByteTransportRetriesPerAttempt: 0 as const,
        postAttemptDelaysMs: [500, 2000] as [500, 2000]
      },
      tools: [
        {
          toolName: 'read_file',
          replayClass: 'retry',
          maxDispatchedAttempts: 3,
          postAttemptDelaysMs: [500, 2000]
        }
      ]
    },
    context: {
      promptTemplateRef: promptManifestRef,
      promptTemplateDigest: promptManifestDigest,
      tokenizerRef: tokenizerManifestRef,
      tokenizerDigest: tokenizerManifestDigest,
      tokenizerVersion: '1.0.0',
      compactionPromptEnvelopeRef: ref(40),
      compactionPromptEnvelopeDigest: ref(41),
      contextLimitTokens: c,
      reservedOutputTokens: o,
      hardPromptTokens: h,
      triggerThresholdTokens: Math.min(Number((7n * BigInt(c)) / 10n), h - 8192),
      protectedRecentTokens: Math.min(32_768, Math.floor(c / 4)),
      summaryTokenCap: Math.min(8192, Math.floor(c / 8)),
      compactionEnvelopeTokens: k,
      sourceInputTokenCap: Math.min(Math.floor(c / 2), c - Math.min(8192, Math.floor(c / 8)) - k),
      maxSummaryBytes: 262_144 as const
    },
    createdAt: '2026-09-05T00:00:00.000Z'
  };
  const assembly = {
    ...assemblyWithoutDigest,
    assemblyDigest: canonicalSha256(assemblyWithoutDigest)
  } satisfies RunAssemblyV1;
  const assemblyRef = planCanonicalArtifact(assembly, assembly.format).ref;

  const material: RunAssemblyValidationMaterial = {
    capabilityEvidence: { ref: capabilityRef, value: capability },
    resolveVerifiedCapabilityClaims: () => ({ ...CLAIMS }),
    priceTable: { ref: priceTableRef, value: priceTable },
    verifyLocalZeroCostAuthority: () => false,
    resolvePriceTableAuthority: () => priceProvenanceRef,
    nativeRequestProfile: { ref: nativeProfileRef, value: nativeProfile },
    promptSerialization: {
      manifestRef: promptManifestRef,
      manifestDigest: promptManifestDigest,
      profileRef: promptProfileRef,
      profile: promptProfile
    },
    tokenizer: {
      manifestRef: tokenizerManifestRef,
      manifestDigest: tokenizerManifestDigest,
      entryVersion: '1.0.0',
      authority: {
        profileRef: tokenizerProfileRef,
        profile: tokenizerProfile,
        vocabularyRef,
        vocabulary,
        mergeRanksRef,
        mergeRanks
      }
    },
    tools: {
      ref: toolManifestRef,
      digest: toolManifestDigest,
      entries: [{ name: 'read_file', replayClass: 'retry' }]
    },
    additionalCredentialGrantRefs: [additionalCredentialRef],
    compactionEnvelopeTokenCount: k,
    verifyReference: () => true,
    verifyProviderAdapter: () => true,
    verifyProviderEndpoint: ({ endpoint, credentialGrantRefs }) =>
      endpoint.kind === 'registered' &&
      endpoint.endpointRegistrationRef === ref(16) &&
      endpoint.endpointIdentityDigest === endpointIdentityDigest &&
      endpoint.tlsPolicyDigest === ref(17) &&
      credentialGrantRefs.length === 1 &&
      credentialGrantRefs[0] === providerCredentialRef
  };
  return {
    assemblyRef,
    assembly,
    admittedAt: '2026-09-05T00:00:01.000Z',
    deadlineAt: '2026-09-06T00:00:00.000Z',
    maxRunCostMicros: 10_000_000,
    runSpecCredentialGrantRefs: [providerCredentialRef, additionalCredentialRef].sort(),
    material
  };
}

function reseal(input: ValidateRunAssemblyInput): void {
  const withoutDigest = { ...input.assembly };
  delete (withoutDigest as Partial<RunAssemblyV1>).assemblyDigest;
  input.assembly.assemblyDigest = canonicalSha256(withoutDigest);
  input.assemblyRef = planCanonicalArtifact(input.assembly, input.assembly.format).ref;
}

test('validateRunAssembly closes model authority across capability, pricing, tools, retry, and context', () => {
  const input = testFixture();
  const result = validateRunAssembly(input);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.authority.provider, 'openai');
  assert.equal(result.authority.negotiatedMode, 'native-tools');
  assert.equal(result.authority.maximumOutputTokens, 4096);
  assert.deepEqual(result.authority.exposedToolNames, ['read_file']);
  assert.equal(result.authority.pricing.kind, 'trusted_price_table');
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
