import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { ProviderName } from '../kernel/types.js';
import type { AgentNegotiatedMode } from '../protocol/agent-ir.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { compileModelObservation } from './attempt.js';
import { calculateModelCostMicros, type ModelPriceTableV1, type ValidatedModelPricing } from './pricing.js';
import { observeProviderResponse } from './provider-observation.js';
import {
  MODEL_VISIBLE_COMPACTION_FORMAT,
  prepareCompactionModelAttempt,
  prepareNormalModelAttempt,
  projectModelVisiblePrompt,
  serializeNativeRequestV1,
  type ModelVisiblePromptV1,
  type CompactionPromptEnvelopeMaterial,
  type CompactionPromptEnvelopeV1,
  type NormalModelAttemptAuthority,
  type NormalPromptProjectionV1,
  type PromptSerializationProfileV1,
  type ProviderNativeRequestAlgorithm,
  type ProviderNativeRequestProfileV1
} from './request.js';
import type {
  ByteBpeTokenizerAuthority,
  TokenizerMergeRanksV1,
  TokenizerProfileV1,
  TokenizerVocabularyV1
} from './tokenizer.js';

const REF = {
  promptManifest: '1'.repeat(64),
  promptManifestDigest: '2'.repeat(64),
  tokenizerManifest: '3'.repeat(64),
  tokenizerManifestDigest: '4'.repeat(64),
  frontier: '5'.repeat(64),
  runSpec: '6'.repeat(64),
  assembly: '7'.repeat(64),
  assemblyDigest: '8'.repeat(64),
  context: '9'.repeat(64),
  contextDigest: 'a'.repeat(64),
  inputSchema: 'b'.repeat(64),
  inputSchemaDigest: 'c'.repeat(64),
  callInput: 'd'.repeat(64),
  callInputDigest: 'e'.repeat(64)
};

const ALGORITHMS: Record<ProviderName, ProviderNativeRequestAlgorithm> = {
  openai: 'cliq-openai-chat-completions-json-v1',
  anthropic: 'cliq-anthropic-messages-json-v1',
  openrouter: 'cliq-openrouter-chat-completions-json-v1',
  'openai-compatible': 'cliq-openai-compatible-chat-completions-json-v1',
  zhipu: 'cliq-zhipu-chat-completions-json-v1',
  ollama: 'cliq-ollama-chat-json-v1'
};

const PATHS: Record<ProviderName, string> = {
  openai: '/chat/completions',
  anthropic: '/v1/messages',
  openrouter: '/chat/completions',
  'openai-compatible': '/chat/completions',
  zhipu: '/chat/completions',
  ollama: '/api/chat'
};

function projection(mode: AgentNegotiatedMode, suffix = ''): { ref: string; value: NormalPromptProjectionV1 } {
  const tools =
    mode === 'text-only'
      ? []
      : [
          {
            index: 0,
            name: 'read_file',
            description: 'Read a workspace file.',
            inputSchemaRef: REF.inputSchema,
            inputSchemaDigest: REF.inputSchemaDigest,
            inputSchema: {
              type: 'object',
              additionalProperties: false,
              required: ['path'],
              properties: { path: { type: 'string' } }
            }
          }
        ];
  const messages: NormalPromptProjectionV1['messages'] = [
    {
      index: 0,
      role: 'system',
      sourceKind: 'assembly_instructions',
      sourceId: REF.assembly,
      contentUtf8: 'Use tools carefully.'
    },
    ...(mode === 'text-only'
      ? []
      : [
          {
            index: 1,
            role: 'assistant' as const,
            sourceItemId: 'item-1',
            contentUtf8: '',
            toolCalls: [
              {
                callId: 'call-1',
                index: 0,
                toolName: 'read_file',
                inputRef: REF.callInput,
                inputDigest: REF.callInputDigest,
                argumentsUtf8: '{"path":"README.md"}'
              }
            ]
          },
          {
            index: 2,
            role: 'tool' as const,
            sourceItemId: 'item-2',
            toolCallId: 'call-1',
            contentUtf8: 'contents'
          }
        ]),
    {
      index: mode === 'text-only' ? 1 : 3,
      role: 'user',
      sourceKind: 'run_objective',
      sourceId: 'objective',
      contentUtf8: `Finish the task${suffix}`
    }
  ];
  const withoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-normal-prompt-projection-v1' as const,
    runId: 'run-1',
    basedOnRunRevision: 4,
    frontierDigest: REF.frontier,
    runSpecRef: REF.runSpec,
    assemblyRef: REF.assembly,
    assemblyDigest: REF.assemblyDigest,
    contextManifestRef: REF.context,
    contextManifestDigest: REF.contextDigest,
    messages,
    tools
  };
  const value: NormalPromptProjectionV1 = {
    ...withoutDigest,
    projectionDigest: canonicalSha256(withoutDigest)
  };
  return { ref: planCanonicalArtifact(value, value.format).ref, value };
}

function visibleSource(mode: AgentNegotiatedMode, suffix = ''): string {
  return canonicalJsonBytes(projectModelVisiblePrompt(projection(mode, suffix).value, mode)).toString('utf8');
}

function compactionSource(suffix = ''): string {
  const value: ModelVisiblePromptV1 = {
    format: MODEL_VISIBLE_COMPACTION_FORMAT,
    messages: [
      { role: 'system', contentUtf8: 'Summarize faithfully.' },
      { role: 'user', contentUtf8: `Source context${suffix}` }
    ],
    tools: [],
    responseContract: {
      toolsAllowed: false,
      requiredStopReason: 'end',
      mediaType: 'text/markdown; charset=utf-8',
      summaryFormat: 'cliq-context-summary-markdown-v1'
    }
  };
  return canonicalJsonBytes(value).toString('utf8');
}

function byteTokenizer(
  provider: ProviderName,
  sources: Array<{ kind: 'normal' | 'compaction'; source: string }>,
  prefix: string,
  suffix: string,
  compactionPrefix: string,
  compactionSuffix: string
): ByteBpeTokenizerAuthority {
  const tokens = Array.from({ length: 256 }, (_, tokenId) => ({
    tokenId,
    bytesBase64url: Buffer.from([tokenId]).toString('base64url')
  }));
  const vocabularyWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-byte-bpe-vocabulary-v1' as const,
    tokens
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
  const profileWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-tokenizer-profile-v1' as const,
    provider,
    model: 'model-1',
    algorithm: 'cliq-byte-bpe-v1' as const,
    vocabularyRef,
    vocabularyDigest: vocabulary.vocabularyDigest,
    mergeRanksRef,
    mergeRanksDigest: mergeRanks.mergeRanksDigest,
    specialTokenPolicy: 'disabled_profile_framing_only' as const,
    goldenVectors: sources.map(({ kind, source }) => {
      const rendered = Buffer.from(
        `${kind === 'normal' ? prefix : compactionPrefix}${source}${kind === 'normal' ? suffix : compactionSuffix}`
      );
      return {
        renderedBytesBase64url: rendered.toString('base64url'),
        tokenIds: [...rendered]
      };
    })
  };
  const profile: TokenizerProfileV1 = {
    ...profileWithoutDigest,
    profileDigest: canonicalSha256(profileWithoutDigest)
  };
  return {
    profileRef: planCanonicalArtifact(profile, profile.format).ref,
    profile,
    vocabularyRef,
    vocabulary,
    mergeRanksRef,
    mergeRanks
  };
}

function pricing(): ValidatedModelPricing {
  const table = {
    schemaVersion: 1,
    format: 'cliq-model-price-table-v1',
    signerKeyId: 'test-key',
    signatureAlgorithm: 'ed25519',
    signatureRef: 'f'.repeat(64),
    provider: 'openai',
    model: 'model-1',
    endpointIdentityDigest: '0'.repeat(64),
    currency: 'USD',
    unit: 'micros_per_million_tokens',
    prices: { input: 1_000_000, output: 2_000_000, cacheRead: 500_000, cacheWrite: 1_500_000 },
    validFrom: '2026-09-05T00:00:00.000Z',
    validThrough: '2026-09-06T00:00:00.000Z',
    tableDigest: 'a'.repeat(64)
  } satisfies ModelPriceTableV1;
  return {
    kind: 'trusted_price_table',
    bound: {
      kind: 'trusted_price_table',
      priceTableRef: 'b'.repeat(64),
      priceTableDigest: table.tableDigest,
      calculationAlgorithm: 'cliq-price-ceil-v1',
      maxRunCostMicros: 10_000_000,
      validThrough: table.validThrough,
      provenanceRef: 'c'.repeat(64)
    },
    table
  };
}

function authority(provider: ProviderName = 'openai', mode: AgentNegotiatedMode = 'native-tools') {
  const prefix = '<normal>';
  const suffix = '</normal>';
  const compactPrefix = '<compact>';
  const compactSuffix = '</compact>';
  const sources: Array<{
    kind: 'normal' | 'compaction';
    mode: AgentNegotiatedMode;
    source: string;
  }> = Array.from({ length: 7 }, (_, index) => ({
    kind: 'normal' as const,
    mode,
    source: visibleSource(mode, ` ${index}`)
  }));
  sources.push({ kind: 'compaction', mode: 'text-only', source: compactionSource(' 7') });
  const promptWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-prompt-serialization-profile-v1' as const,
    provider,
    model: 'model-1',
    algorithm: 'cliq-jcs-framed-chat-v1' as const,
    normalPrefixUtf8: prefix,
    normalSuffixUtf8: suffix,
    compactionPrefixUtf8: compactPrefix,
    compactionSuffixUtf8: compactSuffix,
    goldenVectors: sources.map(({ kind, source }) => ({
      payloadJcsUtf8: source,
      renderedBytesBase64url: Buffer.from(
        `${kind === 'normal' ? prefix : compactPrefix}${source}${kind === 'normal' ? suffix : compactSuffix}`
      ).toString('base64url')
    }))
  };
  const promptProfile: PromptSerializationProfileV1 = {
    ...promptWithoutDigest,
    profileDigest: canonicalSha256(promptWithoutDigest)
  };
  const tokenizer = byteTokenizer(provider, sources, prefix, suffix, compactPrefix, compactSuffix);
  const algorithm = ALGORITHMS[provider];
  const nativeWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-provider-native-request-profile-v1' as const,
    provider,
    model: 'model-1',
    algorithm,
    requestPath: PATHS[provider],
    mediaType: 'application/json' as const,
    goldenVectors: sources.map(({ kind, mode: vectorMode, source }) => {
      const output = serializeNativeRequestV1({
        algorithm,
        requestKind: kind,
        provider,
        model: 'model-1',
        negotiatedMode: vectorMode,
        maximumOutputTokens: 256,
        sourceJcsUtf8: source
      });
      const rendered = Buffer.from(
        `${kind === 'normal' ? prefix : compactPrefix}${source}${kind === 'normal' ? suffix : compactSuffix}`
      );
      return {
        requestKind: kind,
        negotiatedMode: vectorMode,
        maximumOutputTokens: 256,
        sourceJcsUtf8: source,
        bodyBytesBase64url: Buffer.from(output.bodyBytes).toString('base64url'),
        inputTokenCount: rendered.byteLength
      };
    })
  };
  const nativeProfile: ProviderNativeRequestProfileV1 = {
    ...nativeWithoutDigest,
    profileDigest: canonicalSha256(nativeWithoutDigest)
  };
  const result: NormalModelAttemptAuthority = {
    provider,
    model: 'model-1',
    negotiatedMode: mode,
    contextLimitTokens: 131_072,
    maximumOutputTokens: 256,
    maximumCompactionOutputTokens: 128,
    exposedToolNames: mode === 'text-only' ? [] : ['read_file'],
    pricing: pricing(),
    promptSerializationRef: REF.promptManifest,
    promptSerializationDigest: REF.promptManifestDigest,
    promptSerializationProfileRef: planCanonicalArtifact(promptProfile, promptProfile.format).ref,
    promptSerializationProfile: promptProfile,
    nativeRequestProfileRef: planCanonicalArtifact(nativeProfile, nativeProfile.format).ref,
    nativeRequestProfile: nativeProfile,
    tokenizerRef: REF.tokenizerManifest,
    tokenizerDigest: REF.tokenizerManifestDigest,
    tokenizer
  };
  return result;
}

test('prepareNormalModelAttempt produces deterministic exact bytes, artifacts, counts, and reservation', () => {
  const prompt = projection('native-tools');
  const input = {
    authority: authority(),
    invocation: { runId: 'run-1', opId: 'model-op-1', attempt: 1 },
    projectionRef: prompt.ref,
    projection: prompt.value
  };
  const first = prepareNormalModelAttempt(input);
  const second = prepareNormalModelAttempt(input);
  assert.deepEqual(first.request, second.request);
  assert.deepEqual(first.outbound.bodyBytes, second.outbound.bodyBytes);
  assert.equal(first.requestRef, second.requestRef);
  assert.equal(first.outbound.bodyBytesRef, first.nativeRequest.bodyBytesRef);
  assert.equal(first.nativeRequest.bodyBytesRef, first.nativeRequest.bodyBytesDigest);
  assert.equal(first.nativeRequest.bodyByteCount, first.outbound.bodyBytes.byteLength);
  assert.equal(first.request.inputTokenCount, first.renderedPromptBytes.byteLength);
  assert.equal(first.request.reservation.inputTokens, first.request.inputTokenCount);
  assert.equal(first.request.reservation.outputTokens, 256);
  assert.equal(first.request.reservation.cacheReadTokens, first.request.inputTokenCount);
  assert.equal(first.request.reservation.cacheWriteTokens, first.request.inputTokenCount);
  assert.equal(first.request.reservation.modelTokens, first.request.inputTokenCount + 256);
  assert.equal(
    first.request.reservation.costMicros,
    first.request.inputTokenCount +
      512 +
      Math.ceil(first.request.inputTokenCount / 2) +
      Math.ceil((first.request.inputTokenCount * 3) / 2)
  );

  const bodySource = Buffer.from(first.outbound.bodyBytes).toString('utf8');
  const body = parseJsonStrict(bodySource) as Record<string, unknown>;
  assert.equal(body.model, 'model-1');
  assert.equal(body.stream, false);
  assert.equal(body.max_completion_tokens, 256);
  assert.equal(hasOwn(body, 'max_tokens'), false);
  assert.ok(Array.isArray(body.tools));
  assert.equal(hasOwn(((body.tools as Array<Record<string, unknown>>)[0]?.function as Record<string, unknown>), 'strict'), false);
  assert.ok(!bodySource.includes('sourceItemId'));
  assert.ok(!bodySource.includes(REF.callInput));
  assert.equal(first.artifacts.length, 3);
  for (const artifact of first.artifacts) {
    assert.equal(artifact.ref, sha256Bytes(artifact.bytes));
  }
});

test('trusted model attempt composes preparation, wire observation, and Agent IR compilation', () => {
  const prompt = projection('native-tools');
  const modelAuthority = authority();
  const prepared = prepareNormalModelAttempt({
    authority: modelAuthority,
    invocation: { runId: 'run-1', opId: 'model-op-1', attempt: 1 },
    projectionRef: prompt.ref,
    projection: prompt.value
  });
  const observed = observeProviderResponse({
    provider: 'openai',
    model: 'model-1',
    negotiatedMode: 'native-tools',
    status: 200,
    mediaType: 'application/json',
    bytes: canonicalJsonBytes({
      id: 'response-1',
      model: 'model-1',
      choices: [
        {
          index: 0,
          finish_reason: 'tool_calls',
          message: {
            content: 'I will read it.',
            tool_calls: [
              {
                id: 'call-2',
                type: 'function',
                function: { name: 'read_file', arguments: '{"path":"README.md"}' }
              }
            ]
          }
        }
      ],
      usage: { prompt_tokens: prepared.request.inputTokenCount, completion_tokens: 8 }
    }),
    observedAt: '2026-09-05T00:00:00.000Z'
  });
  assert.equal(observed.observation.kind, 'decoded');
  const compiled = compileModelObservation({
    runId: 'run-1',
    opId: 'model-op-1',
    attempt: 1,
    request: {
      kind: 'normal',
      requestRef: prepared.requestRef,
      requestDigest: prepared.request.requestDigest
    },
    provider: 'openai',
    model: 'model-1',
    negotiatedMode: 'native-tools',
    promptProjectionRef: prompt.ref,
    promptProjectionDigest: prompt.value.projectionDigest,
    reservedModelTokens: prepared.request.reservation.modelTokens,
    observation: observed.observation,
    resolveToolInput({ toolName, observedInput }) {
      assert.equal(toolName, 'read_file');
      assert.equal(observedInput.encoding, 'jcs_json');
      return {
        kind: 'resolved',
        inputSchemaRef: REF.inputSchema,
        inputSchemaDigest: REF.inputSchemaDigest,
        value: observedInput.encoding === 'jcs_json'
          ? (observedInput.value as Record<string, unknown>)
          : {}
      };
    },
    calculateUsageCostMicros(usage) {
      if (modelAuthority.pricing.kind !== 'trusted_price_table') throw new Error('expected priced fixture');
      return calculateModelCostMicros(usage, modelAuthority.pricing.table.prices);
    }
  });
  assert.equal(compiled.kind, 'usable');
  assert.equal(compiled.kind === 'usable' ? compiled.turn.stopReason : undefined, 'tool_calls');
  if (compiled.kind !== 'usable' || compiled.turn.stopReason !== 'tool_calls') return;
  assert.deepEqual(compiled.turn.toolCalls.map(({ callId, index, toolName }) => ({ callId, index, toolName })), [
    { callId: 'call-2', index: 0, toolName: 'read_file' }
  ]);
  const [toolCall] = compiled.turn.toolCalls;
  assert.ok(toolCall);
  const input = compiled.artifacts.find((artifact) => artifact.ref === toolCall.inputRef);
  assert.ok(input);
  assert.equal((parseJsonStrict(Buffer.from(input.bytes).toString('utf8')) as Record<string, unknown>).disposition, 'resolved');
});

test('native serializers cover all six provider algorithms without SDK defaults', () => {
  for (const provider of Object.keys(ALGORITHMS) as ProviderName[]) {
    const mode: AgentNegotiatedMode = 'native-tools';
    const output = serializeNativeRequestV1({
      algorithm: ALGORITHMS[provider],
      requestKind: 'normal',
      provider,
      model: 'model-1',
      negotiatedMode: mode,
      maximumOutputTokens: 512,
      sourceJcsUtf8: visibleSource(mode)
    });
    assert.equal(output.requestPath, PATHS[provider], provider);
    assert.equal(output.mediaType, 'application/json', provider);
    const body = parseJsonStrict(Buffer.from(output.bodyBytes).toString('utf8')) as Record<string, unknown>;
    assert.equal(body.model, 'model-1', provider);
    assert.equal(body.stream, false, provider);
    assert.ok(Array.isArray(body.tools), provider);
    if (provider === 'anthropic') {
      assert.equal(body.system, 'Use tools carefully.');
      assert.equal(body.max_tokens, 512);
    } else if (provider === 'ollama') {
      assert.deepEqual(JSON.parse(JSON.stringify(body.options)), { num_predict: 512 });
      const messages = body.messages as Array<Record<string, unknown>>;
      const assistant = messages[1] as Record<string, unknown>;
      const call = (assistant.tool_calls as Array<Record<string, unknown>>)[0] as Record<string, unknown>;
      assert.deepEqual(JSON.parse(JSON.stringify(call)), {
        type: 'function',
        function: { index: 0, name: 'read_file', arguments: { path: 'README.md' } }
      });
      assert.deepEqual(JSON.parse(JSON.stringify(messages[2])), {
        role: 'tool',
        tool_name: 'read_file',
        content: 'contents'
      });
    } else {
      if (provider === 'openai' || provider === 'openrouter') {
        assert.equal(body.max_completion_tokens, 512);
        assert.equal(hasOwn(body, 'max_tokens'), false);
      } else {
        assert.equal(body.max_tokens, 512);
        assert.equal(hasOwn(body, 'max_completion_tokens'), false);
      }
      assert.equal(body.tool_choice, 'auto');
    }
  }
});

test('native serializer rejects runtime enum injection before selecting a serializer branch', () => {
  const valid = {
    algorithm: ALGORITHMS.openai,
    requestKind: 'normal',
    provider: 'openai',
    model: 'model-1',
    negotiatedMode: 'native-tools',
    maximumOutputTokens: 512,
    sourceJcsUtf8: visibleSource('native-tools')
  };
  const serialize = (override: Record<string, unknown>) =>
    serializeNativeRequestV1({
      ...valid,
      ...override
    } as unknown as Parameters<typeof serializeNativeRequestV1>[0]);

  assert.throws(() => serialize({ provider: 'toString' }), /provider is invalid/u);
  assert.throws(() => serialize({ algorithm: 'toString' }), /algorithm is invalid/u);
  assert.throws(() => serialize({ requestKind: 'future-kind' }), /request kind is invalid/u);
  assert.throws(() => serialize({ negotiatedMode: 'future-mode' }), /negotiated mode is invalid/u);
});

test('object-only providers retain malformed historical tool input in a valid object envelope', () => {
  const visible = projectModelVisiblePrompt(projection('native-tools').value, 'native-tools');
  const assistant = visible.messages[1];
  assert.equal(assistant?.role, 'assistant');
  if (assistant?.role !== 'assistant') throw new Error('expected assistant fixture');
  assistant.toolCalls[0]!.argumentsUtf8 = '{"path":';
  const sourceJcsUtf8 = canonicalJsonBytes(visible).toString('utf8');

  for (const provider of ['anthropic', 'ollama'] as const) {
    const output = serializeNativeRequestV1({
      algorithm: ALGORITHMS[provider],
      requestKind: 'normal',
      provider,
      model: 'model-1',
      negotiatedMode: 'native-tools',
      maximumOutputTokens: 512,
      sourceJcsUtf8
    });
    const body = parseJsonStrict(Buffer.from(output.bodyBytes).toString('utf8')) as Record<string, unknown>;
    const messages = body.messages as Array<Record<string, unknown>>;
    const providerAssistant = provider === 'anthropic' ? messages[0]! : messages[1]!;
    const blocks = provider === 'anthropic'
      ? (providerAssistant.content as Array<Record<string, unknown>>)
      : (providerAssistant.tool_calls as Array<Record<string, unknown>>);
    const call = blocks.find((entry) => provider === 'anthropic' ? entry.type === 'tool_use' : true)!;
    const providerInput = provider === 'anthropic'
      ? call.input
      : (call.function as Record<string, unknown>).arguments;
    assert.deepEqual(JSON.parse(JSON.stringify(providerInput)), {
      __cliqRetainedInput: {
        format: 'cliq-retained-provider-tool-input-v1',
        encoding: 'utf8_json_fragment',
        utf8: '{"path":'
      }
    });
  }
});

test('constrained IR is emitted only through provider-enforced schema mechanisms', () => {
  for (const provider of ['openai', 'openrouter', 'openai-compatible', 'ollama'] as const) {
    const output = serializeNativeRequestV1({
      algorithm: ALGORITHMS[provider],
      requestKind: 'normal',
      provider,
      model: 'model-1',
      negotiatedMode: 'constrained-ir',
      maximumOutputTokens: 256,
      sourceJcsUtf8: visibleSource('constrained-ir')
    });
    const body = parseJsonStrict(Buffer.from(output.bodyBytes).toString('utf8')) as Record<string, unknown>;
    assert.equal(hasOwn(body, 'tools'), false, provider);
    assert.equal(hasOwn(body, provider === 'ollama' ? 'format' : 'response_format'), true, provider);
    const schema =
      provider === 'ollama'
        ? body.format
        : (((body.response_format as Record<string, unknown>).json_schema as Record<string, unknown>)
            .schema as Record<string, unknown>);
    assert.equal((schema as Record<string, unknown>).type, 'object', provider);
    assert.equal(hasOwn(schema as Record<string, unknown>, 'anyOf'), false, provider);
    const properties = (schema as Record<string, unknown>).properties as Record<string, unknown>;
    const turn = properties.turn as Record<string, unknown>;
    assert.ok(Array.isArray(turn.anyOf), provider);
  }
  for (const provider of ['anthropic', 'zhipu'] as const) {
    assert.throws(
      () =>
        serializeNativeRequestV1({
          algorithm: ALGORITHMS[provider],
          requestKind: 'normal',
          provider,
          model: 'model-1',
          negotiatedMode: 'constrained-ir',
          maximumOutputTokens: 256,
          sourceJcsUtf8: visibleSource('constrained-ir')
        }),
      /does not implement constrained IR/u
    );
  }
});

test('text-only mode carries JSON-looking model content only as inert message text', () => {
  const source = visibleSource('text-only', ' {"bash":"do-not-run"}');
  const output = serializeNativeRequestV1({
    algorithm: ALGORITHMS.openai,
    requestKind: 'normal',
    provider: 'openai',
    model: 'model-1',
    negotiatedMode: 'text-only',
    maximumOutputTokens: 256,
    sourceJcsUtf8: source
  });
  const body = parseJsonStrict(Buffer.from(output.bodyBytes).toString('utf8')) as Record<string, unknown>;
  assert.equal(hasOwn(body, 'tools'), false);
  assert.equal(hasOwn(body, 'response_format'), false);
  assert.ok(Buffer.from(output.bodyBytes).toString('utf8').includes('do-not-run'));
});

test('normal model-visible projection is the exact ref-free RFC payload', () => {
  const projected = projectModelVisiblePrompt(projection('native-tools').value, 'native-tools');
  assert.equal(projected.format, 'cliq-model-visible-prompt-v1');
  assert.deepEqual(projected.responseContract, { mode: 'native-tools', toolCallsAllowed: true });
  assert.deepEqual(projected.tools.map(({ index, name }) => ({ index, name })), [
    { index: 0, name: 'read_file' }
  ]);
  const assistant = projected.messages[1];
  assert.equal(assistant?.role, 'assistant');
  if (assistant?.role !== 'assistant') throw new Error('expected assistant fixture');
  assert.deepEqual(assistant.toolCalls.map(({ callId, index }) => ({ callId, index })), [
    { callId: 'call-1', index: 0 }
  ]);
  const source = canonicalJsonBytes(projected).toString('utf8');
  for (const forbidden of ['sourceItemId', 'sourceKind', 'sourceId', 'inputRef', 'inputDigest', REF.assembly]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
});

test('signed prompt and native request profiles require unique conformance vectors', () => {
  const prompt = projection('native-tools');
  const duplicatePrompt = authority();
  duplicatePrompt.promptSerializationProfile.goldenVectors[1] = {
    ...duplicatePrompt.promptSerializationProfile.goldenVectors[0]!
  };
  const promptProfileWithoutDigest = { ...duplicatePrompt.promptSerializationProfile };
  delete (promptProfileWithoutDigest as Partial<PromptSerializationProfileV1>).profileDigest;
  duplicatePrompt.promptSerializationProfile.profileDigest = canonicalSha256(promptProfileWithoutDigest);
  duplicatePrompt.promptSerializationProfileRef = planCanonicalArtifact(
    duplicatePrompt.promptSerializationProfile,
    duplicatePrompt.promptSerializationProfile.format
  ).ref;
  assert.throws(
    () =>
      prepareNormalModelAttempt({
        authority: duplicatePrompt,
        invocation: { runId: 'run-1', opId: 'model-op-1', attempt: 1 },
        projectionRef: prompt.ref,
        projection: prompt.value
      }),
    /golden vectors must be unique/u
  );

  const duplicateNative = authority();
  duplicateNative.nativeRequestProfile.goldenVectors[1] = {
    ...duplicateNative.nativeRequestProfile.goldenVectors[0]!
  };
  const nativeProfileWithoutDigest = { ...duplicateNative.nativeRequestProfile };
  delete (nativeProfileWithoutDigest as Partial<ProviderNativeRequestProfileV1>).profileDigest;
  duplicateNative.nativeRequestProfile.profileDigest = canonicalSha256(nativeProfileWithoutDigest);
  duplicateNative.nativeRequestProfileRef = planCanonicalArtifact(
    duplicateNative.nativeRequestProfile,
    duplicateNative.nativeRequestProfile.format
  ).ref;
  assert.throws(
    () =>
      prepareNormalModelAttempt({
        authority: duplicateNative,
        invocation: { runId: 'run-1', opId: 'model-op-1', attempt: 1 },
        projectionRef: prompt.ref,
        projection: prompt.value
      }),
    /golden vectors must be unique/u
  );
});

test('request preparation rejects profile tampering, projection extensions, tool drift, and context overflow', () => {
  const prompt = projection('native-tools');
  const tampered = authority();
  tampered.nativeRequestProfile.requestPath = '/other';
  assert.throws(
    () =>
      prepareNormalModelAttempt({
        authority: tampered,
        invocation: { runId: 'run-1', opId: 'model-op-1', attempt: 1 },
        projectionRef: prompt.ref,
        projection: prompt.value
      }),
    /profile values are invalid/u
  );

  const extendedPrompt = projection('native-tools');
  const extended = extendedPrompt.value as NormalPromptProjectionV1 & { hidden?: boolean };
  extended.hidden = true;
  assert.throws(
    () =>
      prepareNormalModelAttempt({
        authority: authority(),
        invocation: { runId: 'run-1', opId: 'model-op-1', attempt: 1 },
        projectionRef: extendedPrompt.ref,
        projection: extended
      }),
    /projection schema is invalid/u
  );

  const driftedPrompt = projection('native-tools');
  const driftedAuthority = authority();
  driftedAuthority.exposedToolNames = ['other'];
  assert.throws(
    () =>
      prepareNormalModelAttempt({
        authority: driftedAuthority,
        invocation: { runId: 'run-1', opId: 'model-op-1', attempt: 1 },
        projectionRef: driftedPrompt.ref,
        projection: driftedPrompt.value
      }),
    /frozen exposed-tool sequence/u
  );

  const overflowPrompt = projection('native-tools');
  const overflowAuthority = authority();
  overflowAuthority.contextLimitTokens = 32_768;
  overflowAuthority.maximumOutputTokens = 8_192;
  overflowPrompt.value.messages[3]!.contentUtf8 = `Finish ${'x'.repeat(30_000)}`;
  const withoutDigest = { ...overflowPrompt.value };
  delete (withoutDigest as Partial<NormalPromptProjectionV1>).projectionDigest;
  overflowPrompt.value.projectionDigest = canonicalSha256(withoutDigest);
  overflowPrompt.ref = planCanonicalArtifact(overflowPrompt.value, overflowPrompt.value.format).ref;
  assert.throws(
    () =>
      prepareNormalModelAttempt({
        authority: overflowAuthority,
        invocation: { runId: 'run-1', opId: 'model-op-1', attempt: 1 },
        projectionRef: overflowPrompt.ref,
        projection: overflowPrompt.value
      }),
    /frozen context limit/u
  );

  const unclosedPrompt = projection('native-tools');
  unclosedPrompt.value.messages.splice(2, 1);
  for (const [index, message] of unclosedPrompt.value.messages.entries()) message.index = index;
  const unclosedWithoutDigest = { ...unclosedPrompt.value };
  delete (unclosedWithoutDigest as Partial<NormalPromptProjectionV1>).projectionDigest;
  unclosedPrompt.value.projectionDigest = canonicalSha256(unclosedWithoutDigest);
  unclosedPrompt.ref = planCanonicalArtifact(unclosedPrompt.value, unclosedPrompt.value.format).ref;
  assert.throws(
    () =>
      prepareNormalModelAttempt({
        authority: authority(),
        invocation: { runId: 'run-1', opId: 'model-op-1', attempt: 1 },
        projectionRef: unclosedPrompt.ref,
        projection: unclosedPrompt.value
      }),
    /preceding tool call|unclosed tool-call batch/u
  );

  const substitutedSystem = projection('native-tools');
  const firstMessage = substitutedSystem.value.messages[0]!;
  if (firstMessage.role !== 'system') throw new Error('expected system fixture');
  firstMessage.sourceId = 'different-assembly';
  const substitutedWithoutDigest = { ...substitutedSystem.value };
  delete (substitutedWithoutDigest as Partial<NormalPromptProjectionV1>).projectionDigest;
  substitutedSystem.value.projectionDigest = canonicalSha256(substitutedWithoutDigest);
  substitutedSystem.ref = planCanonicalArtifact(substitutedSystem.value, substitutedSystem.value.format).ref;
  assert.throws(
    () =>
      prepareNormalModelAttempt({
        authority: authority(),
        invocation: { runId: 'run-1', opId: 'model-op-1', attempt: 1 },
        projectionRef: substitutedSystem.ref,
        projection: substitutedSystem.value
      }),
    /frozen assembly instruction/u
  );
});

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
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

test('prepareCompactionModelAttempt renders one retained two-message prompt with no tools', () => {
  const input = {
    authority: authority(),
    invocation: { runId: 'run-1', opId: 'compaction-op-1', attempt: 1 },
    compactionPlanRef: 'f'.repeat(64),
    envelope: compactionEnvelope(),
    sourceContextUtf8: 'first item\ne\u0301xact fragment'
  };
  const first = prepareCompactionModelAttempt(input);
  const second = prepareCompactionModelAttempt(input);
  assert.deepEqual(first.request, second.request);
  assert.deepEqual(first.outbound.bodyBytes, second.outbound.bodyBytes);
  assert.equal(first.nativeRequest.negotiatedMode, 'text-only');
  assert.equal(first.nativeRequest.source.kind, 'compaction');
  assert.equal(first.request.maximumOutputTokens, 128);
  assert.equal(first.request.renderedPromptRef, first.renderedPromptRef);
  assert.equal(first.request.renderedPromptDigest, first.renderedPromptRef);
  assert.equal(first.request.reservation.outputTokens, 128);
  assert.equal(first.artifacts.length, 4);

  const body = parseJsonStrict(Buffer.from(first.outbound.bodyBytes).toString('utf8')) as Record<string, unknown>;
  assert.equal(hasOwn(body, 'tools'), false);
  const messages = body.messages as Array<Record<string, unknown>>;
  assert.equal(messages.length, 2);
  assert.equal(messages[0]?.role, 'system');
  assert.equal(messages[1]?.role, 'user');
  assert.equal(
    messages[1]?.content,
    `${input.envelope.userPrefix.value.utf8}${input.sourceContextUtf8}${input.envelope.userSuffix.value.utf8}`
  );
});

test('compaction preparation rejects mutable envelope substitution and placeholder injection', () => {
  const substituted = compactionEnvelope();
  substituted.userPrefix.value.utf8 = 'changed';
  assert.throws(
    () =>
      prepareCompactionModelAttempt({
        authority: authority(),
        invocation: { runId: 'run-1', opId: 'compaction-op-1', attempt: 1 },
        compactionPlanRef: 'f'.repeat(64),
        envelope: substituted,
        sourceContextUtf8: 'context'
      }),
    /byte count does not match|digest does not rehash/u
  );

  const extendedText = compactionEnvelope();
  (extendedText.userPrefix.value as ModelTextV1 & { hidden?: boolean }).hidden = true;
  assert.throws(
    () =>
      prepareCompactionModelAttempt({
        authority: authority(),
        invocation: { runId: 'run-1', opId: 'compaction-op-1', attempt: 1 },
        compactionPlanRef: 'f'.repeat(64),
        envelope: extendedText,
        sourceContextUtf8: 'context'
      }),
    /wrong schema/u
  );

  const injected = compactionEnvelope();
  const prefix = modelText(`before ${injected.value.sourcePlaceholder}`);
  injected.userPrefix = prefix;
  injected.value.userPrefixRef = prefix.ref;
  injected.value.userPrefixDigest = prefix.value.textDigest;
  const withoutDigest = { ...injected.value };
  delete (withoutDigest as Partial<CompactionPromptEnvelopeV1>).envelopeDigest;
  injected.value.envelopeDigest = canonicalSha256(withoutDigest);
  injected.ref = planCanonicalArtifact(injected.value, injected.value.format).ref;
  assert.throws(
    () =>
      prepareCompactionModelAttempt({
        authority: authority(),
        invocation: { runId: 'run-1', opId: 'compaction-op-1', attempt: 1 },
        compactionPlanRef: 'f'.repeat(64),
        envelope: injected,
        sourceContextUtf8: 'context'
      }),
    /fixed text violates/u
  );
});
