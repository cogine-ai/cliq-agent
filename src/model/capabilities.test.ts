import assert from 'node:assert/strict';
import { test } from 'node:test';

import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ProviderName } from '../kernel/types.js';
import {
  negotiateModelCapabilities,
  providerTransportCapabilities,
  type ModelCapabilityEvidenceV1,
  type NormalizedModelCapabilityClaimsV1,
  type ProviderAdapterIdentity
} from './capabilities.js';

const ENDPOINT_DIGEST = '1'.repeat(64);
const ADAPTER: ProviderAdapterIdentity = {
  adapterId: 'provider-adapter',
  version: '1.0.0',
  codeDigest: '2'.repeat(64)
};
const CLAIMS: NormalizedModelCapabilityClaimsV1 = {
  nativeToolCalling: true,
  streaming: true,
  trustedUsageEvidence: false,
  contextLimitTokens: 131_072,
  maxOutputTokens: 16_384
};

function evidenceValue(
  provider: ProviderName = 'openai',
  claims: NormalizedModelCapabilityClaimsV1 = CLAIMS
): ModelCapabilityEvidenceV1 {
  const withoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-model-capability-evidence-v1' as const,
    provider,
    model: 'model-1',
    endpointIdentityDigest: ENDPOINT_DIGEST,
    adapter: ADAPTER,
    source:
      provider === 'ollama'
        ? {
            kind: 'managed_local' as const,
            localInferenceServiceSpecRef: '3'.repeat(64),
            localInferenceServiceSpecDigest: '4'.repeat(64),
            localModelManifestRef: '5'.repeat(64),
            localModelManifestDigest: '6'.repeat(64)
          }
        : {
            kind: 'signed_catalog' as const,
            runtimeBundleRef: '3'.repeat(64),
            catalogEntryRef: '4'.repeat(64),
            catalogEntryDigest: '5'.repeat(64)
          },
    ...claims,
    observedAt: '2026-09-05T00:00:00.000Z',
    validThrough: '2026-09-06T00:00:00.000Z'
  };
  return {
    ...withoutDigest,
    evidenceDigest: digestOmitting({ ...withoutDigest, evidenceDigest: '' }, 'evidenceDigest')
  };
}

function negotiate(
  provider: ProviderName,
  evidence: ModelCapabilityEvidenceV1 | null = evidenceValue(provider),
  sourceClaims: NormalizedModelCapabilityClaimsV1 | null = CLAIMS
) {
  return negotiateModelCapabilities({
    provider,
    model: 'model-1',
    endpointIdentityDigest: ENDPOINT_DIGEST,
    adapter: ADAPTER,
    admittedAt: '2026-09-05T00:00:01.000Z',
    deadlineAt: '2026-09-05T12:00:00.000Z',
    streamingRequested: true,
    ...(evidence === null
      ? {}
      : { evidence: { ref: planCanonicalArtifact(evidence, evidence.format).ref, value: evidence } }),
    resolveVerifiedSourceClaims: () => sourceClaims
  });
}

test('provider transport capabilities are restrictions, not model evidence', () => {
  assert.deepEqual(providerTransportCapabilities('anthropic'), {
    nativeTools: true,
    streaming: true
  });
  assert.deepEqual(providerTransportCapabilities('zhipu'), {
    nativeTools: true,
    streaming: true
  });
});

test('negotiateModelCapabilities selects native tools only from matching positive evidence', () => {
  for (const provider of ['openai', 'anthropic', 'openrouter', 'openai-compatible', 'zhipu', 'ollama'] as const) {
    const result = negotiate(provider);
    assert.equal(result.ok, true);
    assert.equal(result.ok ? result.negotiation.mode : undefined, 'native-tools');
    assert.equal(result.ok ? result.negotiation.streaming : undefined, true);
    assert.equal(result.ok ? result.negotiation.evidenceDigest : undefined, evidenceValue(provider).evidenceDigest);
  }
});

test('negotiation rejects the removed constrained-output capability instead of enabling autonomous execution', () => {
  const evidence = evidenceValue('openai');
  Object.assign(evidence, { constrainedOutput: true });
  assert.equal(negotiate('openai', evidence).ok, false);
});

test('negotiateModelCapabilities maps absent or false autonomous evidence to text-only', () => {
  const missing = negotiate('openai', null);
  assert.deepEqual(missing, { ok: false, mode: 'text-only', reason: 'evidence_missing' });

  const claims = { ...CLAIMS, nativeToolCalling: false };
  const evidence = evidenceValue('zhipu', claims);
  const result = negotiate('zhipu', evidence, claims);
  assert.equal(result.ok, true);
  assert.equal(result.ok ? result.negotiation.mode : undefined, 'text-only');
});

test('negotiateModelCapabilities rejects evidence digest and artifact substitution', () => {
  const digestMismatch = evidenceValue();
  digestMismatch.evidenceDigest = 'f'.repeat(64);
  const digestResult = negotiate('openai', digestMismatch);
  assert.deepEqual(digestResult, { ok: false, mode: 'text-only', reason: 'evidence_digest_mismatch' });

  const evidence = evidenceValue();
  const result = negotiateModelCapabilities({
    provider: 'openai',
    model: 'model-1',
    endpointIdentityDigest: ENDPOINT_DIGEST,
    adapter: ADAPTER,
    admittedAt: '2026-09-05T00:00:01.000Z',
    deadlineAt: '2026-09-05T12:00:00.000Z',
    streamingRequested: true,
    evidence: { ref: '9'.repeat(64), value: evidence },
    resolveVerifiedSourceClaims: () => CLAIMS
  });
  assert.deepEqual(result, { ok: false, mode: 'text-only', reason: 'evidence_digest_mismatch' });
});

test('negotiateModelCapabilities rejects identity, expiry, and source-claim drift', () => {
  const wrongIdentity = evidenceValue();
  wrongIdentity.model = 'other-model';
  wrongIdentity.evidenceDigest = digestOmitting(wrongIdentity, 'evidenceDigest');
  assert.deepEqual(negotiate('openai', wrongIdentity), {
    ok: false,
    mode: 'text-only',
    reason: 'evidence_identity_mismatch'
  });

  const expired = evidenceValue();
  expired.validThrough = '2026-09-05T01:00:00.000Z';
  expired.evidenceDigest = digestOmitting(expired, 'evidenceDigest');
  assert.deepEqual(negotiate('openai', expired), {
    ok: false,
    mode: 'text-only',
    reason: 'evidence_expired'
  });

  const driftedClaims = { ...CLAIMS, nativeToolCalling: false };
  assert.deepEqual(negotiate('openai', evidenceValue(), driftedClaims), {
    ok: false,
    mode: 'text-only',
    reason: 'evidence_source_claim_mismatch'
  });
});

test('negotiateModelCapabilities rejects unverifiable and structurally extended evidence', () => {
  assert.deepEqual(negotiate('openai', evidenceValue(), null), {
    ok: false,
    mode: 'text-only',
    reason: 'evidence_source_unverified'
  });

  const extended = { ...evidenceValue(), inferredFromProviderName: true } as ModelCapabilityEvidenceV1;
  assert.deepEqual(negotiate('openai', extended), {
    ok: false,
    mode: 'text-only',
    reason: 'evidence_schema_invalid'
  });

  const ambientOllama = evidenceValue('ollama');
  ambientOllama.source = {
    kind: 'signed_catalog',
    runtimeBundleRef: '3'.repeat(64),
    catalogEntryRef: '4'.repeat(64),
    catalogEntryDigest: '5'.repeat(64)
  };
  ambientOllama.evidenceDigest = digestOmitting(ambientOllama, 'evidenceDigest');
  assert.deepEqual(negotiate('ollama', ambientOllama), {
    ok: false,
    mode: 'text-only',
    reason: 'evidence_schema_invalid'
  });

  const prototypeKey = evidenceValue();
  prototypeKey.source = { kind: 'toString' } as unknown as ModelCapabilityEvidenceV1['source'];
  assert.deepEqual(negotiate('openai', prototypeKey), {
    ok: false,
    mode: 'text-only',
    reason: 'evidence_schema_invalid'
  });
});

test('negotiateModelCapabilities validates context and output limits before admission', () => {
  const invalidClaims = { ...CLAIMS, contextLimitTokens: 16_384, maxOutputTokens: 8_192 };
  const invalid = evidenceValue('openai', invalidClaims);
  assert.deepEqual(negotiate('openai', invalid, invalidClaims), {
    ok: false,
    mode: 'text-only',
    reason: 'evidence_schema_invalid'
  });
});

test('negotiateModelCapabilities never widens a disabled streaming claim', () => {
  const claims = { ...CLAIMS, streaming: false };
  const evidence = evidenceValue('openrouter', claims);
  const result = negotiate('openrouter', evidence, claims);
  assert.equal(result.ok, true);
  assert.equal(result.ok ? result.negotiation.streaming : undefined, false);
});
