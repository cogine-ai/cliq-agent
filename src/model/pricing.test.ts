import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting } from '../kernel/identity.js';
import {
  calculateModelCostMicros,
  ceilTokenPriceMicros,
  createModelRequestReservation,
  priceTableDigest,
  validateModelPricing,
  type LocalZeroCostProvenanceV1,
  type ModelPriceTableV1,
  type ModelPricingBound,
  type ValidatedModelPricing
} from './pricing.js';

const ENDPOINT_DIGEST = '1'.repeat(64);
const CREDENTIAL_REF = '2'.repeat(64);
const AUTHORITY_REF = '3'.repeat(64);

function priceTable(): ModelPriceTableV1 {
  const withoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-model-price-table-v1' as const,
    signerKeyId: 'cliq-release-key-1',
    signatureAlgorithm: 'ed25519' as const,
    signatureRef: '4'.repeat(64),
    provider: 'openai' as const,
    model: 'model-1',
    endpointIdentityDigest: ENDPOINT_DIGEST,
    currency: 'USD' as const,
    unit: 'micros_per_million_tokens' as const,
    prices: { input: 2_000_000, output: 8_000_000, cacheRead: 500_000, cacheWrite: 2_500_000 },
    validFrom: '2026-09-01T00:00:00.000Z',
    validThrough: '2026-09-10T00:00:00.000Z'
  };
  const value = { ...withoutDigest, tableDigest: '0'.repeat(64) };
  value.tableDigest = priceTableDigest(value);
  return value;
}

function trustedBound(table: ModelPriceTableV1, ref: string): Extract<ModelPricingBound, { kind: 'trusted_price_table' }> {
  return {
    kind: 'trusted_price_table',
    priceTableRef: ref,
    priceTableDigest: table.tableDigest,
    calculationAlgorithm: 'cliq-price-ceil-v1',
    maxRunCostMicros: 50_000_000,
    validThrough: table.validThrough,
    provenanceRef: AUTHORITY_REF
  };
}

function validateTrusted(table = priceTable(), boundOverride?: Partial<Extract<ModelPricingBound, { kind: 'trusted_price_table' }>>) {
  const artifact = planCanonicalArtifact(table, table.format);
  return validateModelPricing({
    provider: 'openai',
    model: 'model-1',
    endpointIdentityDigest: ENDPOINT_DIGEST,
    credentialGrantRefs: [CREDENTIAL_REF],
    admittedAt: '2026-09-05T00:00:00.000Z',
    deadlineAt: '2026-09-06T00:00:00.000Z',
    maxRunCostMicros: 50_000_000,
    bound: { ...trustedBound(table, artifact.ref), ...boundOverride },
    priceTable: { ref: artifact.ref, value: table },
    verifyLocalZeroCostAuthority: () => false,
    resolvePriceTableAuthority: () => AUTHORITY_REF
  });
}

function localProvenance(): LocalZeroCostProvenanceV1 {
  const endpoint = { scheme: 'http' as const, host: '127.0.0.1' as const, port: 49_152 };
  const withoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-local-zero-cost-v1' as const,
    ownerPrincipalId: 'principal-1',
    provider: 'ollama' as const,
    model: 'qwen-test',
    serviceSpecRef: '5'.repeat(64),
    serviceSpecDigest: '6'.repeat(64),
    stableServiceIdentityDigest: '7'.repeat(64),
    endpoint,
    endpointIdentityDigest: canonicalSha256(endpoint),
    boundaryEvidenceRef: '8'.repeat(64),
    boundaryEvidenceDigest: '9'.repeat(64),
    capabilityEvidenceRef: 'a'.repeat(64),
    capabilityDigest: 'b'.repeat(64),
    createdAt: '2026-09-05T00:00:00.000Z',
    validThrough: '2026-09-10T00:00:00.000Z'
  };
  return {
    ...withoutDigest,
    provenanceDigest: digestOmitting({ ...withoutDigest, provenanceDigest: '' }, 'provenanceDigest')
  };
}

function validateLocal(provenance = localProvenance(), verified = true, credentialGrantRefs: string[] = []) {
  const artifact = planCanonicalArtifact(provenance, provenance.format);
  return validateModelPricing({
    provider: 'ollama',
    model: 'qwen-test',
    endpointIdentityDigest: provenance.endpointIdentityDigest,
    credentialGrantRefs,
    admittedAt: '2026-09-05T00:00:01.000Z',
    deadlineAt: '2026-09-06T00:00:00.000Z',
    maxRunCostMicros: 0,
    bound: { kind: 'zero_cost', maxRunCostMicros: 0, provenanceRef: artifact.ref },
    localProvenance: { ref: artifact.ref, value: provenance },
    verifyLocalZeroCostAuthority: () => verified,
    resolvePriceTableAuthority: () => null
  });
}

test('cliq-price-ceil-v1 rounds every component independently', () => {
  assert.equal(ceilTokenPriceMicros(0, 1), 0);
  assert.equal(ceilTokenPriceMicros(1, 1), 1);
  assert.equal(ceilTokenPriceMicros(1_000_000, 3), 3);
  assert.equal(
    calculateModelCostMicros(
      { inputTokens: 1, outputTokens: 1, cacheReadTokens: 1, cacheWriteTokens: 1 },
      { input: 1, output: 1, cacheRead: 1, cacheWrite: 1 }
    ),
    4
  );
});

test('cliq-price-ceil-v1 rejects unsafe inputs and exact-result overflow', () => {
  assert.throws(() => ceilTokenPriceMicros(-1, 1), /nonnegative safe integer/);
  assert.throws(() => ceilTokenPriceMicros(Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER), /safe-integer range/);
  assert.throws(
    () => calculateModelCostMicros(
      {
        inputTokens: Number.MAX_SAFE_INTEGER,
        outputTokens: Number.MAX_SAFE_INTEGER,
        cacheReadTokens: 0,
        cacheWriteTokens: 0
      },
      { input: 1_000_000, output: 1_000_000, cacheRead: 0, cacheWrite: 0 }
    ),
    /safe-integer range/
  );
});

test('validateModelPricing accepts an exact signed price-table authority projection', () => {
  const result = validateTrusted();
  assert.equal(result.ok, true);
  assert.equal(result.ok ? result.pricing.kind : undefined, 'trusted_price_table');
});

test('priceTableDigest excludes signature bytes reference but the artifact identity does not', () => {
  const first = priceTable();
  const second = { ...first, signatureRef: 'c'.repeat(64) };
  assert.equal(priceTableDigest(first), priceTableDigest(second));
  assert.notEqual(
    planCanonicalArtifact(first, first.format).ref,
    planCanonicalArtifact(second, second.format).ref
  );
});

test('validateModelPricing rejects table tampering, authority failure, and endpoint mismatch', () => {
  const tampered = priceTable();
  tampered.prices = { ...tampered.prices, output: tampered.prices.output + 1 };
  assert.deepEqual(validateTrusted(tampered), {
    ok: false,
    code: 'MODEL_COST_UNKNOWN',
    reason: 'price_table_invalid'
  });

  const table = priceTable();
  const artifact = planCanonicalArtifact(table, table.format);
  const authorityFailure = validateModelPricing({
    provider: 'openai',
    model: 'model-1',
    endpointIdentityDigest: ENDPOINT_DIGEST,
    credentialGrantRefs: [CREDENTIAL_REF],
    admittedAt: '2026-09-05T00:00:00.000Z',
    deadlineAt: '2026-09-06T00:00:00.000Z',
    maxRunCostMicros: 50_000_000,
    bound: trustedBound(table, artifact.ref),
    priceTable: { ref: artifact.ref, value: table },
    verifyLocalZeroCostAuthority: () => false,
    resolvePriceTableAuthority: () => null
  });
  assert.deepEqual(authorityFailure, {
    ok: false,
    code: 'MODEL_COST_UNKNOWN',
    reason: 'price_table_signature_invalid'
  });

  const endpointMismatch = { ...table, endpointIdentityDigest: 'd'.repeat(64), tableDigest: '' };
  endpointMismatch.tableDigest = priceTableDigest(endpointMismatch);
  assert.deepEqual(validateTrusted(endpointMismatch), {
    ok: false,
    code: 'MODEL_COST_UNKNOWN',
    reason: 'pricing_identity_mismatch'
  });
});

test('validateModelPricing requires price validity through the complete Run deadline', () => {
  const table = priceTable();
  table.validThrough = '2026-09-05T12:00:00.000Z';
  table.tableDigest = priceTableDigest(table);
  assert.deepEqual(validateTrusted(table), {
    ok: false,
    code: 'MODEL_COST_UNKNOWN',
    reason: 'pricing_validity_insufficient'
  });
});

test('validateModelPricing rejects credentialless or mismatched remote price bounds', () => {
  const table = priceTable();
  const artifact = planCanonicalArtifact(table, table.format);
  const credentialless = validateModelPricing({
    provider: 'openai',
    model: 'model-1',
    endpointIdentityDigest: ENDPOINT_DIGEST,
    credentialGrantRefs: [],
    admittedAt: '2026-09-05T00:00:00.000Z',
    deadlineAt: '2026-09-06T00:00:00.000Z',
    maxRunCostMicros: 50_000_000,
    bound: trustedBound(table, artifact.ref),
    priceTable: { ref: artifact.ref, value: table },
    verifyLocalZeroCostAuthority: () => false,
    resolvePriceTableAuthority: () => AUTHORITY_REF
  });
  assert.deepEqual(credentialless, {
    ok: false,
    code: 'MODEL_COST_UNKNOWN',
    reason: 'price_table_invalid'
  });

  assert.deepEqual(validateTrusted(table, { maxRunCostMicros: 1 }), {
    ok: false,
    code: 'MODEL_COST_UNKNOWN',
    reason: 'pricing_identity_mismatch'
  });
});

test('validateModelPricing accepts only independently verified managed-local zero cost', () => {
  const result = validateLocal();
  assert.equal(result.ok, true);
  assert.equal(result.ok ? result.pricing.kind : undefined, 'zero_cost');

  assert.deepEqual(validateLocal(localProvenance(), false), {
    ok: false,
    code: 'MODEL_COST_UNKNOWN',
    reason: 'zero_cost_provenance_invalid'
  });
  assert.deepEqual(validateLocal(localProvenance(), true, [CREDENTIAL_REF]), {
    ok: false,
    code: 'MODEL_COST_UNKNOWN',
    reason: 'zero_cost_provenance_invalid'
  });
});

test('createModelRequestReservation freezes the conservative N/O/N/N vector', () => {
  const result = validateTrusted();
  assert.equal(result.ok, true);
  const pricing = result.ok ? result.pricing : (null as never);
  assert.deepEqual(createModelRequestReservation(100, 20, pricing), {
    inputTokens: 100,
    outputTokens: 20,
    cacheReadTokens: 100,
    cacheWriteTokens: 100,
    modelTokens: 120,
    costMicros: 660
  });

  const zeroPricing: ValidatedModelPricing = {
    kind: 'zero_cost',
    bound: { kind: 'zero_cost', maxRunCostMicros: 0, provenanceRef: 'e'.repeat(64) },
    provenance: localProvenance()
  };
  assert.equal(createModelRequestReservation(100, 20, zeroPricing).costMicros, 0);
});
