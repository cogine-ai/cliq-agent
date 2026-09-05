import { immutableSnapshot } from './immutable.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { ArtifactRef, ModelPricingBound as KernelModelPricingBound, ProviderName } from '../kernel/types.js';

export type ModelTokenComponents = {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
};

export type ModelTokenPrices = {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
};

export type ModelRequestReservation = ModelTokenComponents & {
  modelTokens: number;
  costMicros: number;
};

export type LocalZeroCostProvenanceV1 = {
  schemaVersion: 1;
  format: 'cliq-local-zero-cost-v1';
  ownerPrincipalId: string;
  provider: 'ollama';
  model: string;
  serviceSpecRef: ArtifactRef;
  serviceSpecDigest: string;
  stableServiceIdentityDigest: string;
  endpoint: { scheme: 'http'; host: '127.0.0.1' | '[::1]'; port: number };
  endpointIdentityDigest: string;
  boundaryEvidenceRef: ArtifactRef;
  boundaryEvidenceDigest: string;
  capabilityEvidenceRef: ArtifactRef;
  capabilityDigest: string;
  createdAt: string;
  validThrough: string;
  provenanceDigest: string;
};

export type ModelPriceTableV1 = {
  schemaVersion: 1;
  format: 'cliq-model-price-table-v1';
  signerKeyId: string;
  signatureAlgorithm: 'ed25519';
  signatureRef: ArtifactRef;
  provider: ProviderName;
  model: string;
  endpointIdentityDigest: string;
  currency: 'USD';
  unit: 'micros_per_million_tokens';
  prices: ModelTokenPrices;
  /** Signed bound for every released request, including rejected/ambiguous requests. Not an estimate. */
  requestTokenCeiling: ModelTokenComponents;
  validFrom: string;
  validThrough: string;
  tableDigest: string;
};

export type ModelPricingBound = KernelModelPricingBound;

export type PricingValidationFailure =
  | 'pricing_bound_invalid'
  | 'zero_cost_provenance_invalid'
  | 'price_table_invalid'
  | 'price_table_signature_invalid'
  | 'pricing_identity_mismatch'
  | 'pricing_validity_insufficient';

export type ValidatedModelPricing =
  | {
      kind: 'zero_cost';
      bound: Extract<ModelPricingBound, { kind: 'zero_cost' }>;
      provenance: LocalZeroCostProvenanceV1;
    }
  | {
      kind: 'trusted_price_table';
      bound: Extract<ModelPricingBound, { kind: 'trusted_price_table' }>;
      table: ModelPriceTableV1;
    };

export type ValidateModelPricingInput = {
  provider: ProviderName;
  model: string;
  endpointIdentityDigest: string;
  credentialGrantRefs: ArtifactRef[];
  admittedAt: string;
  deadlineAt: string;
  maxRunCostMicros: number;
  bound: ModelPricingBound;
  localProvenance?: { ref: ArtifactRef; value: LocalZeroCostProvenanceV1 };
  priceTable?: { ref: ArtifactRef; value: ModelPriceTableV1 };
  verifyLocalZeroCostAuthority: (provenance: LocalZeroCostProvenanceV1) => boolean;
  resolvePriceTableAuthority: (table: ModelPriceTableV1) => ArtifactRef | null;
};

export type ValidateModelPricingResult =
  | { ok: true; pricing: ValidatedModelPricing }
  | { ok: false; code: 'MODEL_COST_UNKNOWN'; reason: PricingValidationFailure };

const LOCAL_PROVENANCE_KEYS = [
  'schemaVersion',
  'format',
  'ownerPrincipalId',
  'provider',
  'model',
  'serviceSpecRef',
  'serviceSpecDigest',
  'stableServiceIdentityDigest',
  'endpoint',
  'endpointIdentityDigest',
  'boundaryEvidenceRef',
  'boundaryEvidenceDigest',
  'capabilityEvidenceRef',
  'capabilityDigest',
  'createdAt',
  'validThrough',
  'provenanceDigest'
] as const;
const LOCAL_ENDPOINT_KEYS = ['scheme', 'host', 'port'] as const;
const PRICE_TABLE_KEYS = [
  'schemaVersion',
  'format',
  'signerKeyId',
  'signatureAlgorithm',
  'signatureRef',
  'provider',
  'model',
  'endpointIdentityDigest',
  'currency',
  'unit',
  'prices',
  'requestTokenCeiling',
  'validFrom',
  'validThrough',
  'tableDigest'
] as const;
const PRICE_KEYS = ['input', 'output', 'cacheRead', 'cacheWrite'] as const;
const ZERO_BOUND_KEYS = ['kind', 'maxRunCostMicros', 'provenanceRef'] as const;
const TABLE_BOUND_KEYS = [
  'kind',
  'priceTableRef',
  'priceTableDigest',
  'calculationAlgorithm',
  'maxRunCostMicros',
  'validThrough',
  'provenanceRef'
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isNonemptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !value.includes('\0');
}

function isArtifactRef(value: unknown): value is ArtifactRef {
  if (typeof value !== 'string') return false;
  try {
    assertArtifactRef(value);
    return true;
  } catch {
    return false;
  }
}

function isNonnegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function checkedSafeInteger(value: number, label: string): number {
  if (!isNonnegativeSafeInteger(value)) {
    throw new RangeError(`${label} must be a nonnegative safe integer`);
  }
  return value;
}

function checkedAdd(left: number, right: number, label: string): number {
  checkedSafeInteger(left, label);
  checkedSafeInteger(right, label);
  const value = left + right;
  if (!Number.isSafeInteger(value)) throw new RangeError(`${label} exceeds the safe-integer range`);
  return value;
}

export function ceilTokenPriceMicros(tokens: number, microsPerMillion: number): number {
  checkedSafeInteger(tokens, 'token count');
  checkedSafeInteger(microsPerMillion, 'token price');
  const numerator = BigInt(tokens) * BigInt(microsPerMillion);
  const rounded = (numerator + 999_999n) / 1_000_000n;
  if (rounded > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError('token price result exceeds the safe-integer range');
  }
  return Number(rounded);
}

export function calculateModelCostMicros(usage: ModelTokenComponents, prices: ModelTokenPrices): number {
  const components = [
    ceilTokenPriceMicros(usage.inputTokens, prices.input),
    ceilTokenPriceMicros(usage.outputTokens, prices.output),
    ceilTokenPriceMicros(usage.cacheReadTokens, prices.cacheRead),
    ceilTokenPriceMicros(usage.cacheWriteTokens, prices.cacheWrite)
  ];
  return components.reduce((total, component) => checkedAdd(total, component, 'model cost'), 0);
}

export function createModelRequestReservation(
  contextLimitTokens: number,
  maximumOutputTokens: number,
  pricing: ValidatedModelPricing
): ModelRequestReservation {
  checkedSafeInteger(contextLimitTokens, 'context limit');
  checkedSafeInteger(maximumOutputTokens, 'maximum output tokens');
  if (maximumOutputTokens < 1) throw new RangeError('maximum output tokens must be positive');
  const components: ModelTokenComponents =
    pricing.kind === 'zero_cost'
      ? { inputTokens: contextLimitTokens, outputTokens: maximumOutputTokens, cacheReadTokens: 0, cacheWriteTokens: 0 }
      : pricing.table.requestTokenCeiling;
  if (components.inputTokens < contextLimitTokens || components.outputTokens < maximumOutputTokens) {
    throw new RangeError('signed request token ceiling does not cover the admitted model limits');
  }
  return {
    ...components,
    modelTokens: checkedAdd(components.inputTokens, components.outputTokens, 'model token reservation'),
    costMicros: pricing.kind === 'zero_cost' ? 0 : calculateModelCostMicros(components, pricing.table.prices)
  };
}

function validTokenCeiling(value: unknown): value is ModelTokenComponents {
  const keys = ['inputTokens', 'outputTokens', 'cacheReadTokens', 'cacheWriteTokens'];
  return (
    isRecord(value) &&
    hasExactKeys(value, keys) &&
    keys.every((key) => isNonnegativeSafeInteger(value[key])) &&
    (value.inputTokens as number) > 0 &&
    (value.outputTokens as number) > 0 &&
    Number.isSafeInteger((value.inputTokens as number) + (value.outputTokens as number))
  );
}

export function priceTableDigest(table: ModelPriceTableV1): string {
  const projection: Record<string, unknown> = {};
  for (const key of Object.keys(table)) {
    if (key === 'tableDigest' || key === 'signatureRef') continue;
    projection[key] = table[key as keyof ModelPriceTableV1];
  }
  return canonicalSha256(projection);
}

function validPrices(value: unknown): value is ModelTokenPrices {
  return (
    isRecord(value) &&
    hasExactKeys(value, PRICE_KEYS) &&
    PRICE_KEYS.every((key) => isNonnegativeSafeInteger(value[key]))
  );
}

function validPriceTableSchema(value: unknown): value is ModelPriceTableV1 {
  if (!isRecord(value) || !hasExactKeys(value, PRICE_TABLE_KEYS)) return false;
  return (
    value.schemaVersion === 1 &&
    value.format === 'cliq-model-price-table-v1' &&
    isNonemptyString(value.signerKeyId) &&
    value.signatureAlgorithm === 'ed25519' &&
    isArtifactRef(value.signatureRef) &&
    isNonemptyString(value.provider) &&
    isNonemptyString(value.model) &&
    isArtifactRef(value.endpointIdentityDigest) &&
    value.currency === 'USD' &&
    value.unit === 'micros_per_million_tokens' &&
    validPrices(value.prices) &&
    validTokenCeiling(value.requestTokenCeiling) &&
    isNonemptyString(value.validFrom) &&
    isNonemptyString(value.validThrough) &&
    isArtifactRef(value.tableDigest)
  );
}

function validLocalProvenanceSchema(value: unknown): value is LocalZeroCostProvenanceV1 {
  if (!isRecord(value) || !hasExactKeys(value, LOCAL_PROVENANCE_KEYS)) return false;
  if (!isRecord(value.endpoint) || !hasExactKeys(value.endpoint, LOCAL_ENDPOINT_KEYS)) return false;
  const refs = [
    value.serviceSpecRef,
    value.serviceSpecDigest,
    value.stableServiceIdentityDigest,
    value.endpointIdentityDigest,
    value.boundaryEvidenceRef,
    value.boundaryEvidenceDigest,
    value.capabilityEvidenceRef,
    value.capabilityDigest,
    value.provenanceDigest
  ];
  return (
    value.schemaVersion === 1 &&
    value.format === 'cliq-local-zero-cost-v1' &&
    isNonemptyString(value.ownerPrincipalId) &&
    value.provider === 'ollama' &&
    isNonemptyString(value.model) &&
    refs.every(isArtifactRef) &&
    value.endpoint.scheme === 'http' &&
    (value.endpoint.host === '127.0.0.1' || value.endpoint.host === '[::1]') &&
    Number.isSafeInteger(value.endpoint.port) &&
    (value.endpoint.port as number) >= 1 &&
    (value.endpoint.port as number) <= 65_535 &&
    isNonemptyString(value.createdAt) &&
    isNonemptyString(value.validThrough)
  );
}

function validBound(bound: unknown): bound is ModelPricingBound {
  if (!isRecord(bound) || typeof bound.kind !== 'string') return false;
  if (bound.kind === 'zero_cost') {
    return hasExactKeys(bound, ZERO_BOUND_KEYS) && bound.maxRunCostMicros === 0 && isArtifactRef(bound.provenanceRef);
  }
  return (
    bound.kind === 'trusted_price_table' &&
    hasExactKeys(bound, TABLE_BOUND_KEYS) &&
    isArtifactRef(bound.priceTableRef) &&
    isArtifactRef(bound.priceTableDigest) &&
    bound.calculationAlgorithm === 'cliq-price-ceil-v1' &&
    isNonnegativeSafeInteger(bound.maxRunCostMicros) &&
    isNonemptyString(bound.validThrough) &&
    isArtifactRef(bound.provenanceRef)
  );
}

function failure(reason: PricingValidationFailure): ValidateModelPricingResult {
  return { ok: false, code: 'MODEL_COST_UNKNOWN', reason };
}

export function validateModelPricing(original: ValidateModelPricingInput): ValidateModelPricingResult {
  const { verifyLocalZeroCostAuthority, resolvePriceTableAuthority, ...data } = original;
  const input = { ...immutableSnapshot(data), verifyLocalZeroCostAuthority, resolvePriceTableAuthority };
  if (!isNonemptyString(input.model)) throw new TypeError('model must be nonempty');
  assertArtifactRef(input.endpointIdentityDigest);
  for (const ref of input.credentialGrantRefs) assertArtifactRef(ref);
  if (input.credentialGrantRefs.some((ref, index) => index > 0 && ref <= input.credentialGrantRefs[index - 1]!)) {
    return failure('pricing_identity_mismatch');
  }
  checkedSafeInteger(input.maxRunCostMicros, 'maximum Run cost');
  const admittedAt = parseCanonicalTime(input.admittedAt);
  const deadlineAt = parseCanonicalTime(input.deadlineAt);
  if (deadlineAt < admittedAt) throw new TypeError('Run deadline must not precede admission');
  if (!validBound(input.bound)) return failure('pricing_bound_invalid');

  if (input.bound.kind === 'zero_cost') {
    if (
      input.provider !== 'ollama' ||
      input.maxRunCostMicros !== 0 ||
      input.credentialGrantRefs.length !== 0 ||
      input.localProvenance === undefined ||
      input.priceTable !== undefined ||
      input.bound.provenanceRef !== input.localProvenance.ref ||
      !validLocalProvenanceSchema(input.localProvenance.value) ||
      !isArtifactRef(input.localProvenance.ref)
    ) {
      return failure('zero_cost_provenance_invalid');
    }
    const provenance = input.localProvenance.value;
    let createdAt: number;
    let validThrough: number;
    try {
      createdAt = parseCanonicalTime(provenance.createdAt);
      validThrough = parseCanonicalTime(provenance.validThrough);
    } catch {
      return failure('zero_cost_provenance_invalid');
    }
    if (
      digestOmitting(provenance, 'provenanceDigest') !== provenance.provenanceDigest ||
      planCanonicalArtifact(provenance, provenance.format).ref !== input.localProvenance.ref ||
      provenance.endpointIdentityDigest !== canonicalSha256(provenance.endpoint)
    ) {
      return failure('zero_cost_provenance_invalid');
    }
    if (
      provenance.provider !== input.provider ||
      provenance.model !== input.model ||
      provenance.endpointIdentityDigest !== input.endpointIdentityDigest
    ) {
      return failure('pricing_identity_mismatch');
    }
    if (createdAt > admittedAt || validThrough < deadlineAt || validThrough < createdAt) {
      return failure('pricing_validity_insufficient');
    }
    let verified = false;
    try {
      verified = input.verifyLocalZeroCostAuthority(provenance);
    } catch {
      verified = false;
    }
    if (!verified) return failure('zero_cost_provenance_invalid');
    return { ok: true, pricing: { kind: 'zero_cost', bound: input.bound, provenance } };
  }

  if (
    input.localProvenance !== undefined ||
    input.priceTable === undefined ||
    input.credentialGrantRefs.length === 0 ||
    !isArtifactRef(input.priceTable.ref) ||
    !validPriceTableSchema(input.priceTable.value)
  ) {
    return failure('price_table_invalid');
  }
  const table = input.priceTable.value;
  if (
    priceTableDigest(table) !== table.tableDigest ||
    planCanonicalArtifact(table, table.format).ref !== input.priceTable.ref ||
    input.bound.priceTableRef !== input.priceTable.ref ||
    input.bound.priceTableDigest !== table.tableDigest
  ) {
    return failure('price_table_invalid');
  }
  if (
    table.provider !== input.provider ||
    table.model !== input.model ||
    table.endpointIdentityDigest !== input.endpointIdentityDigest ||
    input.bound.maxRunCostMicros !== input.maxRunCostMicros ||
    input.bound.validThrough !== table.validThrough
  ) {
    return failure('pricing_identity_mismatch');
  }

  let validFrom: number;
  let validThrough: number;
  try {
    validFrom = parseCanonicalTime(table.validFrom);
    validThrough = parseCanonicalTime(table.validThrough);
    parseCanonicalTime(input.bound.validThrough);
  } catch {
    return failure('price_table_invalid');
  }
  if (validFrom > admittedAt || validThrough < deadlineAt || validThrough < validFrom) {
    return failure('pricing_validity_insufficient');
  }

  let provenanceRef: ArtifactRef | null;
  try {
    provenanceRef = input.resolvePriceTableAuthority(table);
  } catch {
    provenanceRef = null;
  }
  if (provenanceRef === null || !isArtifactRef(provenanceRef) || provenanceRef !== input.bound.provenanceRef) {
    return failure('price_table_signature_invalid');
  }
  return { ok: true, pricing: { kind: 'trusted_price_table', bound: input.bound, table } };
}
