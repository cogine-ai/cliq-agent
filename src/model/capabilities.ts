import { canonicalJsonBytes } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { ArtifactRef, ProviderName } from '../kernel/types.js';
import type { AgentNegotiatedMode } from '../protocol/agent-ir.js';

export type ProviderAdapterIdentity = {
  adapterId: string;
  version: string;
  codeDigest: string;
};

export type NormalizedModelCapabilityClaimsV1 = {
  nativeToolCalling: boolean;
  streaming: boolean;
  trustedUsageEvidence: boolean;
  contextLimitTokens: number;
  maxOutputTokens: number;
};

export type ModelCapabilityEvidenceV1 = {
  schemaVersion: 1;
  format: 'cliq-model-capability-evidence-v1';
  provider: ProviderName;
  model: string;
  endpointIdentityDigest: string;
  adapter: ProviderAdapterIdentity;
  source:
    | {
        kind: 'signed_catalog';
        runtimeBundleRef: ArtifactRef;
        catalogEntryRef: ArtifactRef;
        catalogEntryDigest: string;
      }
    | {
        kind: 'registered_endpoint_negotiation';
        endpointRegistrationRef: ArtifactRef;
        negotiationReceiptRef: ArtifactRef;
        negotiationReceiptDigest: string;
      }
    | {
        kind: 'managed_local';
        localInferenceServiceSpecRef: ArtifactRef;
        localInferenceServiceSpecDigest: string;
        localModelManifestRef: ArtifactRef;
        localModelManifestDigest: string;
      };
  nativeToolCalling: boolean;
  streaming: boolean;
  trustedUsageEvidence: boolean;
  contextLimitTokens: number;
  maxOutputTokens: number;
  observedAt: string;
  validThrough: string;
  evidenceDigest: string;
};

export type ProviderTransportCapabilities = Readonly<{
  nativeTools: boolean;
  streaming: boolean;
}>;

const PROVIDER_TRANSPORT_CAPABILITIES: Readonly<Record<ProviderName, ProviderTransportCapabilities>> = Object.freeze(
  Object.fromEntries(
    ['openai', 'anthropic', 'openrouter', 'openai-compatible', 'zhipu', 'ollama'].map((provider) => [
      provider,
      Object.freeze({ nativeTools: true, streaming: true })
    ])
  ) as Record<ProviderName, ProviderTransportCapabilities>
);

export function providerTransportCapabilities(provider: ProviderName): ProviderTransportCapabilities {
  return PROVIDER_TRANSPORT_CAPABILITIES[provider];
}

export type CapabilityEvidenceFailure =
  | 'evidence_missing'
  | 'evidence_schema_invalid'
  | 'evidence_digest_mismatch'
  | 'evidence_identity_mismatch'
  | 'evidence_source_unverified'
  | 'evidence_source_claim_mismatch'
  | 'evidence_expired'
  | 'evidence_claims_invalid';

export type ModelCapabilityNegotiation = {
  provider: ProviderName;
  model: string;
  endpointIdentityDigest: string;
  adapter: ProviderAdapterIdentity;
  evidenceRef: ArtifactRef;
  evidenceDigest: string;
  mode: AgentNegotiatedMode;
  streaming: boolean;
  nativeToolCalling: boolean;
  trustedUsageEvidence: boolean;
  contextLimitTokens: number;
  maxOutputTokens: number;
};

export type ModelCapabilityNegotiationResult =
  | { ok: true; negotiation: ModelCapabilityNegotiation }
  | { ok: false; mode: 'text-only'; reason: CapabilityEvidenceFailure };

export type NegotiateModelCapabilitiesInput = {
  provider: ProviderName;
  model: string;
  endpointIdentityDigest: string;
  adapter: ProviderAdapterIdentity;
  admittedAt: string;
  deadlineAt: string;
  streamingRequested: boolean;
  evidence?: {
    ref: ArtifactRef;
    value: ModelCapabilityEvidenceV1;
  };
  resolveVerifiedSourceClaims: (
    source: ModelCapabilityEvidenceV1['source']
  ) => NormalizedModelCapabilityClaimsV1 | null;
};

const EVIDENCE_KEYS = [
  'schemaVersion',
  'format',
  'provider',
  'model',
  'endpointIdentityDigest',
  'adapter',
  'source',
  'nativeToolCalling',
  'streaming',
  'trustedUsageEvidence',
  'contextLimitTokens',
  'maxOutputTokens',
  'observedAt',
  'validThrough',
  'evidenceDigest'
] as const;

const ADAPTER_KEYS = ['adapterId', 'version', 'codeDigest'] as const;
const SOURCE_KEYS = {
  signed_catalog: ['kind', 'runtimeBundleRef', 'catalogEntryRef', 'catalogEntryDigest'],
  registered_endpoint_negotiation: [
    'kind',
    'endpointRegistrationRef',
    'negotiationReceiptRef',
    'negotiationReceiptDigest'
  ],
  managed_local: [
    'kind',
    'localInferenceServiceSpecRef',
    'localInferenceServiceSpecDigest',
    'localModelManifestRef',
    'localModelManifestDigest'
  ]
} as const;

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

function validAdapter(value: unknown): value is ProviderAdapterIdentity {
  return (
    isRecord(value) &&
    hasExactKeys(value, ADAPTER_KEYS) &&
    isNonemptyString(value.adapterId) &&
    isNonemptyString(value.version) &&
    isArtifactRef(value.codeDigest)
  );
}

function validSource(value: unknown): value is ModelCapabilityEvidenceV1['source'] {
  if (!isRecord(value) || typeof value.kind !== 'string' || !Object.hasOwn(SOURCE_KEYS, value.kind)) return false;
  const kind = value.kind as keyof typeof SOURCE_KEYS;
  if (!hasExactKeys(value, SOURCE_KEYS[kind])) return false;
  return Object.entries(value).every(([key, member]) => key === 'kind' || isArtifactRef(member));
}

function claimsFromEvidence(evidence: ModelCapabilityEvidenceV1): NormalizedModelCapabilityClaimsV1 {
  return {
    nativeToolCalling: evidence.nativeToolCalling,
    streaming: evidence.streaming,
    trustedUsageEvidence: evidence.trustedUsageEvidence,
    contextLimitTokens: evidence.contextLimitTokens,
    maxOutputTokens: evidence.maxOutputTokens
  };
}

function claimsEqual(left: NormalizedModelCapabilityClaimsV1, right: NormalizedModelCapabilityClaimsV1): boolean {
  return canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
}

function validClaims(claims: NormalizedModelCapabilityClaimsV1): boolean {
  return (
    typeof claims.nativeToolCalling === 'boolean' &&
    typeof claims.streaming === 'boolean' &&
    typeof claims.trustedUsageEvidence === 'boolean' &&
    Number.isSafeInteger(claims.contextLimitTokens) &&
    claims.contextLimitTokens >= 32_768 &&
    Number.isSafeInteger(claims.maxOutputTokens) &&
    claims.maxOutputTokens >= 1 &&
    claims.maxOutputTokens <= Math.floor(claims.contextLimitTokens / 4)
  );
}

function validEvidenceSchema(value: unknown): value is ModelCapabilityEvidenceV1 {
  if (!isRecord(value) || !hasExactKeys(value, EVIDENCE_KEYS)) return false;
  if (value.schemaVersion !== 1 || value.format !== 'cliq-model-capability-evidence-v1') return false;
  if (!isNonemptyString(value.model) || !isArtifactRef(value.endpointIdentityDigest)) return false;
  if (!validAdapter(value.adapter) || !validSource(value.source)) return false;
  if (!isArtifactRef(value.evidenceDigest)) return false;
  if (!isNonemptyString(value.observedAt) || !isNonemptyString(value.validThrough)) return false;
  const providerNames: ProviderName[] = ['openrouter', 'anthropic', 'openai', 'openai-compatible', 'zhipu', 'ollama'];
  if (!providerNames.includes(value.provider as ProviderName)) return false;
  if (
    (value.provider === 'ollama' && value.source.kind !== 'managed_local') ||
    (value.provider !== 'ollama' && value.source.kind === 'managed_local')
  )
    return false;
  return validClaims(value as ModelCapabilityEvidenceV1);
}

function sameAdapter(left: ProviderAdapterIdentity, right: ProviderAdapterIdentity): boolean {
  return left.adapterId === right.adapterId && left.version === right.version && left.codeDigest === right.codeDigest;
}

function fail(reason: CapabilityEvidenceFailure): ModelCapabilityNegotiationResult {
  return { ok: false, mode: 'text-only', reason };
}

export function negotiateModelCapabilities(input: NegotiateModelCapabilitiesInput): ModelCapabilityNegotiationResult {
  if (!isNonemptyString(input.model) || !validAdapter(input.adapter)) {
    throw new TypeError('model and adapter identity must be complete');
  }
  assertArtifactRef(input.endpointIdentityDigest);
  const admittedAt = parseCanonicalTime(input.admittedAt);
  const deadlineAt = parseCanonicalTime(input.deadlineAt);
  if (deadlineAt < admittedAt) throw new TypeError('Run deadline must not precede admission');
  if (input.evidence === undefined) return fail('evidence_missing');
  if (!validEvidenceSchema(input.evidence.value) || !isArtifactRef(input.evidence.ref)) {
    return fail('evidence_schema_invalid');
  }

  const evidence = input.evidence.value;
  if (
    digestOmitting(evidence, 'evidenceDigest') !== evidence.evidenceDigest ||
    planCanonicalArtifact(evidence, evidence.format).ref !== input.evidence.ref
  ) {
    return fail('evidence_digest_mismatch');
  }
  if (
    evidence.provider !== input.provider ||
    evidence.model !== input.model ||
    evidence.endpointIdentityDigest !== input.endpointIdentityDigest ||
    !sameAdapter(evidence.adapter, input.adapter)
  ) {
    return fail('evidence_identity_mismatch');
  }

  let observedAt: number;
  let validThrough: number;
  try {
    observedAt = parseCanonicalTime(evidence.observedAt);
    validThrough = parseCanonicalTime(evidence.validThrough);
  } catch {
    return fail('evidence_schema_invalid');
  }
  if (observedAt > admittedAt || validThrough < deadlineAt || validThrough < observedAt) {
    return fail('evidence_expired');
  }

  const evidenceClaims = claimsFromEvidence(evidence);
  if (!validClaims(evidenceClaims)) return fail('evidence_claims_invalid');
  let sourceClaims: NormalizedModelCapabilityClaimsV1 | null;
  try {
    sourceClaims = input.resolveVerifiedSourceClaims(evidence.source);
  } catch {
    return fail('evidence_source_unverified');
  }
  if (sourceClaims === null) return fail('evidence_source_unverified');
  if (!validClaims(sourceClaims) || !claimsEqual(evidenceClaims, sourceClaims)) {
    return fail('evidence_source_claim_mismatch');
  }

  const transport = providerTransportCapabilities(input.provider);
  const mode: AgentNegotiatedMode = transport.nativeTools && evidence.nativeToolCalling ? 'native-tools' : 'text-only';
  return {
    ok: true,
    negotiation: {
      provider: input.provider,
      model: input.model,
      endpointIdentityDigest: input.endpointIdentityDigest,
      adapter: input.adapter,
      evidenceRef: input.evidence.ref,
      evidenceDigest: evidence.evidenceDigest,
      mode,
      streaming: input.streamingRequested && transport.streaming && evidence.streaming,
      nativeToolCalling: evidence.nativeToolCalling,
      trustedUsageEvidence: evidence.trustedUsageEvidence,
      contextLimitTokens: evidence.contextLimitTokens,
      maxOutputTokens: evidence.maxOutputTokens
    }
  };
}
