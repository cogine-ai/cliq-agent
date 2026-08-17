import { digestOmitting } from '../kernel/identity.js';
import type {
  AdmittedContextManifest,
  ContextManifest,
  DirectUnverifiedConsentV1,
  FrozenIgnoreRulesV1,
  LocalControlChannelIdentityV1,
  RunObjectiveV1,
  RunSpec,
  SessionContextProjection,
  SourceManifest,
  SourceProjectionSpec,
  VerifierSpec,
  WorkspaceEntryManifest,
  WorkspaceIdentityV1,
  WorkspaceStateManifest
} from '../kernel/types.js';
import { KernelStorageError } from './errors.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `${label} must be a nonempty string`);
  }
  return value;
}

export function decodeWorkspaceIdentity(value: unknown): WorkspaceIdentityV1 {
  if (!isRecord(value) || value.format !== 'cliq-workspace-identity-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace identity has the wrong schema');
  }
  const identity = value as WorkspaceIdentityV1;
  if (digestOmitting(identity, 'identityDigest') !== identity.identityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace identity digest does not rehash');
  }
  if (identity.kind === 'legacy_unavailable') {
    throw new KernelStorageError('INVALID_REQUEST', 'legacy_unavailable Sessions cannot admit a Run');
  }
  return identity;
}

export function decodeSessionProjection(value: unknown): SessionContextProjection {
  if (!isRecord(value) || value.format !== 'cliq-session-context-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'session projection has the wrong schema');
  }
  const projection = value as SessionContextProjection;
  if (digestOmitting(projection, 'projectionDigest') !== projection.projectionDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'session projection digest does not rehash');
  }
  return projection;
}

export function decodeControlChannel(value: unknown): LocalControlChannelIdentityV1 {
  if (!isRecord(value) || value.format !== 'cliq-local-control-channel-identity-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel identity has the wrong schema');
  }
  const channel = value as LocalControlChannelIdentityV1;
  if (digestOmitting(channel, 'channelIdentityDigest') !== channel.channelIdentityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel digest does not rehash');
  }
  return channel;
}

export function decodeRunObjective(value: unknown): RunObjectiveV1 {
  if (!isRecord(value) || value.format !== 'cliq-run-objective-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'run objective has the wrong schema');
  }
  const objective = value as RunObjectiveV1;
  if (digestOmitting(objective, 'objectiveDigest') !== objective.objectiveDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'run objective digest does not rehash');
  }
  return objective;
}

export function decodeAdmittedContext(value: unknown): AdmittedContextManifest {
  if (!isRecord(value) || value.format !== 'cliq-admitted-context-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'admitted context has the wrong schema');
  }
  const manifest = value as AdmittedContextManifest;
  if (digestOmitting(manifest, 'contextDigest') !== manifest.contextDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'admitted context digest does not rehash');
  }
  return manifest;
}

export function decodeContextManifest(value: unknown): ContextManifest {
  if (!isRecord(value) || value.format !== 'cliq-context-manifest-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'run context manifest has the wrong schema');
  }
  const manifest = value as ContextManifest;
  if (digestOmitting(manifest, 'projectionDigest') !== manifest.projectionDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'run context manifest digest does not rehash');
  }
  return manifest;
}

export function decodeFrozenIgnoreRules(value: unknown): FrozenIgnoreRulesV1 {
  if (!isRecord(value) || value.format !== 'cliq-frozen-ignore-rules-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules have the wrong schema');
  }
  const rules = value as FrozenIgnoreRulesV1;
  if (digestOmitting(rules, 'rulesDigest') !== rules.rulesDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules digest does not rehash');
  }
  return rules;
}

export function decodeSourceProjection(value: unknown): SourceProjectionSpec {
  if (!isRecord(value) || value.matcherVersion !== 'cliq-exact-path-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source projection has the wrong schema');
  }
  const spec = value as SourceProjectionSpec;
  if (digestOmitting(spec, 'projectionDigest') !== spec.projectionDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source projection digest does not rehash');
  }
  return spec;
}

export function decodeWorkspaceEntries(value: unknown): WorkspaceEntryManifest {
  if (!isRecord(value) || value.format !== 'cliq-workspace-entries-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace entries have the wrong schema');
  }
  const entries = value as WorkspaceEntryManifest;
  if (digestOmitting(entries, 'treeDigest') !== entries.treeDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace entries digest does not rehash');
  }
  return entries;
}

export function decodeSourceManifest(value: unknown): SourceManifest {
  if (!isRecord(value) || value.format !== 'cliq-source-manifest-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source manifest has the wrong schema');
  }
  const manifest = value as SourceManifest;
  if (digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source manifest digest does not rehash');
  }
  return manifest;
}

export function decodeWorkspaceState(value: unknown): WorkspaceStateManifest {
  if (!isRecord(value) || value.format !== 'cliq-workspace-state-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace state has the wrong schema');
  }
  const state = value as WorkspaceStateManifest;
  if (digestOmitting(state, 'stateDigest') !== state.stateDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace state digest does not rehash');
  }
  return state;
}

export function decodeVerifierSpec(value: unknown): VerifierSpec {
  if (!isRecord(value) || value.format !== 'cliq-verifier-spec-v1' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'verifier spec has the wrong schema');
  }
  const spec = value as VerifierSpec;
  if (digestOmitting(spec, 'specDigest') !== spec.specDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'verifier spec digest does not rehash');
  }
  return spec;
}

export function decodeUnverifiedConsent(value: unknown): DirectUnverifiedConsentV1 {
  if (!isRecord(value) || value.kind !== 'direct_unverified_consent' || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'unverified consent has the wrong schema');
  }
  const consent = value as DirectUnverifiedConsentV1;
  if (digestOmitting(consent, 'consentDigest') !== consent.consentDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'unverified consent digest does not rehash');
  }
  if (consent.allowUnverified !== true) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'unverified consent must set allowUnverified=true');
  }
  return consent;
}

export function decodeRunSpec(value: unknown): RunSpec {
  if (!isRecord(value) || value.schemaVersion !== 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'RunSpec must have schemaVersion=1');
  }
  const spec = value as RunSpec;
  if (spec.operation !== 'agent' && spec.operation !== 'delivery') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'RunSpec operation is invalid');
  }
  requireString(spec.objectiveRef, 'RunSpec.objectiveRef');
  requireString(spec.admittedContextRef, 'RunSpec.admittedContextRef');
  requireString(spec.baseWorkspaceManifestRef, 'RunSpec.baseWorkspaceManifestRef');
  return spec;
}
