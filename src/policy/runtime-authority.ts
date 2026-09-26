import { createPublicKey, verify } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { assertArtifactRef, identityHash } from '../kernel/identity.js';
import type { PolicyEngineProfileV1, RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import type { RunAssemblyV1, ToolContractManifestV1 } from '../kernel/types.js';

/** Supplied by trusted Supervisor composition, never by a Run, repository, worker or control request. */
export type ReleaseTrustKey = { keyId: string; publicKeyPem: string };

export type RuntimeBundleManifest = {
  schemaVersion: 1; bundleVersion: string;
  controlProtocolRange: { min: 1; max: 1 };
  headlessSchemaRange: { min: number; max: number };
  stateSchemaRange: { min: number; max: number };
  workerProtocolRange: { min: number; max: number };
  entries: Array<{ entryId: string; role: string; version: string; relativePath: string;
    digest: string; byteCount: number; executable: boolean }>;
  structuredArtifacts: Array<{ artifactId: string; rootEntryId: string; artifactRef: string;
    semanticDigest: string; memberRefs: string[]; kind: string; provider?: string; model?: string; executableEntryId?: string }>;
  guestToolchainManifestRefs: string[];
  publisherKeyId: string; manifestDigest: string; signature: string;
};

export function exactKeys(value: object, keys: readonly string[]): boolean {
  return value !== null && typeof value === 'object' && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

export function requireEqual(left: unknown, right: unknown, label: string): void {
  if (canonicalSha256(left) !== canonicalSha256(right)) throw new TypeError(`${label} differs from retained authority`);
}

export function policyProfile(): PolicyEngineProfileV1 {
  const core = { schemaVersion: 1 as const, format: 'cliq-policy-engine-profile-v1' as const,
    evaluator: 'cliq-policy-evaluator-v1' as const, permissionGrammar: 'cliq-permission-grammar-v0' as const,
    bashParser: 'cliq-bash-head-parser-v1' as const };
  return { ...core, profileDigest: canonicalSha256(core) };
}

/** Signed manifest structure and role identities only; consumers still verify their selected bytes and semantics. */
export function verifyRuntimeBundle(bundle: RuntimeBundleManifest, releaseKeys: readonly ReleaseTrustKey[]): void {
  const { signature: _signature, manifestDigest: _digest, ...bundleCore } = bundle;
  if (!exactKeys(bundle, ['schemaVersion', 'bundleVersion', 'controlProtocolRange', 'headlessSchemaRange',
    'stateSchemaRange', 'workerProtocolRange', 'entries', 'structuredArtifacts', 'guestToolchainManifestRefs',
    'publisherKeyId', 'manifestDigest', 'signature']) || bundle.schemaVersion !== 1 ||
      typeof bundle.bundleVersion !== 'string' || !bundle.bundleVersion || canonicalJsonBytes(bundle).byteLength > 1_048_576 ||
      canonicalSha256(bundleCore) !== bundle.manifestDigest) throw new TypeError('RuntimeBundle identity mismatch');
  for (const range of [bundle.controlProtocolRange, bundle.headlessSchemaRange, bundle.stateSchemaRange, bundle.workerProtocolRange]) {
    if (!exactKeys(range, ['min', 'max']) || !Number.isSafeInteger(range.min) || !Number.isSafeInteger(range.max) ||
        range.min < 1 || range.min > range.max) throw new TypeError('invalid RuntimeBundle protocol range');
  }
  requireEqual(bundle.controlProtocolRange, { min: 1, max: 1 }, 'control protocol');
  const trusted = releaseKeys.filter((key) => key.keyId === bundle.publisherKeyId);
  if (trusted.length !== 1 || new Set(releaseKeys.map((key) => key.keyId)).size !== releaseKeys.length ||
      typeof bundle.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/u.test(bundle.signature)) {
    throw new TypeError('RuntimeBundle has no unique trusted release signature');
  }
  const key = createPublicKey(trusted[0]!.publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519' || !verify(null,
    Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`, 'utf8'), key, Buffer.from(bundle.signature, 'base64'))) {
    throw new TypeError('RuntimeBundle release signature is invalid');
  }
  const roles = ['supervisor', 'worker', 'provider_adapter', 'tool_adapter', 'policy_engine', 'system_prompt', 'compaction_prompt',
    'skill_bundle', 'guest_toolchain', 'sandbox_root_profile', 'mcp_server', 'mcp_recovery_adapter', 'mcp_recovery_profile',
    'local_inference', 'trust_store', 'schema', 'platform_helper', 'bundle_object'];
  for (const entry of bundle.entries) {
    if (!exactKeys(entry, ['entryId', 'role', 'version', 'relativePath', 'digest', 'byteCount', 'executable']) ||
        !roles.includes(entry.role) || typeof entry.entryId !== 'string' || !entry.entryId || typeof entry.version !== 'string' || !entry.version || typeof entry.executable !== 'boolean' ||
        !Number.isSafeInteger(entry.byteCount) || entry.byteCount < 0 || typeof entry.relativePath !== 'string' ||
        !entry.relativePath || entry.relativePath.includes('\\') || entry.relativePath.includes('\0') ||
        entry.relativePath.split('/').some((part) => ['', '.', '..'].includes(part))) throw new TypeError('invalid signed RuntimeBundle entry');
    assertArtifactRef(entry.digest);
  }
  for (const field of ['entryId', 'relativePath', 'digest'] as const) {
    if (new Set(bundle.entries.map((entry) => entry[field])).size !== bundle.entries.length) throw new TypeError(`duplicate bundle ${field}`);
  }
  const byRole = (role: string) => bundle.entries.filter((entry) => entry.role === role);
  if (byRole('supervisor').length !== 1 || !byRole('supervisor')[0]!.executable || byRole('worker').length < 1 || byRole('policy_engine').length !== 1 ||
      byRole('trust_store').length !== 1 || byRole('trust_store')[0]!.entryId !== 'default_https_trust_store' ||
      byRole('trust_store')[0]!.executable || byRole('sandbox_root_profile').length < 1 ||
      byRole('sandbox_root_profile').some((entry) => entry.executable)) throw new TypeError('RuntimeBundle required roles are missing or ambiguous');
  verifyStructuredBundleIndex(bundle);
}

const STRUCTURED_ROOT_ROLES = {
  system_prompt: 'system_prompt',
  compaction_prompt: 'compaction_prompt',
  mcp_recovery_adapter: 'mcp_recovery_profile',
  policy_engine_profile: 'policy_engine',
  bundled_skill: 'skill_bundle',
  guest_toolchain: 'guest_toolchain',
  legacy_portable_schema: 'schema'
} as const;

function boundedCanonicalLabel(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= 256 && normalizeCanonicalText(value) === value;
}

/** Check the signed index before an installer opens any referenced path. */
function verifyStructuredBundleIndex(bundle: RuntimeBundleManifest): void {
  if (!Array.isArray(bundle.structuredArtifacts) || !Array.isArray(bundle.guestToolchainManifestRefs)) {
    throw new TypeError('RuntimeBundle structured index is not an array');
  }
  const byId = new Map(bundle.entries.map((entry) => [entry.entryId, entry]));
  const roots = new Set<string>();
  const rootRefs = new Set<string>();
  const usedMembers = new Set<string>();
  const guestRefs: string[] = [];
  let previousKey: string | undefined;
  for (const structured of bundle.structuredArtifacts) {
    if (structured === null || typeof structured !== 'object' || Array.isArray(structured) ||
        !Object.hasOwn(STRUCTURED_ROOT_ROLES, structured.kind)) {
      throw new TypeError('RuntimeBundle has an unknown structured artifact kind');
    }
    const kind = structured.kind as keyof typeof STRUCTURED_ROOT_ROLES;
    const prompt = kind === 'system_prompt' || kind === 'compaction_prompt';
    const recovery = kind === 'mcp_recovery_adapter';
    const keys = ['kind', 'artifactId', 'rootEntryId', 'artifactRef', 'semanticDigest', 'memberRefs',
      ...(prompt ? ['provider', 'model'] : []), ...(recovery ? ['executableEntryId'] : [])];
    if (!exactKeys(structured, keys) ||
        !boundedCanonicalLabel(structured.artifactId) ||
        !boundedCanonicalLabel(structured.rootEntryId) ||
        typeof structured.artifactRef !== 'string' || typeof structured.semanticDigest !== 'string' ||
        !Array.isArray(structured.memberRefs)) {
      throw new TypeError('RuntimeBundle structured artifact has an invalid closed shape');
    }
    assertArtifactRef(structured.artifactRef);
    assertArtifactRef(structured.semanticDigest);
    if (prompt) {
      if (!['openai', 'anthropic', 'openrouter', 'openai-compatible', 'zhipu', 'ollama'].includes(
        String(structured.provider)) || !boundedCanonicalLabel(structured.model)) {
        throw new TypeError('RuntimeBundle prompt identity is invalid');
      }
    }
    if (recovery) {
      if (!boundedCanonicalLabel(structured.executableEntryId) ||
          byId.get(structured.executableEntryId)?.role !== 'mcp_recovery_adapter' ||
          !byId.get(structured.executableEntryId)?.executable) {
        throw new TypeError('RuntimeBundle recovery adapter executable is invalid');
      }
    }
    if (kind === 'legacy_portable_schema' &&
        structured.artifactId !== 'legacy_windows_export_profiles_v1') {
      throw new TypeError('RuntimeBundle legacy schema artifact id is invalid');
    }
    const key = [kind, prompt ? structured.provider : '', prompt ? structured.model : '', structured.artifactId].join('\0');
    if (previousKey !== undefined && Buffer.compare(Buffer.from(previousKey), Buffer.from(key)) >= 0) {
      throw new TypeError('RuntimeBundle structured artifacts are not unique and byte-sorted');
    }
    previousKey = key;
    const root = byId.get(structured.rootEntryId);
    if (!root || root.role !== STRUCTURED_ROOT_ROLES[kind] || root.executable ||
        root.digest !== structured.artifactRef || roots.has(root.entryId)) {
      throw new TypeError('RuntimeBundle structured root differs from its signed entry');
    }
    roots.add(root.entryId);
    rootRefs.add(structured.artifactRef);
    let previousMember: string | undefined;
    for (const member of structured.memberRefs) {
      if (typeof member !== 'string') throw new TypeError('RuntimeBundle member ref is not a string');
      assertArtifactRef(member);
      if (member === structured.artifactRef ||
          (previousMember !== undefined && previousMember >= member)) {
        throw new TypeError('RuntimeBundle members are self-referential, duplicated or unsorted');
      }
      previousMember = member;
      usedMembers.add(member);
    }
    if (kind === 'guest_toolchain') guestRefs.push(structured.artifactRef);
  }
  for (const entry of bundle.entries) {
    if (Object.values(STRUCTURED_ROOT_ROLES).includes(entry.role as typeof STRUCTURED_ROOT_ROLES[keyof typeof STRUCTURED_ROOT_ROLES]) &&
        !roots.has(entry.entryId)) {
      throw new TypeError('RuntimeBundle omits a required structured root');
    }
  }
  if (bundle.guestToolchainManifestRefs.length !== guestRefs.length ||
      bundle.guestToolchainManifestRefs.some((ref, index) => ref !== guestRefs[index])) {
    throw new TypeError('RuntimeBundle guest toolchain index differs from structured roots');
  }
  if ([...usedMembers].some((ref) => rootRefs.has(ref))) {
    throw new TypeError('RuntimeBundle structured root cannot be a member object');
  }
  const objects = bundle.entries.filter((entry) => entry.role === 'bundle_object');
  if (objects.length !== usedMembers.size) {
    throw new TypeError('RuntimeBundle has missing or unused member objects');
  }
  for (const member of usedMembers) {
    const entry = byId.get(identityHash('runtime-bundle-object-v1', member));
    if (!entry || entry.role !== 'bundle_object' || entry.executable || entry.version !== '1' ||
        entry.digest !== member ||
        entry.relativePath !== `objects/sha256/${member.slice(0, 2)}/${member}`) {
      throw new TypeError('RuntimeBundle member object does not match its signed path and digest');
    }
  }
}

/** Verify the signed manifest and exact selected policy/tool identities, not installation or other structured-root semantics. */
export function verifyToolRuntimeAuthority(input: {
  assembly: RunAssemblyV1; policy: RunPolicySnapshotV1; bundle: RuntimeBundleManifest;
  profile: PolicyEngineProfileV1; tools: ToolContractManifestV1['entries']; releaseKeys: readonly ReleaseTrustKey[];
}): void {
  const { assembly, policy, bundle, profile, tools, releaseKeys } = input;
  verifyRuntimeBundle(bundle, releaseKeys);
  if (canonicalSha256(bundle) !== assembly.runtime.runtimeBundleRef || bundle.manifestDigest !== assembly.runtime.runtimeBundleManifestDigest ||
      policy.engine.runtimeBundleRef !== assembly.runtime.runtimeBundleRef) throw new TypeError('policy RuntimeBundle identity mismatch');
  const byRole = (role: string) => bundle.entries.filter((entry) => entry.role === role);
  const profileEntry = byRole('policy_engine')[0]!;
  if (profileEntry.executable || profileEntry.entryId !== policy.engine.profileEntryId || profileEntry.version !== policy.engine.version ||
      profileEntry.digest !== policy.engine.profileRef || profileEntry.byteCount !== canonicalJsonBytes(profile).byteLength) {
    throw new TypeError('policy profile differs from the sole signed data entry');
  }
  requireEqual(profile, policyProfile(), 'fixed policy profile');
  if (profile.profileDigest !== policy.engine.profileDigest || canonicalSha256(profile) !== policy.engine.profileRef) {
    throw new TypeError('policy complete-byte and semantic digests do not match their own domains');
  }
  const profiles = bundle.structuredArtifacts.filter((entry) => entry.kind === 'policy_engine_profile');
  if (profiles.length !== 1 || !exactKeys(profiles[0]!, ['artifactId', 'rootEntryId', 'artifactRef', 'semanticDigest', 'memberRefs', 'kind']) ||
      !profiles[0]!.artifactId || profiles[0]!.rootEntryId !== profileEntry.entryId || profiles[0]!.artifactRef !== policy.engine.profileRef ||
      profiles[0]!.semanticDigest !== profile.profileDigest || profiles[0]!.memberRefs.length !== 0) {
    throw new TypeError('policy structured artifact is not the exact self-contained signed profile');
  }
  const executable = (id: string, digest: string, role: string, version?: string) => {
    const entry = bundle.entries.find((entry) => entry.entryId === id);
    if (!entry?.executable || entry.role !== role || entry.digest !== digest || (version !== undefined && entry.version !== version)) {
      throw new TypeError('selected executable does not match its signed RuntimeBundle entry');
    }
  };
  executable(assembly.runtime.workerExecutableId, assembly.runtime.workerExecutableDigest, 'worker');
  executable(assembly.provider.adapter.adapterId, assembly.provider.adapter.codeDigest, 'provider_adapter', assembly.provider.adapter.version);
  for (const tool of tools) if (tool.execution.kind === 'builtin') {
    executable(tool.execution.adapterId, tool.execution.adapterCodeDigest, 'tool_adapter', tool.execution.adapterVersion);
  }
}
