// Pure signed-artifact decoding shared by installation and its private
// credential repository. These functions never mint a physical/SQL/time owner.
import { X509Certificate } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, identityHash, normalizeBoundedText, sha256Bytes } from '../kernel/identity.js';
import type { ProviderName } from '../kernel/types.js';
import { verifyModelText } from '../model/attempt.js';
import { immutableSnapshot } from '../model/immutable.js';
import { compactionEnvelopeEstimate, type CompactionPromptEnvelopeMaterial, type CompactionPromptEnvelopeV1 } from '../model/request.js';
import { exactKeys, policyProfile, verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { KernelStorageError } from './errors.js';
import { decodeGuestToolchainManifest, guestToolchainMembers, guestToolchainRoots } from './guest-toolchain.js';
import { decodeBundledSkillClosure } from '../kernel/skill.js';
import { bundledSkillMembers, bundledSkillRoots } from './bundled-skills.js';
import { skillInstruction } from './skill-data.js';

function mismatch(message: string, cause?: unknown): never {
  throw new KernelStorageError('ARTIFACT_MISMATCH', message, cause === undefined ? undefined : { cause });
}

export function checkCanonicalBytes(bytes: Buffer): unknown {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
    let count = 0;
    while (pending.length) {
      const item = pending.pop()!;
      if (++count > 10_000 || item.depth > 32) mismatch('installed runtime canonical graph exceeds its decoding bound');
      if (item.value && typeof item.value === 'object') for (const child of Object.values(item.value)) pending.push({ value: child, depth: item.depth + 1 });
    }
    if (!canonicalJsonBytes(value).equals(bytes)) mismatch('installed runtime JSON bytes are not canonical');
    return value;
  } catch (cause) { if (cause instanceof KernelStorageError) throw cause; mismatch('installed runtime canonical data cannot be decoded', cause); }
}
export function validateBundle(value: unknown, releaseKeys: readonly ReleaseTrustKey[]): RuntimeBundleManifest {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) mismatch('installed runtime manifest must be an object');
    const bundle = value as RuntimeBundleManifest;
    if (!Array.isArray(bundle.entries) || !Array.isArray(bundle.structuredArtifacts) || !Array.isArray(bundle.guestToolchainManifestRefs)) mismatch('installed runtime manifest graph must contain arrays');
    verifyRuntimeBundle(bundle, releaseKeys);
    for (const entry of bundle.entries) {
      // This fixed signed script is code data for the retained guest Node,
      // never a host executable, native addon or caller-selected helper.
      const sourceInspector = entry.entryId === 'source_git_inspector' && entry.role === 'platform_helper' &&
        entry.version === '1' && entry.relativePath === 'helpers/source-git-inspector.mjs' &&
        !entry.executable && entry.byteCount >= 1 && entry.byteCount <= 1_048_576;
      const builtinTools = entry.entryId === 'builtin_tools' && entry.role === 'tool_adapter' &&
        entry.version === '1' && entry.relativePath === 'adapters/builtin-tools.mjs' &&
        !entry.executable && entry.byteCount >= 1 && entry.byteCount <= 1_048_576;
      if (entry.relativePath.normalize('NFC') !== entry.relativePath || Buffer.byteLength(entry.relativePath) > 4096 ||
          entry.relativePath === 'manifest.json' || entry.relativePath.startsWith('manifest.json/') ||
          entry.relativePath === 'model-authority.json' || entry.relativePath.startsWith('model-authority.json/') ||
          entry.relativePath === 'model-objects' || entry.relativePath.startsWith('model-objects/') ||
          (entry.executable && entry.byteCount === 0) ||
          (entry.entryId === 'source_git_inspector' && !sourceInspector) ||
          (entry.entryId === 'builtin_tools' && !builtinTools) ||
          (['supervisor', 'worker', 'provider_adapter', 'tool_adapter', 'platform_helper', 'mcp_server', 'mcp_recovery_adapter', 'local_inference'].includes(entry.role) && !entry.executable && !sourceInspector && !builtinTools) ||
          entry.role === 'mcp_recovery_profile' ||
          (entry.role === 'guest_toolchain' && entry.executable) ||
          (['policy_engine', 'system_prompt', 'compaction_prompt', 'bundle_object', 'schema', 'skill_bundle'].includes(entry.role) && entry.executable)) {
        mismatch('installed runtime entry path or role is unsupported');
      }
    }
    structuredMetadata(bundle);
    return immutableSnapshot(bundle);
  } catch (cause) { if (cause instanceof KernelStorageError) throw cause; mismatch('installed runtime release manifest failed validation', cause); }
}

type StructuredRoot = RuntimeBundleManifest['structuredArtifacts'][number];
function boundedText(value: unknown): string {
  if (typeof value !== 'string' || normalizeBoundedText(value, 1, 512) !== value) mismatch('installed structured root text is invalid');
  return value;
}
/** This installed recipe supports its fixed policy, prompts and signed guest.
 * Other normative kinds require their own complete implemented decoders. */
function structuredMetadata(bundle: RuntimeBundleManifest): StructuredRoot[] {
  if (bundle.structuredArtifacts.length > 65) mismatch('installed structured root inventory exceeds its bound');
  bundledSkillRoots(bundle); // The skill family also remains inside all original aggregate bounds.
  const roots: StructuredRoot[] = [], identities = new Set<string>(), entries = new Set<string>();
  let previous: Buffer | undefined;
  for (const root of bundle.structuredArtifacts) {
    const prompt = root.kind === 'system_prompt' || root.kind === 'compaction_prompt';
    if (!exactKeys(root, ['artifactId', 'rootEntryId', 'artifactRef', 'semanticDigest', 'memberRefs', 'kind',
      ...(prompt ? ['provider', 'model'] : [])]) || (!prompt && root.kind !== 'policy_engine_profile' && root.kind !== 'guest_toolchain' && root.kind !== 'bundled_skill'))
      mismatch('installed runtime contains an unsupported structured root');
    boundedText(root.artifactId); boundedText(root.rootEntryId);
    if (prompt && (!['openai', 'anthropic', 'openrouter', 'openai-compatible', 'zhipu', 'ollama'].includes(boundedText(root.provider)) ||
        !boundedText(root.model))) mismatch('installed provider prompt identity is invalid');
    assertArtifactRef(root.artifactRef); assertArtifactRef(root.semanticDigest);
    const key = Buffer.from([root.kind, root.provider ?? '', root.model ?? '', root.artifactId].join('\0'));
    const identity = [root.kind, root.provider ?? '', root.model ?? '', ...(root.kind === 'bundled_skill' ? [root.artifactId] : [])].join('\0');
    if ((previous && Buffer.compare(previous, key) >= 0) || identities.has(identity) || entries.has(root.rootEntryId))
      mismatch('installed structured roots are unordered or ambiguous');
    previous = key; identities.add(identity); entries.add(root.rootEntryId);
    const entry = bundle.entries.find(entry => entry.entryId === root.rootEntryId);
    const role = root.kind === 'policy_engine_profile' ? 'policy_engine' : root.kind === 'bundled_skill' ? 'skill_bundle' : root.kind;
    if (!entry || entry.executable || entry.role !== role || entry.digest !== root.artifactRef || entry.byteCount > 1048576 ||
        !Array.isArray(root.memberRefs) || root.memberRefs.length > (root.kind === 'bundled_skill' ? 129 : 3) ||
        root.memberRefs.some((ref, index) => { assertArtifactRef(ref); return ref === root.artifactRef || (index > 0 && ref <= root.memberRefs[index - 1]!); }) ||
        (root.kind !== 'compaction_prompt' && root.kind !== 'guest_toolchain' && root.kind !== 'bundled_skill' && root.memberRefs.length !== 0))
      mismatch('installed structured root does not bind its complete signed entry');
    roots.push(root);
  }
  if (roots.filter(root => root.kind === 'policy_engine_profile').length !== 1 ||
      bundle.entries.some(entry => ['policy_engine', 'system_prompt', 'compaction_prompt', 'guest_toolchain', 'skill_bundle'].includes(entry.role) && !entries.has(entry.entryId)))
    mismatch('installed signed structured entries are missing their exact discovery roots');
  for (const root of roots.filter(root => root.kind === 'system_prompt')) {
    if (!roots.some(other => other.kind === 'compaction_prompt' && other.provider === root.provider && other.model === root.model))
      mismatch('installed provider prompt pair is incomplete');
  }
  for (const root of roots.filter(root => root.kind === 'compaction_prompt')) {
    if (!roots.some(other => other.kind === 'system_prompt' && other.provider === root.provider && other.model === root.model))
      mismatch('installed provider prompt pair is incomplete');
  }
  guestToolchainRoots(bundle);
  return roots;
}

export type InstalledStructuredArtifacts = Readonly<{
  systemPrompts: readonly Readonly<{ provider: ProviderName; model: string; ref: string; value: ModelTextV1 }>[];
  compactionPrompts: readonly Readonly<{ provider: ProviderName; model: string; material: CompactionPromptEnvelopeMaterial }>[];
  objects: readonly Readonly<{ artifactRef: string; schemaKind: string }>[];
}>;

/** Complete structured metadata/member validation, after physical byte capture.
 * Guest image bytes are streamed by installation, never buffered as JSON here;
 * that owner independently authenticates each guest's detached release signature.
 * A valid data graph does not authorize a process, model or tool dispatch. */
export function validateInstalledStructuredArtifacts(bundle: RuntimeBundleManifest,
  objects: ReadonlyMap<string, Buffer>): InstalledStructuredArtifacts {
  try {
    const roots = structuredMetadata(bundle);
    const metadata = new Map<string, string>(), members = new Set<string>();
    const systemPrompts: Array<{ provider: ProviderName; model: string; ref: string; value: ModelTextV1 }> = [];
    const compactionPrompts: Array<{ provider: ProviderName; model: string; material: CompactionPromptEnvelopeMaterial }> = [];
    const raw = (ref: string): Buffer => {
      const entry = bundle.entries.find(entry => entry.digest === ref), bytes = objects.get(ref);
      if (!entry || !Buffer.isBuffer(bytes) || bytes.length !== entry.byteCount || sha256Bytes(bytes) !== ref)
        mismatch('installed structured object bytes do not bind their signed entry');
      return bytes;
    };
    const read = (ref: string): unknown => checkCanonicalBytes(raw(ref));
    for (const root of roots) {
      const value = read(root.artifactRef);
      if (root.kind === 'policy_engine_profile') {
        const profile = policyProfile();
        if (canonicalSha256(value) !== canonicalSha256(profile) || root.semanticDigest !== profile.profileDigest)
          mismatch('signed policy root is not the fixed supported evaluator profile');
        metadata.set(root.artifactRef, profile.format);
      } else if (root.kind === 'system_prompt') {
        const text = value as ModelTextV1;
        verifyModelText(text);
        if (!text.utf8.trim() || text.textDigest !== root.semanticDigest) mismatch('installed system prompt is empty or has another semantic digest');
        metadata.set(root.artifactRef, text.format);
        systemPrompts.push({ provider: root.provider as ProviderName, model: root.model!, ref: root.artifactRef, value: text });
      } else if (root.kind === 'guest_toolchain') {
        const manifest = decodeGuestToolchainManifest(value);
        guestToolchainMembers(bundle, root.artifactRef, manifest);
        if (raw(manifest.signatureRef).length !== 64) mismatch('guest detached signature is not complete');
        for (const member of root.memberRefs) members.add(member);
        metadata.set(root.artifactRef, manifest.format);
        metadata.set(manifest.signatureRef, 'cliq-ed25519-signature-v1');
        metadata.set(manifest.guestImageRef, 'cliq-guest-image-raw-ext4-v1');
      } else if (root.kind === 'bundled_skill') {
        const closure = decodeBundledSkillClosure(value);
        bundledSkillMembers(bundle, root, closure);
        const instruction = closure.files.find(file => file.canonicalRelativePath === 'SKILL.md')!;
        skillInstruction(closure.skillId, raw(instruction.rawBytesRef));
        metadata.set(root.artifactRef, closure.format);
        for (const file of closure.files) {
          members.add(file.rawBytesRef); metadata.set(file.rawBytesRef, 'cliq-skill-source-file-v1');
        }
      } else {
        const envelope = value as CompactionPromptEnvelopeV1;
        const expected = [...new Set([envelope.systemInstructionRef, envelope.userPrefixRef, envelope.userSuffixRef])].sort();
        if (canonicalSha256(expected) !== canonicalSha256(root.memberRefs)) mismatch('installed compaction members differ from the exact envelope');
        const text = (ref: string) => {
          const entry = bundle.entries.find(entry => entry.digest === ref);
          if (!entry || entry.role !== 'bundle_object' || entry.executable || entry.entryId !== identityHash('runtime-bundle-object-v1', ref) ||
              entry.version !== '1' || entry.relativePath !== `objects/sha256/${ref.slice(0, 2)}/${ref}`)
            mismatch('installed prompt member is not its exact signed object entry');
          const value = read(ref) as ModelTextV1;
          verifyModelText(value); members.add(ref); metadata.set(ref, value.format); return { ref, value };
        };
        const material: CompactionPromptEnvelopeMaterial = { ref: root.artifactRef, value: envelope,
          systemInstruction: text(envelope.systemInstructionRef), userPrefix: text(envelope.userPrefixRef), userSuffix: text(envelope.userSuffixRef) };
        compactionEnvelopeEstimate(material);
        if (envelope.envelopeDigest !== root.semanticDigest) mismatch('installed compaction envelope semantic digest differs');
        metadata.set(root.artifactRef, envelope.format);
        compactionPrompts.push({ provider: root.provider as ProviderName, model: root.model!, material });
      }
    }
    if (bundle.entries.some(entry => entry.role === 'bundle_object' && !members.has(entry.digest)))
      mismatch('installed runtime contains an unused signed bundle object');
    return immutableSnapshot({ systemPrompts, compactionPrompts,
      objects: [...metadata].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .map(([artifactRef, schemaKind]) => ({ artifactRef, schemaKind })) });
  } catch (cause) { if (cause instanceof KernelStorageError) throw cause; mismatch('installed structured prompt closure failed validation', cause); }
}
export function validateTrustStore(bytes: Buffer): void {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const certificates = text.match(/-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu);
    if (!certificates?.length || text.replace(/-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu, '').trim()) mismatch('signed HTTPS trust store must contain only PEM certificates');
    for (const certificate of certificates) new X509Certificate(certificate);
  } catch (cause) { if (cause instanceof KernelStorageError) throw cause; mismatch('signed HTTPS trust store is invalid', cause); }
}
