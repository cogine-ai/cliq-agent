import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { CompactionPromptEnvelopeV1 } from '../model/request.js';
import { verifyModelText } from '../model/attempt.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { exactKeys, policyProfile, verifyRuntimeBundle,
  type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';

type BundleEntry = RuntimeBundleManifest['entries'][number];
type StructuredRoot = RuntimeBundleManifest['structuredArtifacts'][number];

/** A caller supplies bytes from an already held source; this verifier never opens a mutable path. */
export type BundleEntryReader = (entry: Readonly<BundleEntry>) => Promise<Uint8Array>;

function parseCanonical(bytes: Uint8Array, label: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    throw new TypeError(`${label} is not JSON`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      !canonicalJsonBytes(value).equals(Buffer.from(bytes))) {
    throw new TypeError(`${label} is not exact canonical JSON`);
  }
  return value as Record<string, unknown>;
}

function sortedRefs(refs: readonly string[]): string[] {
  return [...new Set(refs)].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}

function requireMembers(root: StructuredRoot, refs: readonly string[]): void {
  if (JSON.stringify(root.memberRefs) !== JSON.stringify(sortedRefs(refs))) {
    throw new TypeError(`RuntimeBundle ${root.kind} member closure differs from decoded payload`);
  }
}

function requireSemantic(root: StructuredRoot, value: Record<string, unknown>, digestField: string): void {
  if (typeof value[digestField] !== 'string') {
    throw new TypeError(`RuntimeBundle ${root.kind} semantic digest is missing`);
  }
  assertArtifactRef(value[digestField]);
  if (digestOmitting(value, digestField) !== value[digestField] || value[digestField] !== root.semanticDigest) {
    throw new TypeError(`RuntimeBundle ${root.kind} semantic digest differs from decoded bytes`);
  }
}

function verifyText(root: StructuredRoot, value: Record<string, unknown>): void {
  verifyModelText(value as ModelTextV1);
  if (!value.utf8 || typeof value.utf8 !== 'string') {
    throw new TypeError('RuntimeBundle system prompt is empty');
  }
  requireSemantic(root, value, 'textDigest');
  requireMembers(root, []);
}

async function verifyCompaction(root: StructuredRoot, value: Record<string, unknown>,
  readMember: (ref: string) => Promise<Uint8Array>): Promise<void> {
  if (!exactKeys(value, ['schemaVersion', 'format', 'systemInstructionRef', 'systemInstructionDigest',
    'userPrefixRef', 'userPrefixDigest', 'sourcePlaceholder', 'userSuffixRef', 'userSuffixDigest',
    'resultContract', 'envelopeDigest']) || value.schemaVersion !== 1 ||
      value.format !== 'cliq-compaction-prompt-envelope-v1' ||
      value.sourcePlaceholder !== '{{CLIQ_SOURCE_CONTEXT_UTF8}}' ||
      value.resultContract === null || typeof value.resultContract !== 'object' ||
      Array.isArray(value.resultContract) ||
      !exactKeys(value.resultContract, ['toolsAllowed', 'requiredStopReason', 'mediaType', 'summaryFormat'])) {
    throw new TypeError('RuntimeBundle compaction envelope has invalid shape');
  }
  const envelope = value as CompactionPromptEnvelopeV1;
  if (envelope.resultContract.toolsAllowed !== false || envelope.resultContract.requiredStopReason !== 'end' ||
      envelope.resultContract.mediaType !== 'text/markdown; charset=utf-8' ||
      envelope.resultContract.summaryFormat !== 'cliq-context-summary-markdown-v1') {
    throw new TypeError('RuntimeBundle compaction envelope has invalid result contract');
  }
  requireSemantic(root, value, 'envelopeDigest');
  const members = [
    [envelope.systemInstructionRef, envelope.systemInstructionDigest],
    [envelope.userPrefixRef, envelope.userPrefixDigest],
    [envelope.userSuffixRef, envelope.userSuffixDigest]
  ] as const;
  requireMembers(root, members.map(([ref]) => ref));
  const texts: string[] = [];
  for (const [ref, digest] of members) {
    assertArtifactRef(ref);
    assertArtifactRef(digest);
    const bytes = await readMember(ref);
    // ModelText is bounded to 1 MiB of text plus a small canonical envelope.
    if (bytes.byteLength > 1_050_000) {
      throw new TypeError('RuntimeBundle compaction text exceeds its byte limit');
    }
    const text = parseCanonical(bytes, 'compaction ModelText');
    verifyModelText(text as ModelTextV1);
    if (text.textDigest !== digest) throw new TypeError('RuntimeBundle compaction text digest differs');
    texts.push(text.utf8 as string);
  }
  if (texts.some((text) => text.includes(envelope.sourcePlaceholder)) ||
      texts.reduce((sum, text) => sum + Buffer.byteLength(text), 0) > 262_144) {
    throw new TypeError('RuntimeBundle compaction fixed text violates its bounds');
  }
}

function canonicalRelativePath(value: unknown): value is string {
  if (typeof value !== 'string' || !value || value.includes('\\') ||
      normalizeCanonicalText(value) !== value || Buffer.byteLength(value) > 4096) return false;
  return value.split('/').every((part) => part !== '' && part !== '.' && part !== '..');
}

async function verifyBundledSkill(root: StructuredRoot, value: Record<string, unknown>,
  readMember: (ref: string) => Promise<Uint8Array>): Promise<void> {
  if (!exactKeys(value, ['schemaVersion', 'format', 'skillId', 'files', 'closureDigest']) ||
      value.schemaVersion !== 1 || value.format !== 'cliq-bundled-skill-closure-v1' ||
      value.skillId !== root.artifactId || !Array.isArray(value.files) ||
      value.files.length < 1 || value.files.length > 128) {
    throw new TypeError('RuntimeBundle bundled skill has invalid closure');
  }
  requireSemantic(root, value, 'closureDigest');
  const refs: string[] = [];
  let previousPath: string | undefined;
  let totalBytes = 0;
  let hasInstructions = false;
  for (const file of value.files) {
    if (file === null || typeof file !== 'object' || Array.isArray(file) ||
        !exactKeys(file, ['canonicalRelativePath', 'rawBytesRef', 'rawBytesDigest', 'rawByteCount']) ||
        !canonicalRelativePath(file.canonicalRelativePath) ||
        (previousPath !== undefined && Buffer.compare(Buffer.from(previousPath), Buffer.from(file.canonicalRelativePath)) >= 0) ||
        typeof file.rawBytesRef !== 'string' || typeof file.rawBytesDigest !== 'string' ||
        !Number.isSafeInteger(file.rawByteCount) || file.rawByteCount < 0) {
      throw new TypeError('RuntimeBundle bundled skill file entry is invalid');
    }
    assertArtifactRef(file.rawBytesRef);
    assertArtifactRef(file.rawBytesDigest);
    if (file.rawBytesRef !== file.rawBytesDigest) {
      throw new TypeError('RuntimeBundle bundled skill raw-byte domains differ');
    }
    previousPath = file.canonicalRelativePath;
    totalBytes += file.rawByteCount;
    if (totalBytes > 16_777_216) throw new TypeError('RuntimeBundle bundled skill exceeds byte limit');
    const bytes = await readMember(file.rawBytesRef);
    if (bytes.byteLength !== file.rawByteCount) throw new TypeError('RuntimeBundle bundled skill byte count differs');
    if (file.canonicalRelativePath === 'SKILL.md') {
      const text = Buffer.from(bytes).toString('utf8');
      if (!text || !Buffer.from(text).equals(Buffer.from(bytes)) ||
          text.includes('\r') || normalizeCanonicalText(text) !== text) {
        throw new TypeError('RuntimeBundle bundled SKILL.md is not canonical text');
      }
      hasInstructions = true;
    }
    refs.push(file.rawBytesRef);
  }
  if (!hasInstructions) throw new TypeError('RuntimeBundle bundled skill has no SKILL.md');
  requireMembers(root, refs);
}

/**
 * Verifies complete bytes and decoded semantics for the currently implemented
 * structured kinds. Unsupported kinds fail closed; installation cannot select
 * a bundle merely because its signed index passed.
 */
export async function verifyBundleStructuredPayloads(bundle: RuntimeBundleManifest,
  releaseKeys: readonly ReleaseTrustKey[], readEntry: BundleEntryReader): Promise<void> {
  verifyRuntimeBundle(bundle, releaseKeys);
  const byId = new Map(bundle.entries.map((entry) => [entry.entryId, entry]));
  const byRef = new Map(bundle.entries.map((entry) => [entry.digest, entry]));
  const read = async (entry: BundleEntry): Promise<Uint8Array> => {
    if (entry.byteCount > 16_777_216) {
      throw new TypeError(`RuntimeBundle structured entry ${entry.entryId} exceeds its byte limit`);
    }
    const source = await readEntry(entry);
    if (!(source instanceof Uint8Array) || source.byteLength !== entry.byteCount) {
      throw new TypeError(`RuntimeBundle entry ${entry.entryId} does not match signed bytes`);
    }
    // The reader may expose a mutable view. Hash and decode one private snapshot.
    const bytes = Buffer.from(source);
    if (sha256Bytes(bytes) !== entry.digest) {
      throw new TypeError(`RuntimeBundle entry ${entry.entryId} does not match signed bytes`);
    }
    return bytes;
  };
  const readMember = async (ref: string): Promise<Uint8Array> => {
    const entry = byRef.get(ref);
    if (!entry || entry.role !== 'bundle_object') throw new TypeError('RuntimeBundle member is not a signed object');
    return read(entry);
  };
  for (const root of bundle.structuredArtifacts) {
    const entry = byId.get(root.rootEntryId)!;
    if (entry.byteCount > 1_048_576) {
      throw new TypeError(`RuntimeBundle ${root.kind} root exceeds its byte limit`);
    }
    const value = parseCanonical(await read(entry), `RuntimeBundle ${root.kind}`);
    switch (root.kind) {
      case 'policy_engine_profile':
        if (canonicalSha256(value) !== canonicalSha256(policyProfile())) {
          throw new TypeError('RuntimeBundle policy profile differs from fixed Supervisor profile');
        }
        requireSemantic(root, value, 'profileDigest');
        requireMembers(root, []);
        break;
      case 'system_prompt':
        verifyText(root, value);
        break;
      case 'compaction_prompt':
        await verifyCompaction(root, value, readMember);
        break;
      case 'bundled_skill':
        await verifyBundledSkill(root, value, readMember);
        break;
      default:
        throw new TypeError(`RuntimeBundle ${root.kind} semantic decoder is unavailable`);
    }
  }
}
