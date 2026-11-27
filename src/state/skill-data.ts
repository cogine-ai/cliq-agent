// Complete immutable skill data only. Filesystem capture, installed release
// composition, admission, policy, owner and execution gates remain separate.
import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { isUtf8 } from 'node:buffer';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeBundledSkillClosure, decodeSkillManifest, decodeSkillSourceIdentity,
  type SkillManifestV1, type SkillSourceIdentityV1, type SkillResourceInputV1, type SkillResourceOutputV1, type SkillResourceKind,
  decodeSkillResourceInput, decodeSkillResourceOutput } from '../kernel/skill.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyModelText } from '../model/attempt.js';
import { verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { exactKeys } from '../policy/runtime-authority.js';
import type { RunAssemblyV1 } from '../kernel/types.js';
import { parseCanonicalTime } from '../kernel/identity.js';
import { parseFrozenSkillMarkdown } from '../skills/markdown.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeLocalPrincipalIdentity, decodeStateRootIdentity, decodeWorkspaceIdentity } from './decoders.js';
import { bundledSkillMembers, bundledSkillRoots } from './bundled-skills.js';
import { validateFrozenSkillResourceGraph } from '../skills/resources.js';

export type SkillAssemblyBinding = Readonly<{ workspaceIdentityRef: string; workspaceIdentityDigest: string; ownerPrincipalId: string;
  runtimeBundleRef: string; runtimeBundleManifestDigest: string }>;
export type FrozenSkillData = Readonly<{ manifestRef: string; manifest: Readonly<SkillManifestV1>;
  source: Readonly<SkillSourceIdentityV1>; instruction: Readonly<ModelTextV1>;
  /** Private complete byte copies for this one owned read, never an execution FD. */
  files: ReadonlyMap<string, Buffer> }>;
type SkillAssembly = Pick<RunAssemblyV1, 'instructions' | 'runtime' | 'createdAt'>;
function invalid(): never { throw new TypeError('frozen skill closure does not match its original sources'); }
function same(left: unknown, right: unknown): boolean { return canonicalSha256(left) === canonicalSha256(right); }
async function canonical<T>(artifacts: ArtifactCatalog, ref: string): Promise<T> {
  const value = await artifacts.readCanonical<T>(ref); if (canonicalSha256(value) !== ref) invalid(); return value;
}

/** Derive source bindings from the original immutable assembly/instruction
 * graph. This reads neither today's Session head nor a mutable skill path. */
export async function readSkillAssemblyBinding(artifacts: ArtifactCatalog, assembly: SkillAssembly): Promise<SkillAssemblyBinding> {
  const manifest = await canonical<Record<string, unknown>>(artifacts, assembly.instructions.workspaceInstructionsRef);
  if (!exactKeys(manifest, ['schemaVersion', 'format', 'workspaceIdentityDigest', 'instructionSourceRef', 'instructionSourceDigest', 'rendering', 'entries', 'manifestDigest']) ||
      manifest.schemaVersion !== 1 || manifest.format !== 'cliq-workspace-instructions-v1' || manifest.rendering !== 'cliq-all-scopes-labeled-instructions-v1' ||
      manifest.manifestDigest !== assembly.instructions.workspaceInstructionsDigest || digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest ||
      typeof manifest.instructionSourceRef !== 'string' || !Array.isArray(manifest.entries) || manifest.entries.length > 64) invalid();
  const source = await canonical<Record<string, unknown>>(artifacts, manifest.instructionSourceRef);
  if (!exactKeys(source, ['schemaVersion', 'format', 'workspaceIdentityRef', 'workspaceIdentityDigest', 'entries', 'capturedAt', 'sourceDigest']) ||
      source.schemaVersion !== 1 || source.format !== 'cliq-workspace-instruction-source-v1' ||
      source.sourceDigest !== manifest.instructionSourceDigest || digestOmitting(source, 'sourceDigest') !== source.sourceDigest ||
      source.workspaceIdentityDigest !== manifest.workspaceIdentityDigest || typeof source.workspaceIdentityRef !== 'string' ||
      typeof source.capturedAt !== 'string' || !Array.isArray(source.entries) || source.entries.length !== manifest.entries.length) invalid();
  parseCanonicalTime(source.capturedAt); parseCanonicalTime(assembly.createdAt);
  if (source.capturedAt > assembly.createdAt) invalid();
  const workspace = decodeWorkspaceIdentity(await canonical(artifacts, source.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.identityDigest !== source.workspaceIdentityDigest) invalid();
  const bundle = await canonical<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
  verifyRuntimeBundle(bundle, artifacts.releaseTrustRoots());
  if (bundle.manifestDigest !== assembly.runtime.runtimeBundleManifestDigest) invalid();
  return Object.freeze({ workspaceIdentityRef: source.workspaceIdentityRef, workspaceIdentityDigest: workspace.identityDigest,
    ownerPrincipalId: workspace.ownerPrincipalId, runtimeBundleRef: assembly.runtime.runtimeBundleRef,
    runtimeBundleManifestDigest: assembly.runtime.runtimeBundleManifestDigest });
}

/** Explicit order and all-and-only full closures, shared by model projection,
 * installed material verification, local resource reads and recovery. */
export async function readAssemblySkills(artifacts: ArtifactCatalog, assembly: SkillAssembly,
  expected?: Readonly<{ workspaceIdentityRef: string; ownerPrincipalId: string }>): Promise<readonly Omit<FrozenSkillData, 'files'>[]> {
  const selected = assembly.instructions.skills;
  if (selected.length > 64 || new Set(selected.map(skill => skill.skillId)).size !== selected.length) invalid();
  if (!selected.length) return Object.freeze([]);
  const binding = await readSkillAssemblyBinding(artifacts, assembly);
  if (expected && (binding.workspaceIdentityRef !== expected.workspaceIdentityRef || binding.ownerPrincipalId !== expected.ownerPrincipalId)) invalid();
  const result: Omit<FrozenSkillData, 'files'>[] = [];
  for (const selection of selected) {
    const { files: _completePrivateBytes, ...description } = await readFrozenSkillData(artifacts, selection, binding);
    result.push(Object.freeze(description));
  }
  return Object.freeze(result);
}

/** Metadata describes only the complete original reads above. It is committed
 * by the owning ordinary admission transaction; labels confer no authority. */
export async function readAssemblySkillMetadata(artifacts: ArtifactCatalog, assembly: SkillAssembly,
  expected: Readonly<{ workspaceIdentityRef: string; ownerPrincipalId: string }>): Promise<readonly PublishedArtifact[]> {
  const descriptions = await readAssemblySkills(artifacts, assembly, expected), metadata = new Map<string, PublishedArtifact>();
  for (const { manifestRef, manifest, source, instruction } of descriptions) {
    for (const [ref, value] of [[manifestRef, manifest], [manifest.sourceIdentityRef, source], [manifest.instructionRef, instruction]] as const)
      metadata.set(ref, { ref, byteLength: canonicalJsonBytes(value).length, mediaType: 'application/json', schemaKind: value.format });
    for (const file of source.files) metadata.set(file.rawBytesRef, { ref: file.rawBytesRef, byteLength: file.rawByteCount,
      mediaType: 'application/octet-stream', schemaKind: 'cliq-skill-source-file-v1' });
  }
  artifacts.assertReadActive(); return Object.freeze([...metadata.values()]);
}

/** The pure rendering algorithm shared by capture and every retained reader.
 * Frontmatter may describe allowed tools; it cannot grant any of them. */
export function skillInstruction(skillId: string, raw: Buffer): Readonly<ModelTextV1> {
  const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
  if (!raw.length || raw.length > 1048576 || !Buffer.from(utf8).equals(raw) ||
      utf8.includes('\r') || normalizeCanonicalText(utf8) !== utf8) invalid();
  const parsed = parseFrozenSkillMarkdown(utf8);
  if (parsed.manifest.name !== skillId || parsed.diagnostics.some(item => item.level === 'error') || !parsed.prompt.trim()) invalid();
  const core = { schemaVersion: 1 as const, format: 'cliq-model-text-v1' as const,
    utf8: parsed.prompt, byteCount: Buffer.byteLength(parsed.prompt) };
  const text = { ...core, textDigest: canonicalSha256(core) }; verifyModelText(text); return immutableSnapshot(text);
}

/** Classification describes inert bytes; no kind is executable authority. */
export function frozenSkillResourceKind(name: string, raw: Uint8Array, executableMode: boolean): SkillResourceKind {
  if (executableMode || !isUtf8(raw) || raw.includes(0) || name.startsWith('scripts/') ||
      /\.(?:py|sh|bash|js|mjs|cjs|ts|tsx|pl|rb|php|exe|dll|so|dylib|wasm)$/iu.test(name)) return 'executable-disabled';
  if (name.endsWith('.schema.json')) return 'schema';
  return name.startsWith('templates/') || /\.(?:tmpl|template)$/u.test(name) ? 'template' : 'text';
}

/** No mutable path is read. The catalog's release roots come only from the
 * trusted installed composition; a source/manifest cannot extend those roots. */
export async function readFrozenSkillData(artifacts: ArtifactCatalog,
  selected: Readonly<{ skillId: string; manifestRef: string; manifestDigest: string }>, binding: SkillAssemblyBinding): Promise<FrozenSkillData> {
  artifacts.assertReadActive();
  const manifest = decodeSkillManifest(await canonical(artifacts, selected.manifestRef));
  if (manifest.skillId !== selected.skillId || manifest.manifestDigest !== selected.manifestDigest) invalid();
  const source = decodeSkillSourceIdentity(await canonical(artifacts, manifest.sourceIdentityRef));
  if (source.skillId !== manifest.skillId || source.sourceScope !== manifest.sourceScope ||
      source.sourceIdentityDigest !== manifest.sourceIdentityDigest) invalid();
  if (source.sourceScope === 'workspace') {
    const workspace = decodeWorkspaceIdentity(await canonical(artifacts, source.workspaceIdentityRef));
    if (workspace.kind !== 'live' || source.workspaceIdentityRef !== binding.workspaceIdentityRef ||
        workspace.identityDigest !== source.workspaceIdentityDigest || workspace.identityDigest !== binding.workspaceIdentityDigest ||
        workspace.ownerPrincipalId !== binding.ownerPrincipalId || source.rootDescriptor.deviceId !== workspace.rootIdentity.deviceId ||
        String(source.rootDescriptor.ownerUid) !== String(workspace.rootIdentity.ownerUid) ||
        !['.cliq/skills/', '.agents/skills/'].some(prefix => source.rootDescriptor.canonicalRootRelativePath === prefix + manifest.skillId)) invalid();
  } else if (source.sourceScope === 'user') {
    const principal = decodeLocalPrincipalIdentity(await canonical(artifacts, source.principalIdentityRef));
    const root = decodeStateRootIdentity(await canonical(artifacts, principal.stateRootIdentityRef));
    if (principal.principalId !== binding.ownerPrincipalId || source.ownerPrincipalId !== binding.ownerPrincipalId ||
        principal.identityDigest !== source.principalIdentityDigest || principal.effectiveUid !== source.rootDescriptor.ownerUid ||
        root.identityDigest !== principal.stateRootIdentityDigest || root.ownerUid !== principal.effectiveUid ||
        !['/.cliq/skills/', '/.agents/skills/'].some(segment => source.rootDescriptor.canonicalAbsolutePath.endsWith(segment + manifest.skillId))) invalid();
  } else {
    if (source.runtimeBundleRef !== binding.runtimeBundleRef || source.runtimeBundleManifestDigest !== binding.runtimeBundleManifestDigest) invalid();
    const bundle = await canonical<RuntimeBundleManifest>(artifacts, source.runtimeBundleRef);
    verifyRuntimeBundle(bundle, artifacts.releaseTrustRoots());
    if (bundle.manifestDigest !== source.runtimeBundleManifestDigest) invalid();
    const entries = bundle.entries.filter(entry => entry.entryId === source.bundleEntryId);
    const entry = entries[0];
    if (entries.length !== 1 || !entry || entry.version !== source.bundleEntryVersion || entry.role !== 'skill_bundle' ||
        entry.executable || entry.digest !== source.bundledClosureRef) invalid();
    const closureRaw = await artifacts.readBytes(source.bundledClosureRef);
    if (closureRaw.length !== entry.byteCount || sha256Bytes(closureRaw) !== entry.digest) invalid();
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(closureRaw));
    if (!canonicalJsonBytes(value).equals(closureRaw)) invalid();
    const closure = decodeBundledSkillClosure(value);
    const root = bundledSkillRoots(bundle).find(root => root.rootEntryId === source.bundleEntryId);
    if (!root) invalid(); bundledSkillMembers(bundle, root, closure);
    if (closure.skillId !== manifest.skillId || closure.closureDigest !== source.bundledClosureDigest ||
        !same(closure.files, source.files.map(({ canonicalRelativePath, rawBytesRef, rawBytesDigest, rawByteCount }) =>
          ({ canonicalRelativePath, rawBytesRef, rawBytesDigest, rawByteCount })))) invalid();
  }
  const expectedPaths = ['SKILL.md', ...manifest.resources.map(resource => resource.canonicalRelativePath)].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  if (!same(expectedPaths, source.files.map(file => file.canonicalRelativePath))) invalid();
  const files = new Map<string, Buffer>();
  const bytes = await artifacts.mapReads(source.files, async file => {
    // The complete original byte stream is exhausted even when a later
    // consumer will request only one bounded range.
    const chunks: Buffer[] = []; let size = 0;
    for await (const chunk of artifacts.readChunks(file.rawBytesRef, file.rawByteCount)) {
      size += chunk.length; if (size > file.rawByteCount) invalid(); chunks.push(chunk);
    }
    const value = Buffer.concat(chunks);
    if (size !== file.rawByteCount || sha256Bytes(value) !== file.rawBytesDigest) invalid();
    return value;
  });
  source.files.forEach((file, index) => files.set(file.canonicalRelativePath, bytes[index]!));
  validateFrozenSkillResourceGraph(files, manifest.resources.map(resource => resource.canonicalRelativePath));
  const instruction = await canonical<ModelTextV1>(artifacts, manifest.instructionRef); verifyModelText(instruction);
  if (instruction.textDigest !== manifest.instructionDigest || !same(instruction, skillInstruction(manifest.skillId, files.get('SKILL.md')!))) invalid();
  for (const resource of manifest.resources) {
    const file = source.files.find(file => file.canonicalRelativePath === resource.canonicalRelativePath)!;
    const captured = source.sourceScope === 'bundled' ? undefined : source.files.find(file => file.canonicalRelativePath === resource.canonicalRelativePath)!;
    if (resource.contentRef !== file.rawBytesRef || resource.contentDigest !== file.rawBytesDigest || resource.kind !==
        frozenSkillResourceKind(file.canonicalRelativePath, files.get(file.canonicalRelativePath)!, !!captured && [448, 493].includes(captured.fileDescriptor.mode))) invalid();
  }
  artifacts.assertReadActive();
  return Object.freeze({ manifestRef: selected.manifestRef, manifest, source, instruction: immutableSnapshot(instruction), files });
}

/** A data projection only. The owning local reducer still checks the actual
 * current Run, original request/grant, selected closure, Stop and SQL cut. */
export function frozenSkillResourceRange(skill: FrozenSkillData, request: Readonly<SkillResourceInputV1>): Readonly<SkillResourceOutputV1> {
  const input = decodeSkillResourceInput(request);
  if (skill.manifest.skillId !== input.skillId) invalid();
  const resource = skill.manifest.resources.find(resource => resource.canonicalRelativePath === input.canonicalRelativePath);
  const value = skill.files.get(input.canonicalRelativePath);
  if (!resource || !value || sha256Bytes(value) !== resource.contentRef || input.offset > value.length) invalid();
  const bytes = value.subarray(input.offset, Math.min(input.offset + input.length, value.length)), nextOffset = input.offset + bytes.length;
  return decodeSkillResourceOutput({ schemaVersion: 1, skillId: input.skillId, canonicalRelativePath: input.canonicalRelativePath,
    kind: resource.kind, byteCount: value.length, offset: input.offset, bytesBase64: bytes.toString('base64'), nextOffset, eof: nextOffset === value.length });
}
