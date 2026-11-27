// Descriptor-backed declarative capture. The caller must cross Workspace
// Trust first; a selected skill grants no tool or execution permissions.
import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { canonicalSkillId, decodeBundledSkillClosure, decodeSkillManifest, decodeSkillSourceIdentity,
  SKILL_RESOURCE_BYTES, SKILL_RESOURCE_COUNT, type DescriptorCapturedSkillSourceFileV1,
  type SkillSourceIdentityV1 } from '../kernel/skill.js';
import type { LocalPrincipalIdentityV1, WorkspaceIdentityV1 } from '../kernel/types.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { verifyRuntimeBundle } from '../policy/runtime-authority.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath,
  type HeldWorkspaceCursor, type HeldWorkspaceEntry, type HeldWorkspaceRoot } from './native-owner.js';
import { decodeLocalPrincipalIdentity } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { frozenSkillResourceKind, skillInstruction } from './skill-data.js';
import { bundledSkillMembers, bundledSkillRoots } from './bundled-skills.js';
import { skillResourceReferences, validateFrozenSkillResourceGraph } from '../skills/resources.js';

type Selected = { skillId: string; manifestRef: string; manifestDigest: string };
type UserRoot = Readonly<{ root: HeldWorkspaceRoot; prefix: 'skills' | '.agents/skills' }>;
type Candidate = { scope: 'workspace' | 'user'; root: HeldWorkspaceRoot; entry: HeldWorkspaceEntry; entries: HeldWorkspaceEntry[] };
function invalid(): never { throw new KernelStorageError('INVALID_REQUEST', 'selected skill source is unavailable, ambiguous or outside the fixed capture contract'); }
function equal(left: unknown, right: unknown): boolean { return canonicalSha256(left) === canonicalSha256(right); }

export async function captureInstalledSkills(input: {
  artifacts: ArtifactCatalog; requestedSkillIds: readonly string[];
  workspaceRoot: HeldWorkspaceRoot; workspaceIdentity: Extract<WorkspaceIdentityV1, { kind: 'live' }>; workspaceIdentityRef: string;
  userRoots: readonly UserRoot[]; actualUserHome: string; principal: LocalPrincipalIdentityV1; principalRef: string;
  bundle: RuntimeBundleManifest; bundleRef: string; signal?: AbortSignal;
}): Promise<{ skills: Selected[]; metadata: PublishedArtifact[] }> {
  const { artifacts, signal } = input, ids = [...input.requestedSkillIds];
  ids.forEach(canonicalSkillId); if (ids.length > 64 || new Set(ids).size !== ids.length) invalid();
  if (!ids.length) return { skills: [], metadata: [] };
  assertHeldWorkspaceRoot(input.workspaceRoot);
  if (!equal(input.workspaceRoot.identity, input.workspaceIdentity.rootIdentity) ||
      heldWorkspaceRootPath(input.workspaceRoot) !== input.workspaceIdentity.canonicalRootPath ||
      canonicalSha256(input.workspaceIdentity) !== input.workspaceIdentityRef) invalid();
  const principal = decodeLocalPrincipalIdentity(input.principal);
  if (canonicalSha256(principal) !== input.principalRef || principal.principalId !== input.workspaceIdentity.ownerPrincipalId ||
      String(principal.effectiveUid) !== String(input.workspaceRoot.identity.ownerUid) ||
      input.userRoots.length !== 2 || new Set(input.userRoots.map(value => value.prefix)).size !== 2 ||
      canonicalSha256(input.bundle) !== input.bundleRef) invalid();
  verifyRuntimeBundle(input.bundle, artifacts.releaseTrustRoots());
  for (const value of input.userRoots) {
    assertHeldWorkspaceRoot(value.root);
    if (heldWorkspaceRootPath(value.root) !== (value.prefix === 'skills' ? path.join(input.actualUserHome, '.cliq') : input.actualUserHome) ||
        String(value.root.identity.ownerUid) !== String(principal.effectiveUid)) invalid();
  }
  const resources: Array<{ close(): void }> = [], cursors: HeldWorkspaceCursor[] = [], heldEntries: HeldWorkspaceEntry[] = [];
  const roots = [input.workspaceRoot, ...input.userRoots.map(value => value.root)], metadata: PublishedArtifact[] = [];
  const candidates = new Map<string, Array<Candidate | { scope: 'bundled'; rootEntryId: string }>>();
  ids.forEach(id => candidates.set(id, []));
  let inventory = 0, failure: unknown;
  const recheck = () => {
    signal?.throwIfAborted(); roots.forEach(assertHeldWorkspaceRoot);
    cursors.forEach(cursor => cursor.assertComplete()); heldEntries.forEach(entry => entry.assertHeld());
  };
  const directory = (entry: HeldWorkspaceEntry, root: HeldWorkspaceRoot) => {
    if (entry.kind !== 'directory' || entry.identity.deviceId !== root.identity.deviceId ||
        String(entry.identity.ownerUid) !== String(principal.effectiveUid)) invalid();
  };
  async function level(cursor: HeldWorkspaceCursor, wanted: (entry: HeldWorkspaceEntry) => boolean): Promise<HeldWorkspaceEntry[]> {
    resources.push(cursor); cursors.push(cursor); const selected: HeldWorkspaceEntry[] = [];
    for (;;) {
      await setImmediate(); signal?.throwIfAborted(); const entry = cursor.next(); if (!entry) break;
      if (++inventory > 100000) { resources.push(entry); invalid(); }
      if (wanted(entry)) { resources.push(entry); heldEntries.push(entry); selected.push(entry); }
      else entry.close();
    }
    cursor.assertComplete(); return selected;
  }
  async function find(root: HeldWorkspaceRoot, relative: string): Promise<HeldWorkspaceEntry | undefined> {
    const parts = relative.split('/'); let cursor = root.openSkillSnapshot(), selected: HeldWorkspaceEntry | undefined;
    for (let index = 0; index < parts.length; index++) {
      const expected = parts.slice(0, index + 1).join('/'), values = await level(cursor, entry => entry.path === expected);
      if (!values.length) return undefined; if (values.length !== 1) invalid();
      selected = values[0]!; directory(selected, root);
      if (index + 1 < parts.length) cursor = selected.openDirectory();
    }
    return selected;
  }
  async function discover(root: HeldWorkspaceRoot, prefix: string, scope: 'workspace' | 'user') {
    const directoryEntry = await find(root, prefix); if (!directoryEntry) return;
    const selected = await level(directoryEntry.openDirectory(), entry => ids.some(id => entry.path === prefix + '/' + id));
    for (const entry of selected) {
      directory(entry, root);
      const entries = await level(entry.openDirectory(), () => true);
      // A same-named ordinary directory without SKILL.md is not a skill.
      // Discovery reads metadata only; selected bytes are read after the
      // complete cross-scope ambiguity check.
      if (!entries.some(file => file.path === entry.path + '/SKILL.md')) continue;
      candidates.get(entry.path.slice(prefix.length + 1))!.push({ scope, root, entry, entries });
    }
  }
  async function publishedRaw(bytes: Buffer): Promise<string> {
    const ref = sha256Bytes(bytes), artifact = await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-skill-source-file-v1');
    if (artifact.ref !== ref || artifact.byteLength !== bytes.length) invalid(); metadata.push(artifact); return ref;
  }
  async function publishSkill(sourceValue: SkillSourceIdentityV1, raw: ReadonlyMap<string, Buffer>): Promise<Selected> {
    const source = decodeSkillSourceIdentity(sourceValue), instruction = skillInstruction(source.skillId, raw.get('SKILL.md')!);
    validateFrozenSkillResourceGraph(raw, source.files.filter(file => file.canonicalRelativePath !== 'SKILL.md').map(file => file.canonicalRelativePath));
    const instructionRef = canonicalSha256(instruction), identityRef = canonicalSha256(source);
    const resources = source.files.filter(file => file.canonicalRelativePath !== 'SKILL.md').map(file => {
      const kind = frozenSkillResourceKind(file.canonicalRelativePath, raw.get(file.canonicalRelativePath)!,
        'fileDescriptor' in file && [448, 493].includes((file as DescriptorCapturedSkillSourceFileV1).fileDescriptor.mode));
      return { canonicalRelativePath: file.canonicalRelativePath, kind, contentRef: file.rawBytesRef, contentDigest: file.rawBytesDigest };
    });
    const core = { schemaVersion: 1 as const, format: 'cliq-skill-manifest-v1' as const, skillId: source.skillId, sourceScope: source.sourceScope,
      sourceIdentityRef: identityRef, sourceIdentityDigest: source.sourceIdentityDigest, instructionRef, instructionDigest: instruction.textDigest, resources };
    const manifest = decodeSkillManifest({ ...core, manifestDigest: canonicalSha256(core) });
    recheck();
    // These three complete inert objects have no intervening authority,
    // clock or SQL effect. The original CAS triple retains every file sync,
    // four namespace barriers, full hash reread and failure/close join.
    const [text, identity, artifact] = await artifacts.publishCanonicalTriple([
      { value: instruction, schemaKind: instruction.format }, { value: source, schemaKind: source.format },
      { value: manifest, schemaKind: manifest.format }
    ]);
    if (text.ref !== instructionRef || identity.ref !== identityRef || artifact.ref !== canonicalSha256(manifest) ||
        text.byteLength !== canonicalJsonBytes(instruction).length || identity.byteLength !== canonicalJsonBytes(source).length ||
        artifact.byteLength !== canonicalJsonBytes(manifest).length || [text, identity, artifact].some(value => value.mediaType !== 'application/json')) invalid();
    recheck();
    metadata.push(text, identity, artifact); return { skillId: manifest.skillId, manifestRef: artifact.ref, manifestDigest: manifest.manifestDigest };
  }
  async function capture(id: string, candidate: Candidate): Promise<Selected> {
    const { root, entry } = candidate;
    if (![448, 493].includes(entry.mode) || candidate.scope === 'user' && entry.mode !== 448) invalid();
    const raw = new Map<string, Buffer>(), files: DescriptorCapturedSkillSourceFileV1[] = [];
    const rootDescriptor = { ...(candidate.scope === 'workspace' ? { canonicalRootRelativePath: entry.path }
      : { canonicalAbsolutePath: path.join(heldWorkspaceRootPath(root), entry.path) }),
      deviceId: entry.identity.deviceId, fileId: entry.identity.fileId, ownerUid: Number(entry.identity.ownerUid), mode: entry.mode };
    // Enumerate metadata only along declared paths. An unrelated file or
    // directory is never opened or frozen merely because it shares a root.
    const directories = new Map<string, readonly HeldWorkspaceEntry[]>([['', candidate.entries]]);
    const locate = async (relative: string): Promise<HeldWorkspaceEntry> => {
      const parts = relative.split('/'); let parent = '';
      for (let index = 0; index < parts.length; index++) {
        const entries = directories.get(parent); if (!entries) invalid();
        const full = entry.path + '/' + parts.slice(0, index + 1).join('/');
        const matches = entries.filter(value => value.path === full); if (matches.length !== 1) invalid();
        const file = matches[0]!; if (index + 1 === parts.length) return file;
        directory(file, root); parent = parts.slice(0, index + 1).join('/');
        if (!directories.has(parent)) directories.set(parent, await level(file.openDirectory(), () => true));
      }
      return invalid();
    };
    let total = 0; const pending = ['SKILL.md'], scheduled = new Set(pending);
    while (pending.length) {
      await setImmediate(); signal?.throwIfAborted(); const relative = pending.shift()!, file = await locate(relative);
      if (file.kind !== 'file' || file.identity.deviceId !== root.identity.deviceId ||
          String(file.identity.ownerUid) !== String(principal.effectiveUid) || file.linkCount !== 1 ||
          ![384, 420, 448, 493].includes(file.mode) || !Number.isSafeInteger(file.byteCount) || file.byteCount < 0 ||
          (relative === 'SKILL.md' ? file.byteCount > 1048576 : (total += file.byteCount) > SKILL_RESOURCE_BYTES)) invalid();
      if (files.length >= SKILL_RESOURCE_COUNT + 1) invalid();
      const reader = file.openFile(); resources.push(reader); const chunks: Buffer[] = []; let size = 0;
      for (;;) { await setImmediate(); signal?.throwIfAborted(); const chunk = reader.readChunk(); if (chunk === null) break;
        size += chunk.length; if (size > file.byteCount) invalid(); chunks.push(chunk); }
      reader.assertHeld(); file.assertHeld(); const bytes = Buffer.concat(chunks); if (size !== file.byteCount) invalid();
      // The original file is completely verified and really closed before
      // publication; its held entry/parent metadata remains for the final cut.
      reader.close(); resources.pop(); file.assertHeld(); raw.set(relative, bytes);
      const ref = await publishedRaw(bytes), descriptor = { deviceId: file.identity.deviceId, fileId: file.identity.fileId,
        ownerUid: Number(file.identity.ownerUid), mode: file.mode as 384 | 420 | 448 | 493, linkCount: 1 as const };
      const fields = { canonicalRelativePath: relative, rawBytesRef: ref, rawBytesDigest: ref, rawByteCount: bytes.length, fileDescriptor: descriptor };
      const digest = canonicalSha256({ sourceScope: candidate.scope, ...(candidate.scope === 'workspace'
        ? { workspaceIdentityDigest: input.workspaceIdentity.identityDigest } : { principalIdentityDigest: principal.identityDigest }), rootDescriptor, ...fields });
      files.push({ ...fields, sourceEntryDigest: digest });
      for (const dependency of skillResourceReferences(relative, bytes)) if (!scheduled.has(dependency)) {
        scheduled.add(dependency); if (scheduled.size > SKILL_RESOURCE_COUNT + 1) invalid(); pending.push(dependency);
      }
    }
    files.sort((left, right) => Buffer.compare(Buffer.from(left.canonicalRelativePath), Buffer.from(right.canonicalRelativePath)));
    const core = { schemaVersion: 1 as const, format: 'cliq-skill-source-identity-v1' as const, skillId: id, sourceScope: candidate.scope,
      ...(candidate.scope === 'workspace' ? { workspaceIdentityRef: input.workspaceIdentityRef, workspaceIdentityDigest: input.workspaceIdentity.identityDigest }
        : { ownerPrincipalId: principal.principalId, principalIdentityRef: input.principalRef, principalIdentityDigest: principal.identityDigest }), rootDescriptor, files };
    return publishSkill({ ...core, sourceIdentityDigest: canonicalSha256(core) } as SkillSourceIdentityV1, raw);
  }
  try {
    await discover(input.workspaceRoot, '.cliq/skills', 'workspace'); await discover(input.workspaceRoot, '.agents/skills', 'workspace');
    for (const value of input.userRoots) await discover(value.root, value.prefix, 'user');
    for (const root of bundledSkillRoots(input.bundle)) {
      const entry = input.bundle.entries.find(entry => entry.entryId === root.rootEntryId)!;
      const closure = decodeBundledSkillClosure(await artifacts.readCanonical(entry.digest));
      if (canonicalSha256(closure) !== entry.digest || canonicalJsonBytes(closure).length !== entry.byteCount || entry.executable) invalid();
      bundledSkillMembers(input.bundle, root, closure);
      if (!ids.includes(closure.skillId)) continue;
      candidates.get(closure.skillId)!.push({ scope: 'bundled', rootEntryId: entry.entryId });
    }
    const selected: Selected[] = [];
    for (const id of ids) {
      const values = candidates.get(id)!; if (values.length !== 1) invalid(); const value = values[0]!;
      if (value.scope !== 'bundled') { selected.push(await capture(id, value)); continue; }
      const entry = input.bundle.entries.find(entry => entry.entryId === value.rootEntryId)!;
      const closure = decodeBundledSkillClosure(await artifacts.readCanonical(entry.digest));
      const raw = new Map<string, Buffer>();
      for (const file of closure.files) {
        const bytes = await artifacts.readBytes(file.rawBytesRef);
        if (bytes.length !== file.rawByteCount || sha256Bytes(bytes) !== file.rawBytesDigest ||
            !input.bundle.entries.some(member => member.role === 'bundle_object' && !member.executable && member.digest === file.rawBytesRef && member.byteCount === file.rawByteCount)) invalid();
        raw.set(file.canonicalRelativePath, bytes);
        metadata.push(await artifacts.describe(file.rawBytesRef, 'application/octet-stream', 'cliq-skill-source-file-v1'));
      }
      const files = closure.files.map(file => ({ ...file, sourceEntryDigest: canonicalSha256({ sourceScope: 'bundled', bundledClosureDigest: closure.closureDigest, ...file }) }));
      const core = { schemaVersion: 1 as const, format: 'cliq-skill-source-identity-v1' as const, skillId: id, sourceScope: 'bundled' as const,
        runtimeBundleRef: input.bundleRef, runtimeBundleManifestDigest: input.bundle.manifestDigest, bundleEntryId: entry.entryId,
        bundleEntryVersion: entry.version, bundledClosureRef: entry.digest, bundledClosureDigest: closure.closureDigest, files };
      selected.push(await publishSkill({ ...core, sourceIdentityDigest: canonicalSha256(core) }, raw));
    }
    recheck(); return { skills: selected, metadata };
  } catch (error) { failure = error; throw error; }
  finally {
    const errors: unknown[] = [];
    for (const resource of resources.reverse()) try { resource.close(); } catch (error) { errors.push(error); }
    if (errors.length) throw new ResourceRetirementError('skill source descriptors did not retire', new AggregateError(failure === undefined ? errors : [failure, ...errors]));
  }
}
