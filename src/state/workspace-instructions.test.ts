import assert from 'node:assert/strict';
import { mkdir, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { KERNEL_CAS_DIRECTORY } from '../config.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { WorkspaceInstructionManifestV1, WorkspaceInstructionSourceManifestV1, WorkspaceIdentityV1 } from '../kernel/types.js';
import { reseal } from '../model/testing/fixtures.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { loadInstructionText } from './agent-context.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { admissionKey, disposeFixture, makePrivateDir, publishEmptySourceGraph, uuidv7 } from './testing/fixtures.js';
import { openStateStore, publishInProcessChannel, type StateStore } from './store.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { readWorkspaceInstructionClosure, type WorkspaceInstructionBinding } from './workspace-instructions.js';

type Fixture = { store: StateStore; stateRoot: string; workspacePath: string; binding: WorkspaceInstructionBinding };
type Pair = { source: WorkspaceInstructionSourceManifestV1; manifest: WorkspaceInstructionManifestV1; manifestRef: string };
const byteCompare = (left: string, right: string) => Buffer.compare(Buffer.from(left), Buffer.from(right));

async function fixture(run: (value: Fixture) => Promise<void>) {
  const stateRoot = await makePrivateDir('.cliq-instructions-state-');
  const workspacePath = await makePrivateDir('.cliq-instructions-workspace-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'instruction-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const session = await store.createSession({ principalId, requestId: uuidv7(),
      admissionKey: admissionKey('instruction-session'), workspacePath, ...channel });
    const workspaceIdentity = await store.artifacts.readCanonical<WorkspaceIdentityV1>(session.session.workspaceIdentityRef);
    await run({ store, stateRoot, workspacePath, binding: {
      workspaceIdentityRef: session.session.workspaceIdentityRef, workspaceIdentity,
      admittedAt: '2100-01-01T00:00:00.000Z'
    } });
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspacePath, { recursive: true, force: true });
  }
}

async function publishPair(value: Fixture, files: Record<string, string | Buffer> = {}): Promise<Pair> {
  if (value.binding.workspaceIdentity.kind !== 'live') throw new Error('test requires a live workspace');
  const source: WorkspaceInstructionSourceManifestV1 = { schemaVersion: 1,
    format: 'cliq-workspace-instruction-source-v1', workspaceIdentityRef: value.binding.workspaceIdentityRef,
    workspaceIdentityDigest: value.binding.workspaceIdentity.identityDigest, entries: [],
    capturedAt: sampleCanonicalNow(), sourceDigest: '' };
  const contents = new Map<string, { contentRef: string; contentDigest: string }>();
  // These are explicitly offline descriptor records. The production native
  // declarative-context capture is a separate integration gate.
  for (const [index, [name, input]] of Object.entries(files).sort(([a], [b]) => byteCompare(a, b)).entries()) {
    const raw = Buffer.from(input);
    const bytes = await value.store.artifacts.publishBytes(raw, 'application/octet-stream', 'instruction-test-bytes');
    const text: ModelTextV1 = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8: raw.toString('utf8'),
      byteCount: raw.byteLength, textDigest: '' };
    text.textDigest = digestOmitting(text, 'textDigest');
    const content = await value.store.artifacts.publishCanonical(text, text.format);
    contents.set(name, { contentRef: content.ref, contentDigest: text.textDigest });
    const entry: WorkspaceInstructionSourceManifestV1['entries'][number] = {
      canonicalRootRelativePath: name, directoryDepth: name.split('/').length - 1,
      fileDescriptor: { deviceId: value.binding.workspaceIdentity.rootIdentity.deviceId, fileId: String(index + 1),
        ownerUid: value.binding.workspaceIdentity.rootIdentity.ownerUid,
        mode: 0o644, linkCount: 1 }, rawBytesRef: bytes.ref, rawBytesDigest: bytes.ref,
      rawByteCount: raw.byteLength, sourceEntryDigest: ''
    };
    entry.sourceEntryDigest = digestOmitting(entry, 'sourceEntryDigest');
    source.entries.push(entry);
  }
  source.sourceDigest = digestOmitting(source, 'sourceDigest');
  const root = await value.store.artifacts.publishCanonical(source, source.format);
  const manifest: WorkspaceInstructionManifestV1 = { schemaVersion: 1, format: 'cliq-workspace-instructions-v1',
    workspaceIdentityDigest: source.workspaceIdentityDigest, instructionSourceRef: root.ref,
    instructionSourceDigest: source.sourceDigest, rendering: 'cliq-all-scopes-labeled-instructions-v1',
    entries: [...source.entries].sort((a, b) => a.directoryDepth - b.directoryDepth ||
      byteCompare(a.canonicalRootRelativePath, b.canonicalRootRelativePath)).map((entry, order) => ({
      order, canonicalRootRelativePath: entry.canonicalRootRelativePath, directoryDepth: entry.directoryDepth,
      appliesToSubtree: true, instructionSourceEntryDigest: entry.sourceEntryDigest, ...contents.get(entry.canonicalRootRelativePath)!
    })), manifestDigest: '' };
  manifest.manifestDigest = digestOmitting(manifest, 'manifestDigest');
  return { source, manifest, manifestRef: (await value.store.artifacts.publishCanonical(manifest, manifest.format)).ref };
}

async function rewrite(value: Fixture, pair: Pair,
  sourceEdit?: (source: WorkspaceInstructionSourceManifestV1) => void,
  manifestEdit?: (manifest: WorkspaceInstructionManifestV1) => void): Promise<Pair> {
  const source = structuredClone(pair.source);
  const manifest = structuredClone(pair.manifest);
  sourceEdit?.(source);
  for (const entry of source.entries) entry.sourceEntryDigest = digestOmitting(entry, 'sourceEntryDigest');
  source.sourceDigest = digestOmitting(source, 'sourceDigest');
  const root = await value.store.artifacts.publishCanonical(source, source.format);
  manifest.instructionSourceRef = root.ref;
  manifest.instructionSourceDigest = source.sourceDigest;
  for (const entry of manifest.entries) {
    const samePath = source.entries.find((candidate) => candidate.canonicalRootRelativePath === entry.canonicalRootRelativePath);
    if (samePath) entry.instructionSourceEntryDigest = samePath.sourceEntryDigest;
  }
  manifestEdit?.(manifest);
  manifest.manifestDigest = digestOmitting(manifest, 'manifestDigest');
  return { source, manifest, manifestRef: (await value.store.artifacts.publishCanonical(manifest, manifest.format)).ref };
}

const load = (value: Fixture, pair: Pair, binding = value.binding) => readWorkspaceInstructionClosure(value.store.artifacts,
  { manifestRef: pair.manifestRef, manifestDigest: pair.manifest.manifestDigest }, binding);

test('retained workspace instructions preserve every scope in root-to-deep order and never reread live files', async () => fixture(async (value) => {
  const pair = await publishPair(value, { 'a/deep/AGENTS.md': 'Deep instructions.\n', 'AGENTS.md': 'Root instructions.\n',
    'z/AGENTS.md': 'Z instructions.\n', 'a/AGENTS.md': '' });
  assert.deepEqual(pair.source.entries.map((entry) => entry.canonicalRootRelativePath),
    ['AGENTS.md', 'a/AGENTS.md', 'a/deep/AGENTS.md', 'z/AGENTS.md']);
  const loaded = await load(value, pair);
  assert.deepEqual(loaded.entries.map((entry) => [entry.order, entry.canonicalRootRelativePath, entry.instructionUtf8]),
    [[0, 'AGENTS.md', 'Root instructions.\n'], [1, 'a/AGENTS.md', ''], [2, 'z/AGENTS.md', 'Z instructions.\n'],
      [3, 'a/deep/AGENTS.md', 'Deep instructions.\n']]);
  assert.equal(Object.isFrozen(loaded.source.entries[0]!.fileDescriptor), true);
  assert.equal(Object.isFrozen(loaded.entries[0]), true);
  await writeFile(path.join(value.workspacePath, 'AGENTS.md'), 'changed live guidance');
  await mkdir(path.join(value.workspacePath, 'new'));
  await writeFile(path.join(value.workspacePath, 'new', 'AGENTS.md'), 'new live guidance');
  assert.deepEqual((await load(value, pair)).entries, loaded.entries);
}));

test('an empty instruction manifest still requires its exact empty source and Session identity', async () => fixture(async (value) => {
  const pair = await publishPair(value);
  assert.deepEqual((await load(value, pair)).entries, []);
  await assert.rejects(load(value, pair, { ...value.binding, workspaceIdentityRef: sha256Bytes(Buffer.from('foreign Session')) }));
  const wrongSource = await rewrite(value, pair, (source) => { source.workspaceIdentityRef = sha256Bytes(Buffer.from('foreign Session')); });
  await assert.rejects(load(value, wrongSource));
}));

test('fully rehashed instruction substitutions cannot widen scopes or replace source history', async () => fixture(async (value) => {
  const pair = await publishPair(value, { 'AGENTS.md': 'Root.\n', 'child/AGENTS.md': 'Child.\n' });
  const sourceCases: Array<(source: WorkspaceInstructionSourceManifestV1) => void> = [
    (source) => { source.entries.reverse(); },
    (source) => { source.entries.pop(); },
    (source) => { source.entries[1]!.canonicalRootRelativePath = 'AGENTS.md'; },
    (source) => { source.entries[1]!.canonicalRootRelativePath = '../AGENTS.md'; },
    (source) => { source.entries[1]!.canonicalRootRelativePath = 'child/agents.md'; },
    (source) => { source.entries[1]!.directoryDepth = 0; },
    (source) => { source.entries[0]!.fileDescriptor.ownerUid += 1; },
    (source) => { source.entries[0]!.fileDescriptor.deviceId = String(BigInt(source.entries[0]!.fileDescriptor.deviceId) + 1n); },
    (source) => { Object.assign(source.entries[0]!.fileDescriptor, { mode: 0o755 }); },
    (source) => { Object.assign(source.entries[0]!.fileDescriptor, { linkCount: 2 }); },
    (source) => { source.entries[0]!.fileDescriptor.fileId = '018'; },
    (source) => { source.entries[0]!.fileDescriptor.deviceId = '18446744073709551616'; },
    (source) => { source.entries[0]!.rawByteCount += 1; },
    (source) => { source.entries[0]!.rawBytesDigest = sha256Bytes(Buffer.from('different digest')); },
    (source) => { source.capturedAt = '2100-01-01T00:00:00.001Z'; },
    (source) => { Object.assign(source.entries[0]!, { pathFallback: '/tmp/AGENTS.md' }); }
  ];
  for (const [index, edit] of sourceCases.entries()) await assert.rejects(load(value, await rewrite(value, pair, edit)),
    `source mutation ${index} must fail even after full graph rehash`);
  const manifestCases: Array<(manifest: WorkspaceInstructionManifestV1) => void> = [
    (manifest) => { manifest.entries.reverse(); manifest.entries.forEach((entry, index) => { entry.order = index; }); },
    (manifest) => { manifest.entries.pop(); },
    (manifest) => { manifest.entries[0]!.order = 1; },
    (manifest) => { Object.assign(manifest.entries[1]!, { appliesToSubtree: false }); },
    (manifest) => { manifest.entries[1]!.directoryDepth = 3; },
    (manifest) => { manifest.entries[0]!.instructionSourceEntryDigest = manifest.entries[1]!.instructionSourceEntryDigest; },
    (manifest) => { manifest.entries[0]!.contentRef = manifest.entries[1]!.contentRef;
      manifest.entries[0]!.contentDigest = manifest.entries[1]!.contentDigest; },
    (manifest) => { Object.assign(manifest, { rendering: 'choose-applicable-instructions' }); },
    (manifest) => { manifest.workspaceIdentityDigest = sha256Bytes(Buffer.from('different workspace')); },
    (manifest) => { Object.assign(manifest, { ambientInstructionPath: '/tmp/AGENTS.md' }); }
  ];
  for (const [index, edit] of manifestCases.entries()) await assert.rejects(load(value, await rewrite(value, pair, undefined, edit)),
    `manifest mutation ${index} must fail even after full graph rehash`);
}));

test('invalid raw instruction text is rejected without normalization or repair', async () => fixture(async (value) => {
  for (const raw of [Buffer.from([0xff]), Buffer.from('line\r\n'), Buffer.from('e\u0301'), Buffer.from('text\0')]) {
    await assert.rejects(load(value, await publishPair(value, { 'AGENTS.md': raw })));
  }
}));

test('instruction count and total raw bytes are hard limits without truncation', async () => fixture(async (value) => {
  await assert.rejects(load(value, await publishPair(value,
    Object.fromEntries(Array.from({ length: 65 }, (_, index) => [`d${index}/AGENTS.md`, ''])))));
  const atLimit = await publishPair(value, { 'AGENTS.md': Buffer.alloc(1_048_576, 0x61) });
  assert.equal((await load(value, atLimit)).entries[0]!.instructionUtf8.length, 1_048_576);
  await assert.rejects(load(value, await publishPair(value,
    { 'AGENTS.md': Buffer.alloc(524_289, 0x61), 'child/AGENTS.md': Buffer.alloc(524_288, 0x62) })));
}));

test('oversized retained byte substitution fails before allocating raw or ModelText bytes', async () => fixture(async (value) => {
  const pair = await publishPair(value, { 'AGENTS.md': 'short' });
  const large = await value.store.artifacts.publishBytes(Buffer.alloc(2_097_152), 'application/octet-stream', 'instruction-test-bytes');
  const changed = await rewrite(value, pair, (source) => {
    source.entries[0]!.rawBytesRef = large.ref; source.entries[0]!.rawBytesDigest = large.ref;
  });
  const reads: string[] = [];
  const original = value.store.artifacts.readBytes.bind(value.store.artifacts);
  value.store.artifacts.readBytes = async (ref) => { reads.push(ref); return original(ref); };
  await assert.rejects(load(value, changed));
  assert.equal(reads.includes(large.ref), false);
}));

test('a missing transitive instruction raw object fails closed after owner restart', async () => {
  const value = await createAgentFixture('instruction-recovery');
  try {
    const run = value.store.getRun(value.runId);
    const session = value.store.getSession(run.sessionId);
    const workspaceIdentity = await value.store.artifacts.readCanonical<WorkspaceIdentityV1>(session.workspaceIdentityRef);
    if (workspaceIdentity.kind !== 'live') throw new Error('test requires a live workspace');
    const source = await publishEmptySourceGraph(value.store, workspaceIdentity.identityDigest);
    const pair = await publishPair({ store: value.store, stateRoot: value.stateRoot, workspacePath: '',
      binding: { workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentity, admittedAt: '2100-01-01T00:00:00.000Z' } },
    { 'AGENTS.md': 'Retained instructions.\n' });
    const binding: WorkspaceInstructionBinding = { workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentity,
      admittedAt: '2100-01-01T00:00:00.000Z' };
    const bad = await rewrite({ store: value.store, stateRoot: value.stateRoot, workspacePath: '', binding },
      pair, undefined, (manifest) => { manifest.entries[0]!.directoryDepth = 2; });
    const invalidAssembly = structuredClone(value.authority.assembly);
    invalidAssembly.instructions.workspaceInstructionsRef = bad.manifestRef;
    invalidAssembly.instructions.workspaceInstructionsDigest = bad.manifest.manifestDigest;
    reseal({ ...value.authority, assembly: invalidAssembly });
    const invalid = await value.store.artifacts.publishCanonical(invalidAssembly, invalidAssembly.format);
    const request = { principalId: workspaceIdentity.ownerPrincipalId,
      requestId: uuidv7(), admissionKey: admissionKey('instruction-second-run'), sessionId: session.id,
      expectedContextRevision: session.contextRevision, workspacePath: workspaceIdentity.canonicalRootPath,
      objective: 'retain declarative context', allowUnverified: true, ...source,
      credentialGrantRefs: value.authority.runSpecCredentialGrantRefs,
      ...await publishInProcessChannel(value.store, workspaceIdentity.ownerPrincipalId) };
    await assert.rejects(value.store.admitRun({ ...request, assemblyRef: invalid.ref }),
      (error: unknown) => error instanceof Error && 'code' in error && error.code === 'ARTIFACT_MISMATCH');
    const assembly = structuredClone(value.authority.assembly);
    assembly.instructions.workspaceInstructionsRef = pair.manifestRef;
    assembly.instructions.workspaceInstructionsDigest = pair.manifest.manifestDigest;
    reseal({ ...value.authority, assembly });
    const published = await value.store.artifacts.publishCanonical(assembly, assembly.format);
    // Reusing the request/admission ids with the repaired graph proves the
    // invalid closure committed no control request or Run ownership row.
    const admitted = await value.store.admitRun({ ...request, assemblyRef: published.ref });
    const system = await loadInstructionText(value.store.artifacts, assembly, {
      workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentity, admittedAt: admitted.run.createdAt
    });
    assert.equal(system, 'Use tools carefully.\n\n' + JSON.stringify({ entries: [{ appliesToSubtree: true,
      canonicalRootRelativePath: 'AGENTS.md', instructionUtf8: 'Retained instructions.\n', order: 0 }],
    format: 'cliq-workspace-instruction-prompt-v1' }));
    assert.equal((await value.store.readRecoveryClosure(admitted.run.id)).run.id, admitted.run.id);
    const retainedPath = path.join(value.stateRoot, KERNEL_CAS_DIRECTORY, pair.source.entries[0]!.rawBytesRef);
    assert.equal(sha256Bytes(await readFile(retainedPath)), pair.source.entries[0]!.rawBytesRef);
    await value.store.close();
    await unlink(retainedPath);
    value.store = await openStateStore(value.stateRoot);
    await assert.rejects(value.store.readRecoveryClosure(admitted.run.id), /workspace instruction closure|not readable|absent|missing/u);
  } finally { await disposeFixture(value); }
});
