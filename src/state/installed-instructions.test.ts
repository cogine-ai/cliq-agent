import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import type { WorkspaceEntryManifest } from '../kernel/types.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { captureWorkspaceEntries } from '../workspace/source-capture.js';
import { loadInstructionText } from './agent-context.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { captureInstalledWorkspaceInstructions } from './installed-run.js';
import { loadNativeStateOwner, type HeldWorkspaceRoot } from './native-owner.js';
import { captureLiveWorkspaceIdentity } from './workspace-identity.js';

async function instructionDurabilityFixture(t: TestContext) {
  const directory = await mkdtemp(path.join(process.cwd(), '.cliq-instruction-durability-'));
  const workspace = path.join(directory, 'workspace'), objects = path.join(directory, 'objects');
  await mkdir(workspace, { mode: 0o700 }); await mkdir(objects, { mode: 0o700 });
  await mkdir(path.join(workspace, 'vendor'), { mode: 0o700 });
  await writeFile(path.join(workspace, 'AGENTS.md'), 'Root guidance.\n', { mode: 0o644 });
  await writeFile(path.join(workspace, 'vendor', 'AGENTS.md'), 'Vendor guidance.\n', { mode: 0o644 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(objects));
  const { identity } = await captureLiveWorkspaceIdentity({ workspacePath: workspace, ownerPrincipalId: 'instruction-durability-data' });
  const identityRef = (await artifacts.publishCanonical(identity, identity.format)).ref;
  const root = (await loadNativeStateOwner()).openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); await rm(directory, { recursive: true, force: true }); });
  return { workspace, objects, artifacts, identity, identityRef, root };
}

test('instruction capture retains every file sync and complete graph with twelve directory barriers for two scopes', async t => {
  const { objects, artifacts, identity, identityRef, root } = await instructionDurabilityFixture(t);
  const open = fs.open.bind(fs), active = new Set<object>(); let rootSyncs = 0, fileSyncs = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
    const handle = await open(...args); active.add(handle);
    const sync = handle.sync.bind(handle), close = handle.close.bind(handle);
    t.mock.method(handle, 'sync', async () => { await sync(); if (args[0] === objects) rootSyncs++; else fileSyncs++; });
    t.mock.method(handle, 'close', async () => { await close(); assert(active.delete(handle)); });
    return handle;
  });
  const captured = await captureInstalledWorkspaceInstructions(root, artifacts, identity, identityRef);
  assert.equal(fileSyncs, 6, 'all original raw, rendered, source and manifest files still sync');
  assert.equal(rootSyncs, 12, 'two independent raw publications and one fully joined four-object closure');
  assert.equal(active.size, 0);
  const source = await artifacts.readCanonical<{ entries: Array<{ rawBytesRef: string }> }>(captured.value.instructionSourceRef);
  assert.deepEqual(await Promise.all(source.entries.map(entry => artifacts.readBytes(entry.rawBytesRef).then(bytes => bytes.toString()))),
    ['Root guidance.\n', 'Vendor guidance.\n']);
  assert.deepEqual(await Promise.all(captured.value.entries.map(entry => artifacts.readCanonical<ModelTextV1>(entry.contentRef).then(value => value.utf8))),
    ['Root guidance.\n', 'Vendor guidance.\n']);
  assert.equal(active.size, 0); root.assertHeld();
});

for (const fault of ['cancel', 'changed_instruction'] as const)
  test(`instruction capture joins the original last sync and refuses ${fault} before returning a graph`, async t => {
    const { workspace, objects, artifacts, identity, identityRef, root } = await instructionDurabilityFixture(t);
    const open = fs.open.bind(fs), active = new Set<object>(), cancellation = new AbortController();
    const reason = new Error('the original instruction capture was cancelled');
    let enter!: () => void, release!: () => void, fileSyncs = 0, settled = false;
    const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const handle = await open(...args); active.add(handle);
      const sync = handle.sync.bind(handle), close = handle.close.bind(handle);
      t.mock.method(handle, 'sync', async () => {
        await sync();
        if (args[0] !== objects && ++fileSyncs === 6) { enter(); await gate; }
      });
      t.mock.method(handle, 'close', async () => { await close(); assert(active.delete(handle)); });
      return handle;
    });
    const pending = captureInstalledWorkspaceInstructions(root, artifacts, identity, identityRef, cancellation.signal);
    void pending.finally(() => { settled = true; }).catch(() => {});
    try {
      await Promise.race([entered, pending.then(() => { throw new Error('the original last sync was bypassed'); })]);
      if (fault === 'cancel') cancellation.abort(reason);
      else await writeFile(path.join(workspace, 'AGENTS.md'), 'Changed guidance.\n');
      assert.equal(settled, false); assert(active.size > 0);
      release();
      await assert.rejects(pending, error => fault === 'cancel' ? error === reason
        : error instanceof Error && /changed|identity/u.test(error.message));
      assert.equal(fileSyncs, 6); assert.equal(active.size, 0); root.assertHeld();
    } finally { release(); await Promise.allSettled([pending]); }
  });

// Approved descriptor/CAS seam only: no Session, Run, permission or execution
// authority is constructed. The real installed journey remains independent.
for (const metadata of ['.git', '.GIT']) {
  test(`installed instructions skip ${metadata} while retaining source-excluded ordinary scopes`, async t => {
    const directory = await mkdtemp(path.join(process.cwd(), '.cliq-instruction-capture-'));
    let root: HeldWorkspaceRoot | undefined;
    t.after(async () => { root?.close(); await rm(directory, { recursive: true, force: true }); });
    const workspace = path.join(directory, 'workspace'), objects = path.join(directory, 'objects');
    await mkdir(workspace, { mode: 0o700 }); await mkdir(objects, { mode: 0o700 });
    await mkdir(path.join(workspace, 'vendor'), { mode: 0o700 });
    await mkdir(path.join(workspace, 'vendor', metadata), { mode: 0o700 });
    await writeFile(path.join(workspace, 'example.txt'), 'ordinary source\n', { mode: 0o644 });
    const instructions = 'Ordinary vendor guidance must remain captured.\n';
    await writeFile(path.join(workspace, 'vendor', 'AGENTS.md'), instructions, { mode: 0o644 });
    // Invalid UTF-8 in Git metadata must not become instruction input at all.
    const invalid = Buffer.from([0xff]);
    const metadataPath = path.join(workspace, 'vendor', metadata, 'AGENTS.md');
    await writeFile(metadataPath, invalid, { mode: 0o644 });
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(objects));
    const { identity } = await captureLiveWorkspaceIdentity({ workspacePath: workspace, ownerPrincipalId: 'instruction-data-fixture' });
    const identityRef = (await artifacts.publishCanonical(identity, identity.format)).ref;
    root = (await loadNativeStateOwner()).openWorkspaceRoot(workspace);
    // The actual source capture selects no vendor bytes; instructions have
    // their own all-scopes capture, not the source projection's allowlist.
    const source = await captureWorkspaceEntries(root, artifacts,
      { selectedPaths: ['example.txt'], maxEntries: 2, maxBytes: 64 });
    assert.deepEqual((await artifacts.readCanonical<WorkspaceEntryManifest>(source.ref)).entries.map(entry => entry.path), ['example.txt']);
    await assert.rejects(captureWorkspaceEntries(root, artifacts,
      { selectedPaths: ['vendor/AGENTS.md'], maxEntries: 4, maxBytes: 64 }), /nested Git metadata/u,
    'ordinary source capture must keep rejecting a selected nested repository');
    const captured = await captureInstalledWorkspaceInstructions(root, artifacts, identity, identityRef);
    assert.deepEqual(captured.value.entries.map(entry => entry.canonicalRootRelativePath), ['vendor/AGENTS.md']);
    const content = await artifacts.readCanonical<ModelTextV1>(captured.value.entries[0]!.contentRef);
    assert.equal(content.utf8, instructions);
    const systemBase = { schemaVersion: 1 as const, format: 'cliq-model-text-v1' as const,
      utf8: 'Fixed system instruction.', byteCount: Buffer.byteLength('Fixed system instruction.') };
    const system = { ...systemBase, textDigest: canonicalSha256(systemBase) };
    const systemRef = (await artifacts.publishCanonical(system, system.format)).ref;
    const rendered = await loadInstructionText(artifacts, { instructions: {
      systemPromptRef: systemRef, systemPromptDigest: system.textDigest,
      workspaceInstructionsRef: captured.ref, workspaceInstructionsDigest: captured.value.manifestDigest, skills: [] } });
    const instructionPrompt = canonicalJsonBytes({ format: 'cliq-workspace-instruction-prompt-v1', entries: [
      { order: 0, canonicalRootRelativePath: 'vendor/AGENTS.md', appliesToSubtree: true, instructionUtf8: instructions }
    ] }).toString('utf8');
    assert.equal(rendered, `${system.utf8}\n\n${instructionPrompt}`,
      'rendering must preserve exact instruction bytes, including their JSON-escaped newline and subtree scope');
    assert.deepEqual(await readFile(metadataPath), invalid);
    root.assertHeld();
  });
}

test('fixed native instruction cursor cannot read ordinary file bytes or symlink targets', async t => {
  const directory = await mkdtemp(path.join(process.cwd(), '.cliq-instruction-cursor-'));
  const resources: Array<{ close(): void }> = [];
  t.after(async () => {
    for (const resource of resources.reverse()) resource.close();
    await rm(directory, { recursive: true, force: true });
  });
  await writeFile(path.join(directory, 'AGENTS.md'), 'Exact ordinary instructions.\n', { mode: 0o644 });
  await writeFile(path.join(directory, 'ordinary'), 'not instruction bytes', { mode: 0o644 });
  await symlink('ordinary', path.join(directory, 'alias'));
  const root = (await loadNativeStateOwner()).openWorkspaceRoot(directory); resources.push(root);
  const ordinaryCursor = root.openSnapshot(); resources.push(ordinaryCursor);
  let ordinaryOpenFile: (() => unknown) | undefined;
  let ordinaryReadSymlink: (() => unknown) | undefined;
  for (;;) {
    const entry = ordinaryCursor.next();
    if (!entry) break;
    resources.push(entry);
    if (entry.path === 'ordinary') ordinaryOpenFile = entry.openFile;
    if (entry.path === 'alias') ordinaryReadSymlink = entry.readSymlink;
  }
  ordinaryCursor.assertComplete();
  assert(ordinaryOpenFile && ordinaryReadSymlink);
  const openInstructions = Reflect.get(root, 'openInstructionSnapshot');
  assert.equal(typeof openInstructions, 'function', 'instructions require their own fixed native cursor, not a relaxed source cursor');
  const cursor = Reflect.apply(openInstructions, root, []) as ReturnType<HeldWorkspaceRoot['openSnapshot']>;
  resources.push(cursor);
  const seen: string[] = [];
  for (;;) {
    const entry = cursor.next();
    if (!entry) break;
    resources.push(entry); seen.push(entry.path);
    if (entry.path === 'ordinary') {
      assert.throws(() => entry.openFile(), /instruction/u);
      assert.throws(() => Reflect.apply(ordinaryOpenFile, entry, []), /instruction/u);
    } else if (entry.path === 'alias') {
      assert.throws(() => entry.readSymlink(), /instruction/u);
      assert.throws(() => Reflect.apply(ordinaryReadSymlink, entry, []), /instruction/u);
    }
    else {
      assert.equal(entry.path, 'AGENTS.md');
      const reader = entry.openFile(); resources.push(reader);
      assert.equal(reader.readChunk()!.toString('utf8'), 'Exact ordinary instructions.\n');
      assert.equal(reader.readChunk(), null); reader.assertHeld();
    }
  }
  cursor.assertComplete();
  assert.deepEqual(seen.sort(), ['AGENTS.md', 'alias', 'ordinary']);
  root.assertHeld();
});
