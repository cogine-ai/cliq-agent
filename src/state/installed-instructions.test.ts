import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
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
