import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { chmod, link, mkdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { LocalControlChannelIdentityV1, LocalPrincipalIdentityV1, WorkspaceIdentityV1 } from '../kernel/types.js';
import { captureInstalledSkills } from './skill-source.js';
import { frozenSkillResourceRange, readFrozenSkillData } from './skill-data.js';
import { loadNativeStateOwner } from './native-owner.js';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';
import { captureInstalledWorkspaceInstructions } from './installed-run.js';
import { loadInstructionText } from './agent-context.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { ResourceRetirementError } from './errors.js';

async function fixture(t: TestContext) {
  const owned = await createQueuedFixture('frozen-skill-data');
  const { store } = owned, session = store.getSession(store.getRun(owned.runId).sessionId);
  const workspace = await store.artifacts.readCanonical<Extract<WorkspaceIdentityV1, { kind: 'live' }>>(session.workspaceIdentityRef);
  const channel = await store.artifacts.readCanonical<LocalControlChannelIdentityV1>(owned.channelIdentityRef);
  const principal = await store.artifacts.readCanonical<LocalPrincipalIdentityV1>(channel.principalIdentityRef);
  const home = path.join(owned.stateRoot, 'component-home');
  for (const directory of ['.cliq', '.agents/skills']) await mkdir(path.join(home, directory), { recursive: true, mode: 0o700 });
  const create = async (scope: 'workspace' | 'user', id: string, file = 'data.txt', bytes = Buffer.from('A retained resource.\n')) => {
    const directory = path.join(scope === 'workspace' ? owned.workspace : home, scope === 'workspace' ? '.cliq/skills' : '.agents/skills', id);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await mkdir(path.dirname(path.join(directory, file)), { recursive: true, mode: 0o700 });
    await writeFile(path.join(directory, 'SKILL.md'), `---\nname: ${id}\ndescription: Frozen test instruction.\n---\nUse the [${id} resource](${file}).\n`, { mode: 0o644 });
    await writeFile(path.join(directory, file), bytes, { mode: file.endsWith('.sh') ? 0o755 : 0o644 });
    return directory;
  };
  const native = await loadNativeStateOwner(), roots = [native.openWorkspaceRoot(owned.workspace), native.openWorkspaceRoot(path.join(home, '.cliq')), native.openWorkspaceRoot(home)];
  t.after(async () => { for (const root of roots.reverse()) root.close(); await disposeFixture(owned); });
  const capture = (requestedSkillIds: readonly string[], signal?: AbortSignal) => captureInstalledSkills({ artifacts: store.artifacts,
    requestedSkillIds, workspaceRoot: roots[0]!, workspaceIdentity: workspace, workspaceIdentityRef: session.workspaceIdentityRef,
    userRoots: [{ root: roots[1]!, prefix: 'skills' }, { root: roots[2]!, prefix: '.agents/skills' }], actualUserHome: home,
    principal, principalRef: channel.principalIdentityRef, bundle: owned.runtimeAuthority.bundle,
    bundleRef: canonicalSha256(owned.runtimeAuthority.bundle), signal });
  const binding = { workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentityDigest: workspace.identityDigest,
    ownerPrincipalId: principal.principalId, runtimeBundleRef: canonicalSha256(owned.runtimeAuthority.bundle),
    runtimeBundleManifestDigest: owned.runtimeAuthority.bundle.manifestDigest };
  return { ...owned, create, roots, capture, binding };
}

test('real user/workspace descriptors freeze exact ordered sources; retained reads survive mutable source deletion', async t => {
  const value = await fixture(t), work = await value.create('workspace', 'work', 'check.sh', Buffer.from('exit 91\n'));
  const user = await value.create('user', 'user');
  const result = await value.capture(['user', 'work']); assert.deepEqual(result.skills.map(skill => skill.skillId), ['user', 'work']);
  assert(result.metadata.length > 0); value.roots.forEach(root => root.assertHeld());
  const before = await readFrozenSkillData(value.store.artifacts, result.skills[1]!, value.binding);
  assert.equal(before.manifest.resources[0]!.kind, 'executable-disabled'); assert.equal(before.instruction.utf8, 'Use the [work resource](check.sh).');
  assert.deepEqual(frozenSkillResourceRange(before, { skillId: 'work', canonicalRelativePath: 'check.sh', offset: 0, length: 4 }),
    { schemaVersion: 1, skillId: 'work', canonicalRelativePath: 'check.sh', kind: 'executable-disabled', byteCount: 8,
      offset: 0, bytesBase64: Buffer.from('exit').toString('base64'), nextOffset: 4, eof: false });
  await rm(work, { recursive: true }); await rm(user, { recursive: true });
  const after = await readFrozenSkillData(value.store.artifacts, result.skills[1]!, value.binding);
  assert.equal(canonicalSha256(after.source), canonicalSha256(before.source));
  assert.equal(after.files.get('check.sh')!.toString(), 'exit 91\n');
  assert.throws(() => frozenSkillResourceRange(after, { skillId: 'work', canonicalRelativePath: 'check.sh', offset: 9, length: 1 }));
});

test('cross-scope duplicate id refuses; a same-named directory without SKILL.md grants no implicit shadow', async t => {
  const value = await fixture(t), first = await value.create('workspace', 'same'); await value.create('user', 'same');
  await assert.rejects(value.capture(['same'])); value.roots.forEach(root => root.assertHeld());
  await rm(path.join(first, 'SKILL.md'));
  const result = await value.capture(['same']);
  const data = await readFrozenSkillData(value.store.artifacts, result.skills[0]!, value.binding);
  assert.equal(data.source.sourceScope, 'user');
});

for (const changed of ['symlink', 'hardlink', 'mode', 'text', 'abort'] as const)
  test(`genuine skill capture refuses ${changed} and joins borrowed directory/read resources`, async t => {
    const value = await fixture(t), directory = await value.create('workspace', 'work'), file = path.join(directory, 'data.txt');
    const abort = new AbortController();
    if (changed === 'symlink') { await rm(file); await symlink('../outside', file); }
    else if (changed === 'hardlink') await link(file, path.join(directory, 'alias.txt'));
    else if (changed === 'mode') await chmod(file, 0o666);
    else if (changed === 'text') await writeFile(path.join(directory, 'SKILL.md'), '---\r\nname: work\r\n---\r\nText.\r\n');
    else abort.abort(new Error('the original skill capture was cancelled'));
    await assert.rejects(value.capture(['work'], abort.signal)); value.roots.forEach(root => root.assertHeld());
  });

test('original full CAS bytes are required after capture; missing raw data never falls back to a live skill path', async t => {
  const value = await fixture(t); await value.create('workspace', 'work'); const selected = (await value.capture(['work'])).skills[0]!;
  const original = await readFrozenSkillData(value.store.artifacts, selected, value.binding), resource = original.manifest.resources[0]!;
  const file = path.join(value.stateRoot, 'cas', resource.contentRef), retained = path.join(value.stateRoot, 'retained-cas-object');
  const bytes = await readFile(file); await rename(file, retained);
  try { await assert.rejects(readFrozenSkillData(value.store.artifacts, selected, value.binding)); }
  finally { await rename(retained, file); }
  assert((await readFrozenSkillData(value.store.artifacts, selected, value.binding)).files.get(resource.canonicalRelativePath)!.equals(bytes));
});

test('real descriptor capture follows only the declared Markdown/JSON closure and retained readers reject a rehashed orphan', async t => {
  const value = await fixture(t), directory = await value.create('workspace', 'work', 'references/guide.md', Buffer.from('[schema](assets/root.json)\n'));
  await mkdir(path.join(directory, 'assets/types'), { recursive: true, mode: 0o700 });
  await writeFile(path.join(directory, 'assets/root.json'), '{"$ref":"types/value.json#/$defs/value"}', { mode: 0o644 });
  await writeFile(path.join(directory, 'assets/types/value.json'), '{"$defs":{"value":{"type":"string"}}}', { mode: 0o644 });
  await writeFile(path.join(directory, 'unselected.txt'), 'unrelated bytes', { mode: 0o666 });
  await symlink('/never-opened', path.join(directory, 'unselected-link'));
  const selected = (await value.capture(['work'])).skills[0]!, data = await readFrozenSkillData(value.store.artifacts, selected, value.binding);
  assert.deepEqual([...data.files.keys()], ['SKILL.md', 'assets/root.json', 'assets/types/value.json', 'references/guide.md']);
  assert(data.source.sourceScope === 'workspace');
  const bytes = Buffer.from('unreferenced'), published = await value.store.artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-skill-source-file-v1');
  const fields = { canonicalRelativePath: 'z.txt', rawBytesRef: published.ref, rawBytesDigest: published.ref, rawByteCount: bytes.length,
    fileDescriptor: { ...data.source.files[0]!.fileDescriptor } };
  const file = { ...fields, sourceEntryDigest: canonicalSha256({ sourceScope: 'workspace', workspaceIdentityDigest: data.source.workspaceIdentityDigest,
    rootDescriptor: data.source.rootDescriptor, ...fields }) };
  const { sourceIdentityDigest: _sourceDigest, ...sourceCore } = data.source;
  const source = { ...sourceCore, files: [...data.source.files, file] }, sourceRef = (await value.store.artifacts.publishCanonical({ ...source,
    sourceIdentityDigest: canonicalSha256(source) }, source.format)).ref;
  const { manifestDigest: _manifestDigest, ...manifestCore } = data.manifest;
  const manifest = { ...manifestCore, sourceIdentityRef: sourceRef, sourceIdentityDigest: canonicalSha256(source), resources: [...data.manifest.resources,
    { canonicalRelativePath: 'z.txt', kind: 'text', contentRef: published.ref, contentDigest: published.ref }] };
  const forged = { ...manifest, manifestDigest: canonicalSha256(manifest) }, forgedRef = (await value.store.artifacts.publishCanonical(forged, forged.format)).ref;
  await assert.rejects(readFrozenSkillData(value.store.artifacts, { skillId: 'work', manifestRef: forgedRef, manifestDigest: forged.manifestDigest }, value.binding));
  await rm(directory, { recursive: true });
  assert.equal((await readFrozenSkillData(value.store.artifacts, selected, value.binding)).files.get('assets/types/value.json')!.toString(), '{"$defs":{"value":{"type":"string"}}}');
});

test('real resource metadata bounds refuse the 129th resource and a file beyond 16 MiB before reading it', async t => {
  const value = await fixture(t), directory = await value.create('workspace', 'work');
  await writeFile(path.join(directory, 'SKILL.md'), '---\nname: work\ndescription: Count boundary.\n---\n' +
    Array.from({ length: 129 }, (_, index) => `[file${index}](r${index}.txt)`).join('\n') + '\n');
  await assert.rejects(value.capture(['work'])); value.roots.forEach(root => root.assertHeld());
  await writeFile(path.join(directory, 'SKILL.md'), '---\nname: work\ndescription: Byte boundary.\n---\n[large](large.bin)\n');
  await writeFile(path.join(directory, 'large.bin'), Buffer.alloc(16 * 1024 * 1024 + 1), { mode: 0o644 });
  await assert.rejects(value.capture(['work'])); value.roots.forEach(root => root.assertHeld());
});

test('model projection preserves explicit skill order and full source bytes without reading mutable skills again', async t => {
  const value = await fixture(t); await value.create('workspace', 'work'); await value.create('user', 'user');
  const selected = await value.capture(['user', 'work']);
  const workspace = await value.store.artifacts.readCanonical<Extract<WorkspaceIdentityV1, { kind: 'live' }>>(value.binding.workspaceIdentityRef);
  const instructions = await captureInstalledWorkspaceInstructions(value.roots[0]!, value.store.artifacts, workspace, value.binding.workspaceIdentityRef);
  const core = { schemaVersion: 1 as const, format: 'cliq-model-text-v1' as const, utf8: 'Signed system.', byteCount: 14 };
  const system = { ...core, textDigest: canonicalSha256(core) }, systemRef = (await value.store.artifacts.publishCanonical(system, system.format)).ref;
  const spec = await value.store.artifacts.readCanonical<import('../kernel/types.js').RunSpec>(value.store.getRun(value.runId).specRef);
  const original = await value.store.artifacts.readCanonical<import('../kernel/types.js').RunAssemblyV1>(spec.assemblyRef);
  const input = { createdAt: sampleCanonicalNow(), runtime: { ...original.runtime, runtimeBundleRef: value.binding.runtimeBundleRef,
    runtimeBundleManifestDigest: value.binding.runtimeBundleManifestDigest }, instructions: { systemPromptRef: systemRef, systemPromptDigest: system.textDigest,
    workspaceInstructionsRef: instructions.ref, workspaceInstructionsDigest: instructions.value.manifestDigest, skills: selected.skills } };
  const expected = ['Signed system.', ...['user', 'work'].map(id => JSON.stringify({ format: 'cliq-skill-instruction-prompt-v1',
    instructionUtf8: `Use the [${id} resource](data.txt).`, skillId: id, sourceScope: id === 'user' ? 'user' : 'workspace' }))].join('\n\n');
  const before = await loadInstructionText(value.store.artifacts, input); assert.equal(before, expected);
  await rm(path.join(value.workspace, '.cliq/skills'), { recursive: true });
  assert.equal(await loadInstructionText(value.store.artifacts, input), before);
  await assert.rejects(loadInstructionText(value.store.artifacts, { ...input, instructions: { ...input.instructions, skills: [selected.skills[0]!, selected.skills[0]!] } }));
});

test('the fixed skill cursor excludes cloned/worktree Git metadata while ordinary and AGENTS capture keep their original guards', async t => {
  const value = await fixture(t), directory = await value.create('workspace', 'work');
  await mkdir(path.join(directory, '.git'), { mode: 0o700 });
  await writeFile(path.join(directory, '.git/config'), 'never capture Git metadata as a skill resource\n', { mode: 0o600 });
  const walk = (instruction: boolean) => {
    const first = instruction ? value.roots[0]!.openInstructionSnapshot() : value.roots[0]!.openSnapshot();
    const handles: Array<{ close(): void }> = [first], cursors = [first]; let instructions = 0;
    try {
      while (cursors.length) {
        const cursor = cursors.at(-1)!, entry = cursor.next();
        if (!entry) { cursor.assertComplete(); cursors.pop(); continue; }
        handles.push(entry);
        if (entry.kind === 'directory') { const child = entry.openDirectory(); handles.push(child); cursors.push(child); }
        else if (instruction && entry.path.endsWith('/SKILL.md')) {
          instructions++; assert.throws(() => entry.openFile(), /AGENTS\.md/u, 'the original instruction recipe cannot read SKILL.md');
        }
      }
      return instructions;
    } finally { handles.reverse().forEach(handle => handle.close()); }
  };
  assert.throws(() => walk(false), /nested Git metadata/u, 'ordinary source capture must retain its original nested-repository refusal');
  assert.equal(walk(true), 1);
  const selected = (await value.capture(['work'])).skills[0]!;
  const data = await readFrozenSkillData(value.store.artifacts, selected, value.binding);
  assert.deepEqual(data.source.files.map(file => file.canonicalRelativePath), ['SKILL.md', 'data.txt']);
  await rm(path.join(directory, '.git'), { recursive: true });
  await writeFile(path.join(directory, '.git'), 'gitdir: /never-opened-external-metadata\n', { mode: 0o600 });
  assert.equal((await value.capture(['work'])).skills[0]!.manifestRef, selected.manifestRef,
    'irrelevant Git metadata is neither read nor allowed to change the immutable skill data');
  value.roots.forEach(root => root.assertHeld());
});

for (const fault of ['cancel', 'source_changed', 'retirement'] as const)
  test(`skill capture joins its real two raw publications and complete triple before ${fault} can return`, async t => {
    const value = await fixture(t), directory = await value.create('workspace', 'work'), before = value.store.getRun(value.runId);
    const objects = path.join(value.stateRoot, 'cas'), actualOpen = fs.open.bind(fs), active = new Set<object>();
    const abort = new AbortController(), reason = new Error('the original skill capture was cancelled after real durability');
    let rootSyncs = 0, fileSyncs = 0, rootCloses = 0, changed = false;
    const mock = t.mock.method(fs, 'open', async (...args: Parameters<typeof actualOpen>) => {
      const handle = await actualOpen(...args), actualSync = handle.sync.bind(handle), actualClose = handle.close.bind(handle); active.add(handle);
      t.mock.method(handle, 'sync', async () => {
        await actualSync(); if (args[0] !== objects) { fileSyncs++; return; }
        rootSyncs++;
        if (rootSyncs === 12) {
          if (fault === 'cancel') abort.abort(reason);
          if (fault === 'source_changed') { await writeFile(path.join(directory, 'data.txt'), 'changed after actual group durability\n'); changed = true; }
        }
      });
      t.mock.method(handle, 'close', async () => {
        await actualClose(); assert(active.delete(handle));
        if (args[0] === objects && ++rootCloses === 3 && fault === 'retirement') throw new Error('actual CAS root FD closed with uncertain retirement report');
      });
      return handle;
    });
    try {
      await assert.rejects(value.capture(['work'], abort.signal), error => fault === 'retirement' ? error instanceof ResourceRetirementError
        : fault === 'cancel' ? error === reason : error instanceof Error);
      assert.equal(rootSyncs, 12, 'two real raw publications and one real three-object group keep all four barriers each');
      assert.equal(fileSyncs, 5, 'each raw and every canonical group member retains its actual file sync');
      assert.equal(active.size, 0); assert.equal(changed, fault === 'source_changed');
      value.roots.forEach(root => root.assertHeld()); assert.deepEqual(value.store.getRun(value.runId), before);
    } finally { mock.mock.restore(); t.mock.restoreAll(); }
  });
