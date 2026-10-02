import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { chmod, link, mkdir, mkdtemp, readdir, rename, rm, stat, symlink, utimes, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import type { WorkspaceEntryManifest } from '../kernel/types.js';
import {
  loadNativePackageReader, openNativeCasRoot, PACKAGE_READER_NATIVE_RELATIVE_PATH
} from '../runtime-bundle/native-package-reader.js';
import { ContentAddressedStore } from './cas.js';
import { decodeWorkspaceEntries } from './decoders.js';
import { loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { captureLiveWorkspaceIdentity } from './workspace-identity.js';
import {
  assertCapturedWorkspaceSourceTree, captureHeldNonGitWorkspaceSourceTree,
  type CapturedWorkspaceSourceTree, type NonGitSourceCapturePolicy
} from './workspace-source-tree.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';
const binding = { principalId: 'source-tree-principal', sessionId: 'source-tree-session',
  expectedContextRevision: 1, admissionKey: Buffer.from('source-tree-run-1').toString('base64url') };
const defaultPolicy: NonGitSourceCapturePolicy = { knownCredentialRoots: [], declaredEphemeralPaths: [],
  limits: { maxEntries: 1000, maxBytes: 16 * 1024 * 1024 } };

function forwarding(held: HeldStateOwnerLock,
  overrides: Partial<HeldStateOwnerLock>): HeldStateOwnerLock {
  return Object.freeze({ ...Object.fromEntries(Object.entries(held).map(([key, value]) =>
    [key, typeof value === 'function' ? value.bind(held) : value])), ...overrides }) as HeldStateOwnerLock;
}

async function fixture(stateInside = false) {
  const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-tree-'));
  const workspace = path.join(parent, 'workspace');
  await mkdir(workspace, { mode: 0o700 });
  const stateRoot = path.join(stateInside ? workspace : parent, 'state');
  await mkdir(stateRoot, { mode: 0o700 });
  const casPath = path.join(stateRoot, 'cas');
  await mkdir(casPath, { mode: 0o700 });
  const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
  const helperPath = fileURLToPath(new URL(`../../dist/${PACKAGE_READER_NATIVE_RELATIVE_PATH}`, import.meta.url));
  const nativeCas = openNativeCasRoot(await loadNativePackageReader(sha256Bytes(readFileSync(helperPath))), casPath);
  const { identity } = await captureLiveWorkspaceIdentity({ workspacePath: workspace,
    ownerPrincipalId: binding.principalId, filesystem: held });
  const capture = (policy = defaultPolicy, filesystem = held) => captureHeldNonGitWorkspaceSourceTree({
    workspace: identity, stateRoot, binding, filesystem, cas: nativeCas, policy });
  const check = (source: CapturedWorkspaceSourceTree, filesystem = held) =>
    assertCapturedWorkspaceSourceTree(source, filesystem, { ...binding, workspacePath: workspace,
      workspaceIdentityDigest: identity.identityDigest, ...source });
  return { parent, workspace, stateRoot, casPath, held, identity, capture, check,
    cas: new ContentAddressedStore(casPath),
    close: async () => { nativeCas.close(); held.close(); await rm(parent, { recursive: true, force: true }); } };
}

test('whole non-Git capture retains binary bytes, modes, empty directories, hardlinks and safe links',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      await mkdir(path.join(f.workspace, 'src'), { mode: 0o700 });
      await mkdir(path.join(f.workspace, 'empty'), { mode: 0o700 });
      await mkdir(path.join(f.workspace, 'src', '.git'), { mode: 0o700 });
      await writeFile(path.join(f.workspace, 'src', '.git', 'secret'), 'never captured');
      await writeFile(path.join(f.workspace, 'src', 'binary\nfile'), Buffer.from([0, 0xff, 0x80, 3]), { mode: 0o600 });
      await writeFile(path.join(f.workspace, 'start.sh'), '#!/bin/sh\n', { mode: 0o700 });
      await link(path.join(f.workspace, 'start.sh'), path.join(f.workspace, 'same.sh'));
      await writeFile(path.join(f.workspace, '.gitignore'), '*\n');
      await symlink('src/binary\nfile', path.join(f.workspace, 'binary-link'));
      await symlink('../empty/missing', path.join(f.workspace, 'src', 'dangling'));
      const source = await f.capture({ ...defaultPolicy, maxChangedPaths: 1, maxChangedBytes: 1 });
      assert.deepEqual(source.entries.entries.map((entry) => entry.path),
        ['.gitignore', 'binary-link', 'empty', 'same.sh', 'src', 'src/binary\nfile', 'src/dangling', 'start.sh']);
      assert.ok(Object.isFrozen(source.entries.entries));
      assert.equal(source.entries.entries.find((entry) => entry.path === 'same.sh')!.mode, 0o755);
      assert.equal(source.entries.entries.find((entry) => entry.path === 'empty')!.mode, 0o755);
      for (const entry of source.entries.entries) {
        if (entry.kind === 'file') {
          assert.deepEqual(await f.cas.read(entry.blobRef), readFileSync(path.join(f.workspace, entry.path)));
        }
      }
      assert.equal(f.check(source).length, 4);
      const again = await f.capture({ ...defaultPolicy, maxChangedPaths: 1, maxChangedBytes: 1 });
      assert.equal(again.baseWorkspaceManifestRef, source.baseWorkspaceManifestRef);
    } finally { await f.close(); }
  });

test('hard exclusions and exact requested excludes prune before reading secret or ephemeral content',
  { skip: !supported }, async () => {
    const f = await fixture(true);
    try {
      for (const directory of ['credentials', 'output', 'vendor']) await mkdir(path.join(f.workspace, directory));
      const secret = Buffer.from('credential contents must not reach CAS');
      for (const directory of ['state', 'credentials', 'output', 'vendor']) {
        await writeFile(path.join(f.workspace, directory, 'secret'), secret);
      }
      await writeFile(path.join(f.workspace, 'skip.txt'), secret);
      await writeFile(path.join(f.workspace, 'keep.txt'), 'ordinary source');
      const source = await f.capture({ ...defaultPolicy,
        knownCredentialRoots: [path.join(f.workspace, 'CREDENTIALS')], declaredEphemeralPaths: ['output'],
        explicitExcludes: [{ path: 'vendor', scope: 'subtree' }, { path: 'skip.txt', scope: 'entry' }] });
      assert.deepEqual(source.entries.entries.map((entry) => entry.path), ['keep.txt']);
      await assert.rejects(f.cas.read(sha256Bytes(secret)));
      assert.equal(f.check(source).length, 4);
      await assert.rejects(f.capture({ ...defaultPolicy, knownCredentialRoots: [f.workspace] }),
        /inside a hard-excluded root/);
      await assert.rejects(f.capture({ ...defaultPolicy, explicitExcludes: [{ path: 'vendor', scope: 'entry' }] }),
        /structural-parent design/);
    } finally { await f.close(); }
  });

test('whole capture checks topology and source limits before publishing regular-file bytes',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      await writeFile(path.join(f.workspace, 'ordinary'), 'source bytes');
      await symlink('../outside', path.join(f.workspace, 'unsafe'));
      await assert.rejects(f.capture(), /leaves the root|unsafe/);
      assert.deepEqual(await readdir(f.casPath), []);
      await rm(path.join(f.workspace, 'unsafe'));
      await symlink('b', path.join(f.workspace, 'a'));
      await symlink('a', path.join(f.workspace, 'b'));
      await assert.rejects(f.capture(), /cyclic/);
      assert.deepEqual(await readdir(f.casPath), []);
      await rm(path.join(f.workspace, 'a'));
      await rm(path.join(f.workspace, 'b'));
      await assert.rejects(f.capture({ ...defaultPolicy, limits: { maxEntries: 0, maxBytes: 100 } }), /entry limit/);
      await assert.rejects(f.capture({ ...defaultPolicy, limits: { maxEntries: 10, maxBytes: 1 } }), /byte limit/);
      await symlink('ordinary', path.join(f.workspace, 'long-link'));
      await assert.rejects(f.capture({ ...defaultPolicy, limits: { maxEntries: 10, maxBytes: 12 } }), /byte limit/);
      assert.deepEqual(await readdir(f.casPath), []);
    } finally { await f.close(); }
  });

test('source symlinks cannot directly or transitively reach hard-excluded stores',
  { skip: !supported }, async () => {
    const f = await fixture(true);
    try {
      await writeFile(path.join(f.workspace, 'ordinary'), 'source bytes');
      await symlink('state', path.join(f.workspace, 'first'));
      await symlink('first/cas', path.join(f.workspace, 'second'));
      await assert.rejects(f.capture(), /hard-excluded root/);
      assert.deepEqual(await readdir(f.casPath), []);
    } finally { await f.close(); }
  });

test('final whole-tree validation detects source additions, deletions, bytes, modes and descriptor changes',
  { skip: !supported }, async (t) => {
    const changes: Array<[string, (workspace: string) => Promise<void> | void]> = [
      ['same-size rewrite with restored mtime', async (workspace) => {
        const file = path.join(workspace, 'a');
        const { mtime, atime } = await stat(file);
        await writeFile(file, 'changed!');
        await utimes(file, atime, mtime);
      }],
      ['new default-selected file', (workspace) => writeFile(path.join(workspace, 'new'), 'new')],
      ['deleted file', (workspace) => rm(path.join(workspace, 'a'))],
      ['file replacement', async (workspace) => {
        await rename(path.join(workspace, 'a'), path.join(workspace, 'displaced'));
        await writeFile(path.join(workspace, 'a'), 'original');
      }],
      ['mode change', (workspace) => chmod(path.join(workspace, 'a'), 0o700)],
      ['directory replacement', async (workspace) => {
        await rename(path.join(workspace, 'dir'), path.join(workspace, 'displaced-dir'));
        await mkdir(path.join(workspace, 'dir'));
      }],
      ['symlink target change', async (workspace) => {
        await rm(path.join(workspace, 'link'));
        await symlink('dir/missing', path.join(workspace, 'link'));
      }],
      ['new Git identity', (workspace) => mkdir(path.join(workspace, '.git'))]
    ];
    for (const [name, change] of changes) await t.test(name, async () => {
      const f = await fixture();
      try {
        await writeFile(path.join(f.workspace, 'a'), 'original');
        await mkdir(path.join(f.workspace, 'dir'));
        await symlink('a', path.join(f.workspace, 'link'));
        const capture = await f.capture();
        await change(f.workspace);
        assert.throws(() => f.check(capture), { code: 'ARTIFACT_MISMATCH' });
      } finally { await f.close(); }
    });
  });

test('final traversal catches a write to an earlier file while a later file is being rehashed',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      await writeFile(path.join(f.workspace, 'a'), 'original');
      await writeFile(path.join(f.workspace, 'z'), 'last');
      let validating = false;
      const filesystem = forwarding(f.held, {
        openWorkspaceSourceFile: (...args) => {
          if (validating && args[2] === 'z') writeFileSync(path.join(f.workspace, 'a'), 'changed!');
          return f.held.openWorkspaceSourceFile(...args);
        }
      });
      const source = await f.capture(defaultPolicy, filesystem);
      validating = true;
      assert.throws(() => f.check(source, filesystem), { code: 'ARTIFACT_MISMATCH' });
    } finally { await f.close(); }
  });

test('wide source directories are enumerated per tree pass rather than per captured file',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      for (let index = 0; index < 64; index += 1) await writeFile(path.join(f.workspace, `file-${index}`), String(index));
      let listings = 0;
      const filesystem = forwarding(f.held, { listWorkspaceSourceDirectory: (...args) => {
        listings += 1;
        return f.held.listWorkspaceSourceDirectory(...args);
      } });
      const source = await f.capture(defaultPolicy, filesystem);
      assert.equal(source.entries.entryCount, 64);
      assert.equal(listings, 4);
      f.check(source, filesystem);
      assert.equal(listings, 6);
    } finally { await f.close(); }
  });

test('a serialized capture copy, another owner, or a different admission binding supplies no live proof',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      const source = await f.capture();
      assert.throws(() => f.check(structuredClone(source)), /not bound/);
      assert.throws(() => f.check(source, forwarding(f.held, {})), /not bound/);
      assert.throws(() => assertCapturedWorkspaceSourceTree(source, f.held, {
        ...binding, admissionKey: Buffer.from('another-run-key1').toString('base64url'),
        workspacePath: f.workspace, workspaceIdentityDigest: f.identity.identityDigest, ...source
      }), /not bound/);
    } finally { await f.close(); }
  });

test('a native helper without change observations cannot silently qualify a captured source tree',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      await writeFile(path.join(f.workspace, 'ordinary'), 'source bytes');
      const legacy = forwarding(f.held, { listWorkspaceSourceDirectory: (...args) =>
        f.held.listWorkspaceSourceDirectory(...args).map((entry) => {
          const copied = { ...entry };
          Reflect.deleteProperty(copied, 'changeToken');
          return copied;
        }) });
      await assert.rejects(f.capture(defaultPolicy, legacy), /no valid native change observation/);
      assert.deepEqual(await readdir(f.casPath), []);
    } finally { await f.close(); }
  });

test('retained source trees reject ASCII and Unicode case aliases even when every digest rehashes', () => {
  for (const paths of [['A', 'a'], ['SS', 'ß'], ['Σ', 'ς']]) {
    const entries: WorkspaceEntryManifest['entries'] = paths.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
      .map((relative) => ({ path: relative, kind: 'file', mode: 0o644, size: 0, blobRef: sha256Bytes(Buffer.alloc(0)) }));
    const tree = { schemaVersion: 1 as const, format: 'cliq-workspace-entries-v1' as const, entries };
    assert.throws(() => decodeWorkspaceEntries({ ...tree, entryCount: 2, byteCount: 0,
      treeDigest: canonicalSha256(tree) }), /case collision/);
  }
});

test('capture rejects actual case collisions on a case-sensitive source filesystem',
  { skip: process.platform !== 'linux' }, async () => {
    const f = await fixture();
    try {
      writeFileSync(path.join(f.workspace, 'A'), 'one');
      writeFileSync(path.join(f.workspace, 'a'), 'two');
      await assert.rejects(f.capture(), /case collision/);
      assert.deepEqual(await readdir(f.casPath), []);
    } finally { await f.close(); }
  });

test('unsupported special files fail source capture before ordinary bytes reach CAS',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      await writeFile(path.join(f.workspace, 'ordinary'), 'source bytes');
      execFileSync('mkfifo', [path.join(f.workspace, 'pipe')]);
      await assert.rejects(f.capture(), { code: 'ARTIFACT_MISMATCH' });
      assert.deepEqual(await readdir(f.casPath), []);
    } finally { await f.close(); }
  });

const qualifyMounts = process.platform === 'linux' && process.env.CLIQ_TEST_SOURCE_BIND_MOUNTS === '1';

test('Linux source capture refuses an external directory bind mount on the same filesystem',
  { skip: !qualifyMounts }, async () => {
    const f = await fixture();
    const target = path.join(f.workspace, 'mounted');
    let mounted = false;
    try {
      const outside = path.join(f.parent, 'outside');
      await mkdir(outside);
      await writeFile(path.join(outside, 'secret'), 'outside source root');
      await mkdir(target);
      assert.equal((await stat(outside)).dev, (await stat(f.workspace)).dev);
      // CI opts into this only in its disposable private mount namespace.
      execFileSync('sudo', ['-n', 'mount', '--bind', outside, target]);
      mounted = true;
      await assert.rejects(f.capture(), { code: 'ARTIFACT_MISMATCH' });
      assert.throws(() => f.held.openWorkspaceSourceFile(f.workspace, f.identity.rootIdentity, 'mounted/secret'),
        { code: 'ARTIFACT_MISMATCH' });
      assert.deepEqual(await readdir(f.casPath), []);
    } finally {
      if (mounted) execFileSync('sudo', ['-n', 'umount', target]);
      await f.close();
    }
  });

test('Linux source validation refuses a bind mount even when its inode and timestamps are identical',
  { skip: !qualifyMounts }, async () => {
    const f = await fixture();
    const target = path.join(f.workspace, 'ordinary');
    let mounted = false;
    try {
      await writeFile(target, 'source bytes');
      const source = await f.capture();
      const before = await stat(target, { bigint: true });
      execFileSync('sudo', ['-n', 'mount', '--bind', target, target]);
      mounted = true;
      const after = await stat(target, { bigint: true });
      for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(before[key], after[key]);
      assert.throws(() => f.check(source), { code: 'ARTIFACT_MISMATCH' });
    } finally {
      if (mounted) execFileSync('sudo', ['-n', 'umount', target]);
      await f.close();
    }
  });
