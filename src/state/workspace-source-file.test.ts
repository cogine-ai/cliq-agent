import assert from 'node:assert/strict';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { link, mkdir, mkdtemp, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { sha256Bytes } from '../kernel/identity.js';
import {
  loadNativePackageReader, openNativeCasRoot, PACKAGE_READER_NATIVE_RELATIVE_PATH
} from '../runtime-bundle/native-package-reader.js';
import { ContentAddressedStore } from './cas.js';
import { loadNativeStateOwner, type HeldStateOwnerLock, type HeldWorkspaceSourceFile } from './native-owner.js';
import { captureHeldWorkspaceSourceFile, publishHeldWorkspaceSourceBlob } from './workspace-source-blob.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('held StateOwner streams an unchanged source file from its exact root and accepts source hardlinks',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-file-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(workspace, { mode: 0o700 });
    await mkdir(path.join(workspace, 'nested'), { mode: 0o700 });
    const bytes = Buffer.alloc(2 * 1024 * 1024 + 17, 0x61);
    await writeFile(path.join(workspace, 'nested', 'source.bin'), bytes, { mode: 0o600 });
    await link(path.join(workspace, 'nested', 'source.bin'), path.join(parent, 'source-link'));
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const root = held.inspectWorkspaceIdentity(workspace).root;
      const file = held.openWorkspaceSourceFile(workspace, root, 'nested/source.bin');
      try {
        assert.equal(file.size, bytes.byteLength);
        assert.equal(file.mode, 0o600);
        assert.equal(file.linkCount, 2);
        assert.equal(file.identity.ownerUid, process.geteuid!());
        const chunks: Buffer[] = [];
        while (chunks.reduce((size, chunk) => size + chunk.byteLength, 0) < file.size) {
          chunks.push(file.readChunk(1024 * 1024));
        }
        assert.deepEqual(Buffer.concat(chunks), bytes);
        file.assertStable();
        assert.equal(file.readChunk(1).byteLength, 0);
        file.rewind();
        assert.deepEqual(file.readChunk(1024 * 1024), bytes.subarray(0, 1024 * 1024));
        assert.throws(() => file.rewind(), /incomplete or changed/);
        assert.throws(() => file.readChunk.call({} as never, 1), /invalid workspace source file handle/);
      } finally { file.close(); }
      assert.throws(() => file.readChunk(1), /workspace source file changed/);
      assert.throws(() => file.rewind(), /incomplete or changed/);
      const revoked = held.openWorkspaceSourceFile(workspace, root, 'nested/source.bin');
      held.close();
      try { assert.throws(() => revoked.readChunk(1), /workspace source file changed/); }
      finally { revoked.close(); }
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });

test('held source reader rejects aliases, changes and displaced roots',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-swap-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(workspace, { mode: 0o700 });
    await mkdir(path.join(workspace, 'nested'), { mode: 0o700 });
    const source = path.join(workspace, 'nested', 'source.txt');
    await writeFile(source, 'first', { mode: 0o600 });
    await symlink(source, path.join(workspace, 'alias.txt'));
    await symlink(path.join(workspace, 'nested'), path.join(workspace, 'nested-alias'));
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const root = held.inspectWorkspaceIdentity(workspace).root;
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, 'alias.txt'), /unsafe or changed/);
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, 'nested-alias/source.txt'), /unsafe or changed/);
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, '.git/config'), /root-relative/);
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, '.Git/config'), /root-relative/);
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, '../source.txt'), /root-relative/);
      const file = held.openWorkspaceSourceFile(workspace, root, 'nested/source.txt');
      try {
        assert.equal(file.readChunk(2).toString('utf8'), 'fi');
        assert.throws(() => file.assertStable(), /incomplete/);
        assert.throws(() => file.rewind(), /incomplete or changed/);
        await writeFile(source, 'other');
        assert.throws(() => file.readChunk(1), /changed/);
        assert.throws(() => file.rewind(), /incomplete or changed/);
      } finally { file.close(); }
      const displacedFile = held.openWorkspaceSourceFile(workspace, root, 'nested/source.txt');
      await rename(workspace, path.join(parent, 'displaced'));
      await mkdir(workspace, { mode: 0o700 });
      try { assert.throws(() => displacedFile.readChunk(1), /changed/); }
      finally { displacedFile.close(); }
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, 'nested/source.txt'), /unsafe or changed/);
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });

test('held source publishes a multi-chunk CAS blob through the same descriptor',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-blob-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    const casPath = path.join(stateRoot, 'cas');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(casPath, { mode: 0o700 });
    await mkdir(workspace, { mode: 0o700 });
    const bytes = Buffer.alloc(3 * 1024 * 1024 + 17, 0x61);
    bytes[1024 * 1024] = 0x62;
    bytes[2 * 1024 * 1024] = 0x63;
    await writeFile(path.join(workspace, 'source.bin'), bytes, { mode: 0o700 });
    await link(path.join(workspace, 'source.bin'), path.join(parent, 'source-hardlink'));
    const helperPath = fileURLToPath(new URL(`../../dist/${PACKAGE_READER_NATIVE_RELATIVE_PATH}`, import.meta.url));
    const binding = await loadNativePackageReader(sha256Bytes(readFileSync(helperPath)));
    const cas = openNativeCasRoot(binding, casPath);
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const root = held.inspectWorkspaceIdentity(workspace).root;
      const captured = await captureHeldWorkspaceSourceFile(held, workspace, root,
        'source.bin', cas);
      assert.deepEqual(captured.entry, { path: 'source.bin', kind: 'file',
        mode: 0o755, size: bytes.byteLength, blobRef: sha256Bytes(bytes) });
      assert.equal(captured.linkCount, 2);
      assert.equal(captured.identity.ownerUid, process.geteuid!());
      const file = held.openWorkspaceSourceFile(workspace, root, 'source.bin');
      try {
        const artifact = await publishHeldWorkspaceSourceBlob(file, cas);
        assert.deepEqual(artifact, {
          ref: sha256Bytes(bytes), byteLength: bytes.byteLength,
          mediaType: 'application/octet-stream', schemaKind: 'cliq-workspace-file-v1'
        });
        assert.deepEqual(await new ContentAddressedStore(casPath).read(artifact.ref), bytes);
      } finally { file.close(); }
      await writeFile(path.join(workspace, 'empty.bin'), Buffer.alloc(0), { mode: 0o600 });
      const empty = held.openWorkspaceSourceFile(workspace, root, 'empty.bin');
      try {
        const artifact = await publishHeldWorkspaceSourceBlob(empty, cas);
        assert.equal(artifact.ref, sha256Bytes(Buffer.alloc(0)));
        assert.equal(artifact.byteLength, 0);
        assert.deepEqual(await new ContentAddressedStore(casPath).read(artifact.ref), Buffer.alloc(0));
      } finally { empty.close(); }
    } finally {
      held.close();
      cas.close();
      await rm(parent, { recursive: true, force: true });
    }
  });

test('captured source blob must still belong to the same literal directory entry',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-entry-race-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    const casPath = path.join(stateRoot, 'cas');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(casPath, { mode: 0o700 });
    await mkdir(workspace, { mode: 0o700 });
    const sourcePath = path.join(workspace, 'source.bin');
    await writeFile(sourcePath, 'original', { mode: 0o700 });
    const helperPath = fileURLToPath(new URL(`../../dist/${PACKAGE_READER_NATIVE_RELATIVE_PATH}`, import.meta.url));
    const binding = await loadNativePackageReader(sha256Bytes(readFileSync(helperPath)));
    const cas = openNativeCasRoot(binding, casPath);
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const root = held.inspectWorkspaceIdentity(workspace).root;
      let listings = 0;
      const replacedAfterPublication = {
        listWorkspaceSourceDirectory: (...args: Parameters<HeldStateOwnerLock['listWorkspaceSourceDirectory']>) => {
          if (++listings === 2) {
            renameSync(sourcePath, path.join(workspace, 'displaced.bin'));
            writeFileSync(sourcePath, 'replacement');
          }
          return held.listWorkspaceSourceDirectory(...args);
        },
        openWorkspaceSourceFile: (...args: Parameters<HeldStateOwnerLock['openWorkspaceSourceFile']>) =>
          held.openWorkspaceSourceFile(...args)
      } as HeldStateOwnerLock;
      await assert.rejects(captureHeldWorkspaceSourceFile(replacedAfterPublication,
        workspace, root, 'source.bin', cas), /changed during capture/);
      assert.equal(listings, 2);

      const oldListing = held.listWorkspaceSourceDirectory(workspace, root, '');
      let reads = 0;
      const replacedBeforeOpening = {
        listWorkspaceSourceDirectory: (...args: Parameters<HeldStateOwnerLock['listWorkspaceSourceDirectory']>) =>
          ++reads === 1 ? oldListing : held.listWorkspaceSourceDirectory(...args),
        openWorkspaceSourceFile: (...args: Parameters<HeldStateOwnerLock['openWorkspaceSourceFile']>) => {
          renameSync(sourcePath, path.join(workspace, 'second-displaced.bin'));
          writeFileSync(sourcePath, 'second replacement');
          return held.openWorkspaceSourceFile(...args);
        }
      } as HeldStateOwnerLock;
      await assert.rejects(captureHeldWorkspaceSourceFile(replacedBeforeOpening,
        workspace, root, 'source.bin', cas), /changed before its held read/);
      assert.equal(reads, 1);
    } finally {
      held.close();
      cas.close();
      await rm(parent, { recursive: true, force: true });
    }
  });

test('source mutation before CAS publication aborts its verified stage without a residue',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-blob-race-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    const casPath = path.join(stateRoot, 'cas');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(casPath, { mode: 0o700 });
    await mkdir(workspace, { mode: 0o700 });
    const sourcePath = path.join(workspace, 'source.bin');
    await writeFile(sourcePath, Buffer.alloc(1024 * 1024 + 1, 0x61), { mode: 0o600 });
    const helperPath = fileURLToPath(new URL(`../../dist/${PACKAGE_READER_NATIVE_RELATIVE_PATH}`, import.meta.url));
    const binding = await loadNativePackageReader(sha256Bytes(readFileSync(helperPath)));
    const cas = openNativeCasRoot(binding, casPath);
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const root = held.inspectWorkspaceIdentity(workspace).root;
      const file = held.openWorkspaceSourceFile(workspace, root, 'source.bin');
      let stableChecks = 0;
      const changing: HeldWorkspaceSourceFile = {
        size: file.size, mode: file.mode, linkCount: file.linkCount, identity: file.identity,
        readChunk: (size) => file.readChunk(size),
        rewind: () => file.rewind(),
        assertStable: () => {
          stableChecks += 1;
          if (stableChecks === 3) {
            writeFileSync(sourcePath, Buffer.alloc(file.size, 0x62));
          }
          file.assertStable();
        },
        close: () => file.close()
      };
      try {
        await assert.rejects(publishHeldWorkspaceSourceBlob(changing, cas), /changed/);
        assert.equal(stableChecks, 3);
        assert.deepEqual(await readdir(casPath), []);
      } finally { file.close(); }
    } finally {
      held.close();
      cas.close();
      await rm(parent, { recursive: true, force: true });
    }
  });
