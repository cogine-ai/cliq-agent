import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { chmod, link, mkdir, mkdtemp, readdir, readFile, realpath, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { sha256Bytes } from '../kernel/identity.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { policyProfile, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ContentAddressedStore } from '../state/cas.js';
import {
  PACKAGE_READER_NATIVE_RELATIVE_PATH, importHeldPackageToCas, importVerifiedPackageEntryToCas,
  loadNativePackageReader, openCandidateStageRoot, openInstalledBundleRoot, openNativeCasRoot,
  openPackageRoot, publishHeldPackageCandidate, readHeldPackageManifest, readVerifiedPackageEntryBytes,
  stageHeldPackageCandidate, streamVerifiedPackageEntry, verifyHeldInstalledBundle, verifyHeldPackage
} from './native-package-reader.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';
const helper = fileURLToPath(new URL(`../../dist/${PACKAGE_READER_NATIVE_RELATIVE_PATH}`, import.meta.url));
const helperDigest = () => sha256Bytes(readFileSync(helper));
const signedEntry = (relativePath: string, bytes: Buffer, executable = false) => ({
  entryId: 'payload', role: 'bundle_object', version: '1', relativePath,
  digest: sha256Bytes(bytes), byteCount: bytes.byteLength, executable
});

async function packageFixture() {
  const rootPath = await mkdtemp(path.join(await realpath(os.tmpdir()), 'cliq-package-reader-'));
  await chmod(rootPath, 0o700);
  return rootPath;
}

test('held package root streams and rehashes a multi-chunk signed entry', { skip: !supported }, async () => {
  const rootPath = await packageFixture();
  try {
    const bytes = Buffer.alloc(2 * 1024 * 1024 + 17, 0x61);
    await mkdir(path.join(rootPath, 'payload'), { mode: 0o700 });
    await writeFile(path.join(rootPath, 'payload', 'worker'), bytes, { mode: 0o500 });
    const binding = await loadNativePackageReader(helperDigest());
    const root = openPackageRoot(binding, rootPath);
    try {
      const chunks: Buffer[] = [];
      await streamVerifiedPackageEntry(root, signedEntry('payload/worker', bytes, true),
        (chunk) => { chunks.push(chunk); });
      assert.deepEqual(chunks.map((chunk) => chunk.length), [1024 * 1024, 1024 * 1024, 17]);
      assert.deepEqual(Buffer.concat(chunks), bytes);
      assert.deepEqual(await readVerifiedPackageEntryBytes(root, signedEntry('payload/worker', bytes, true)), bytes);
      const held = root.openEntry('payload/worker', bytes.byteLength, true);
      try { assert.throws(() => held.readChunk(1.5), /invalid package read chunk/); }
      finally { held.close(); }
      await assert.rejects(streamVerifiedPackageEntry(root, {
        ...signedEntry('payload/worker', bytes, true), digest: '0'.repeat(64)
      }, () => {}), /different complete-file digest/);
    } finally { root.close(); }
  } finally { await rm(rootPath, { recursive: true, force: true }); }
});

test('native reader rejects symlink, hardlink, unsafe modes, and replaced package root',
  { skip: !supported }, async () => {
    const rootPath = await packageFixture();
    const moved = `${rootPath}-moved`;
    try {
      const bytes = Buffer.from('signed payload');
      await writeFile(path.join(rootPath, 'regular'), bytes, { mode: 0o400 });
      await link(path.join(rootPath, 'regular'), path.join(rootPath, 'hardlink'));
      await symlink('regular', path.join(rootPath, 'symlink'));
      await writeFile(path.join(rootPath, 'writable'), bytes, { mode: 0o666 });
      await chmod(path.join(rootPath, 'writable'), 0o666);
      await writeFile(path.join(rootPath, 'setuid'), bytes, { mode: 0o500 });
      await chmod(path.join(rootPath, 'setuid'), 0o4500);
      const binding = await loadNativePackageReader(helperDigest());
      const root = openPackageRoot(binding, rootPath);
      try {
        for (const name of ['hardlink', 'symlink', 'writable', 'setuid']) {
          await assert.rejects(streamVerifiedPackageEntry(root, signedEntry(name, bytes, name === 'setuid'), () => {}),
            /unsafe or changed/);
        }
        await rename(rootPath, moved);
        await mkdir(rootPath, { mode: 0o700 });
        assert.throws(() => root.openEntry('regular', bytes.length, false), /invalid package entry request/);
      } finally { root.close(); }
    } finally {
      await rm(rootPath, { recursive: true, force: true });
      await rm(moved, { recursive: true, force: true });
    }
  });

test('held entry refuses changed bytes, path substitution, and incomplete reads', { skip: !supported }, async () => {
  const rootPath = await packageFixture();
  try {
    const location = path.join(rootPath, 'payload');
    await writeFile(location, 'ABCD', { mode: 0o400 });
    const root = openPackageRoot(await loadNativePackageReader(helperDigest()), rootPath);
    try {
      const partial = root.openEntry('payload', 4, false);
      try {
        assert.equal(partial.readChunk(2).toString(), 'AB');
        assert.throws(() => partial.assertStable(), /incomplete or changed/);
      } finally { partial.close(); }
      const modified = root.openEntry('payload', 4, false);
      try {
        assert.equal(modified.readChunk(4).toString(), 'ABCD');
        await chmod(location, 0o600);
        await writeFile(location, 'WXYZ');
        await chmod(location, 0o400);
        assert.throws(() => modified.assertStable(), /incomplete or changed/);
      } finally { modified.close(); }
      const replaced = root.openEntry('payload', 4, false);
      try {
        assert.equal(replaced.readChunk(4).toString(), 'WXYZ');
        await rename(location, `${location}-old`);
        await writeFile(location, 'WXYZ', { mode: 0o400 });
        assert.throws(() => replaced.assertStable(), /incomplete or changed/);
      } finally { replaced.close(); }
    } finally { root.close(); }
  } finally { await rm(rootPath, { recursive: true, force: true }); }
});

test('native helper requires its separately pinned bootstrap digest', { skip: !supported }, async () => {
  await assert.rejects(loadNativePackageReader('0'.repeat(64)), /trusted bootstrap pin/);
  await assert.rejects(loadNativePackageReader(helperDigest(), 1), /trusted bootstrap pin/);
});

test('candidate copy rejects unsafe source and destination paths and a replaced stage',
  { skip: !supported }, async () => {
    const sourcePath = await packageFixture();
    const stagePath = await packageFixture();
    const moved = `${stagePath}-moved`;
    try {
      const bytes = Buffer.from('verified worker bytes');
      await writeFile(path.join(sourcePath, 'worker'), bytes, { mode: 0o500 });
      await symlink('worker', path.join(sourcePath, 'linked'));
      const binding = await loadNativePackageReader(helperDigest());
      const source = openPackageRoot(binding, sourcePath);
      const candidate = openCandidateStageRoot(binding, stagePath);
      try {
        assert.throws(() => candidate.copyEntry(source, 'linked', bytes.length, true),
          /candidate entry copy is unsafe or changed/);
        assert.throws(() => candidate.copyEntry(source, '../worker', bytes.length, true),
          /candidate entry copy is unsafe or changed/);
        await symlink('missing', path.join(stagePath, 'blocked'));
        assert.throws(() => candidate.copyEntry(source, 'blocked/worker', bytes.length, true),
          /candidate entry copy is unsafe or changed/);
        await rm(path.join(stagePath, 'blocked'));
        candidate.copyEntry(source, 'worker', bytes.length, true);
        assert.deepEqual(await readFile(path.join(stagePath, 'worker')), bytes);
        assert.equal((await stat(path.join(stagePath, 'worker'))).mode & 0o7777, 0o500);
        assert.throws(() => candidate.copyEntry(source, 'worker', bytes.length, true),
          /candidate entry copy is unsafe or changed/);
        await rename(stagePath, moved);
        await mkdir(stagePath, { mode: 0o700 });
        assert.throws(() => candidate.copyEntry(source, 'new-worker', bytes.length, true),
          /invalid candidate copy request/);
      } finally { candidate.close(); source.close(); }
    } finally {
      await rm(sourcePath, { recursive: true, force: true });
      await rm(stagePath, { recursive: true, force: true });
      await rm(moved, { recursive: true, force: true });
    }
  });

test('fixed package manifest rejects missing, linked, group-writable, and oversized files',
  { skip: !supported }, async () => {
    const rootPath = await packageFixture();
    const manifestPath = path.join(rootPath, 'runtime-bundle.json');
    const binding = await loadNativePackageReader(helperDigest());
    const read = () => {
      const root = openPackageRoot(binding, rootPath);
      try { return readHeldPackageManifest(root); }
      finally { root.close(); }
    };
    try {
      assert.throws(read, /manifest is unsafe or missing/);
      await writeFile(path.join(rootPath, 'target'), '{}', { mode: 0o400 });
      await symlink('target', manifestPath);
      assert.throws(read, /manifest is unsafe or missing/);
      await rm(manifestPath);
      await writeFile(manifestPath, '{}', { mode: 0o660 });
      await chmod(manifestPath, 0o660);
      assert.throws(read, /manifest is unsafe or missing/);
      await chmod(manifestPath, 0o400);
      assert.equal(read().toString(), '{}');
      await chmod(manifestPath, 0o600);
      await writeFile(manifestPath, Buffer.alloc(1024 * 1024 + 1));
      assert.throws(read, /manifest is unsafe or missing/);
    } finally {
      await rm(rootPath, { recursive: true, force: true });
    }
  });

test('package path capabilities reject symlinked ancestors and forged readers', { skip: !supported }, async () => {
  const rootPath = await packageFixture();
  const aliasPath = `${rootPath}-alias`;
  try {
    const bytes = Buffer.from('payload');
    await mkdir(path.join(rootPath, 'real'), { mode: 0o700 });
    await writeFile(path.join(rootPath, 'real', 'file'), bytes, { mode: 0o400 });
    await symlink('real', path.join(rootPath, 'alias'));
    await symlink(rootPath, aliasPath);
    const binding = await loadNativePackageReader(helperDigest());
    assert.throws(() => openPackageRoot(binding, aliasPath), /unsafe or changed/);
    assert.throws(() => openPackageRoot({
      openRoot: () => { throw new Error('forged'); },
      openInstalledRoot: () => { throw new Error('forged'); },
      openRuntimeRoot: () => { throw new Error('forged'); },
      openInitialSelectionWriter: () => { throw new Error('forged'); },
      openCandidateRoot: () => { throw new Error('forged'); },
      openCasRoot: () => { throw new Error('forged'); }
    }, rootPath),
      /pinned native helper/);
    const root = openPackageRoot(binding, rootPath);
    try {
      assert.throws(() => root.openEntry('alias/file', bytes.length, false), /unsafe or changed/);
      await assert.rejects(streamVerifiedPackageEntry({
        openEntry: () => { throw new Error('forged'); }, manifestByteCount: () => 1,
        activeByteCount: () => 1, listEntries: () => [], close: () => {}
      }, signedEntry('real/file', bytes), () => {}), /pinned native helper/);
    } finally { root.close(); }
  } finally {
    await rm(aliasPath, { force: true });
    await rm(rootPath, { recursive: true, force: true });
  }
});

test('package and CAS roots reject a group-writable ancestor', { skip: !supported }, async () => {
  const parent = await packageFixture();
  try {
    const unsafe = path.join(parent, 'unsafe');
    const packagePath = path.join(unsafe, 'package');
    const casPath = path.join(unsafe, 'cas');
    await mkdir(unsafe, { mode: 0o700 });
    await mkdir(packagePath, { mode: 0o700 });
    await mkdir(casPath, { mode: 0o700 });
    await chmod(unsafe, 0o770);
    const binding = await loadNativePackageReader(helperDigest());
    assert.throws(() => openPackageRoot(binding, packagePath), /package root is unsafe or changed/);
    assert.throws(() => openNativeCasRoot(binding, casPath), /CAS root is unsafe or changed/);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('signed manifest and all declared package bytes pass one held native package root', { skip: !supported }, async () => {
  const rootPath = await packageFixture();
  const casPath = await packageFixture();
  const candidatePath = await packageFixture();
  const retryPath = await packageFixture();
  const statePath = await mkdtemp(path.join(await realpath('/tmp'), 'cliq-publish-'));
  try {
    const key = generateKeyPairSync('ed25519');
    const releaseKeys = [{ keyId: 'package-test',
      publicKeyPem: key.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
    const profile = policyProfile();
    const payloads = [
      ['supervisor', 'supervisor', Buffer.from('supervisor'), true],
      ['worker', 'worker', Buffer.from('worker'), true],
      ['policy', 'policy_engine', canonicalJsonBytes(profile), false],
      ['default_https_trust_store', 'trust_store', Buffer.from('trust'), false],
      ['root-profile', 'sandbox_root_profile', Buffer.from('root'), false]
    ] as const;
    await mkdir(path.join(rootPath, 'payload'), { mode: 0o700 });
    const entries: RuntimeBundleManifest['entries'] = [];
    for (const [entryId, role, bytes, executable] of payloads) {
      const relativePath = `payload/${entryId}`;
      await writeFile(path.join(rootPath, relativePath), bytes, { mode: executable ? 0o500 : 0o400 });
      entries.push({ entryId, role, version: '1', relativePath,
        digest: sha256Bytes(bytes), byteCount: bytes.byteLength, executable });
    }
    const manifest: RuntimeBundleManifest = {
      schemaVersion: 1, bundleVersion: 'package-test-v1', controlProtocolRange: { min: 1, max: 1 },
      headlessSchemaRange: { min: 1, max: 1 }, stateSchemaRange: { min: 1, max: 2 },
      workerProtocolRange: { min: 1, max: 1 }, entries,
      structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'policy',
        rootEntryId: 'policy', artifactRef: entries[2]!.digest,
        semanticDigest: profile.profileDigest, memberRefs: [] }],
      guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId,
      manifestDigest: '', signature: ''
    };
    const { signature: _signature, manifestDigest: _digest, ...core } = manifest;
    manifest.manifestDigest = canonicalSha256(core);
    manifest.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${manifest.manifestDigest}`),
      key.privateKey).toString('base64');
    const manifestBytes = canonicalJsonBytes(manifest);
    await writeFile(path.join(rootPath, 'runtime-bundle.json'), manifestBytes, { mode: 0o400 });

    const binding = await loadNativePackageReader(helperDigest());
    const root = openPackageRoot(binding, rootPath);
    const cas = openNativeCasRoot(binding, casPath);
    try {
      assert.deepEqual(readHeldPackageManifest(root), manifestBytes);
      assert.equal((await verifyHeldPackage(root, releaseKeys)).bundleRef, sha256Bytes(manifestBytes));
      const candidate = openCandidateStageRoot(binding, candidatePath);
      const bundleRef = sha256Bytes(manifestBytes);
      const bundlePath = path.join(statePath, 'runtime', 'bundles', bundleRef);
      try {
        assert.equal((await stageHeldPackageCandidate(root, candidate, releaseKeys)).bundleRef,
          sha256Bytes(manifestBytes));
        assert.equal((await stat(candidatePath)).mode & 0o7777, 0o500);
        assert.equal((await stat(path.join(candidatePath, 'payload'))).mode & 0o7777, 0o500);
        assert.deepEqual(await readFile(path.join(candidatePath, 'payload', 'policy')),
          canonicalJsonBytes(profile));
        assert.throws(() => candidate.copyEntry(root, 'payload/policy', entries[2]!.byteCount, false),
          /invalid candidate copy request/);
        await mkdir(path.join(statePath, 'runtime', 'bundles'), { recursive: true, mode: 0o700 });
        const bundlesPath = path.join(statePath, 'runtime', 'bundles');
        const displaced = path.join(statePath, 'runtime', 'displaced-bundles');
        await rename(bundlesPath, displaced);
        await symlink(displaced, bundlesPath);
        await assert.rejects(publishHeldPackageCandidate(candidate, statePath, releaseKeys),
          /no-replace publication is unsafe or incomplete/);
        await rm(bundlesPath);
        await rename(displaced, bundlesPath);
        const published = await publishHeldPackageCandidate(candidate, statePath, releaseKeys);
        assert.equal(published.bundlePath, bundlePath);
        assert.equal((await stat(bundlePath)).mode & 0o7777, 0o500);
        assert.deepEqual(await readdir(path.join(statePath, 'runtime')), ['bundles']);
        const retry = openCandidateStageRoot(binding, retryPath);
        try {
          await stageHeldPackageCandidate(root, retry, releaseKeys);
          await assert.rejects(publishHeldPackageCandidate(retry, statePath, releaseKeys),
            /no-replace publication is unsafe or incomplete/);
          assert.equal((await stat(retryPath)).mode & 0o7777, 0o500);
          assert.deepEqual(await readdir(path.join(statePath, 'runtime', 'bundles')), [bundleRef]);
        } finally { retry.close(); }
      } finally { candidate.close(); }
      const installed = openInstalledBundleRoot(binding, bundlePath);
      try {
        assert.equal((await verifyHeldInstalledBundle(installed, releaseKeys,
          sha256Bytes(manifestBytes))).bundleRef, sha256Bytes(manifestBytes));
      } finally { installed.close(); }
      const imported = await importHeldPackageToCas(root, cas, releaseKeys);
      assert.equal(imported.bundleRef, sha256Bytes(manifestBytes));
      assert.deepEqual(await new ContentAddressedStore(casPath).read(imported.bundleRef), manifestBytes);
      assert.equal((await readdir(casPath)).length, entries.length + 1);
      await chmod(path.join(rootPath, 'payload', 'policy'), 0o600);
      await writeFile(path.join(rootPath, 'payload', 'policy'), Buffer.alloc(entries[2]!.byteCount, 0x61));
      await chmod(path.join(rootPath, 'payload', 'policy'), 0o400);
      await assert.rejects(verifyHeldPackage(root, releaseKeys), /different complete-file digest/);
      await assert.rejects(importHeldPackageToCas(root, cas, releaseKeys), /different complete-file digest/);
      assert.equal((await readdir(casPath)).length, entries.length + 1);
    } finally { cas.close(); root.close(); }
  } finally {
    await rm(rootPath, { recursive: true, force: true });
    await rm(casPath, { recursive: true, force: true });
    await chmod(candidatePath, 0o700).catch(() => {});
    await chmod(path.join(candidatePath, 'payload'), 0o700).catch(() => {});
    await rm(candidatePath, { recursive: true, force: true });
    await chmod(retryPath, 0o700);
    await chmod(path.join(retryPath, 'payload'), 0o700).catch(() => {});
    await rm(retryPath, { recursive: true, force: true });
    for (const ref of await readdir(path.join(statePath, 'runtime', 'bundles')).catch(() => [])) {
      const installed = path.join(statePath, 'runtime', 'bundles', ref);
      await chmod(installed, 0o700);
      await chmod(path.join(installed, 'payload'), 0o700).catch(() => {});
    }
    await rm(statePath, { recursive: true, force: true });
  }
});

test('native CAS import streams signed bytes, publishes once, and verifies an existing object',
  { skip: !supported }, async () => {
    const rootPath = await packageFixture();
    const casPath = await packageFixture();
    try {
      const bytes = Buffer.alloc(2 * 1024 * 1024 + 17, 0x62);
      const entry = signedEntry('large-worker', bytes, true);
      await writeFile(path.join(rootPath, entry.relativePath), bytes, { mode: 0o500 });
      const binding = await loadNativePackageReader(helperDigest());
      const source = openPackageRoot(binding, rootPath);
      const cas = openNativeCasRoot(binding, casPath);
      try {
        await importVerifiedPackageEntryToCas(source, cas, entry);
        assert.deepEqual(await new ContentAddressedStore(casPath).read(entry.digest), bytes);
        const published = await stat(path.join(casPath, entry.digest));
        assert.equal(published.mode & 0o7777, 0o400);
        assert.equal(published.nlink, 1);
        await importVerifiedPackageEntryToCas(source, cas, entry);
        assert.deepEqual(await readdir(casPath), [entry.digest]);
      } finally { cas.close(); source.close(); }
    } finally {
      await rm(rootPath, { recursive: true, force: true });
      await rm(casPath, { recursive: true, force: true });
    }
  });

test('native CAS import removes failed staging and refuses a corrupt existing object',
  { skip: !supported }, async () => {
    const rootPath = await packageFixture();
    const casPath = await packageFixture();
    try {
      const bytes = Buffer.from('expected signed bytes');
      const entry = signedEntry('payload', bytes);
      await writeFile(path.join(rootPath, 'payload'), bytes, { mode: 0o400 });
      const binding = await loadNativePackageReader(helperDigest());
      const source = openPackageRoot(binding, rootPath);
      const cas = openNativeCasRoot(binding, casPath);
      try {
        await assert.rejects(importVerifiedPackageEntryToCas(source, cas,
          { ...entry, digest: '0'.repeat(64) }), /different complete-file digest/);
        assert.deepEqual(await readdir(casPath), []);
        const corrupt = Buffer.alloc(bytes.byteLength, 0x78);
        await writeFile(path.join(casPath, entry.digest), corrupt, { mode: 0o400 });
        await assert.rejects(importVerifiedPackageEntryToCas(source, cas, entry),
          /CAS artifact differs from its expected digest/);
        assert.deepEqual(await readdir(casPath), [entry.digest]);
        assert.deepEqual(await readFile(path.join(casPath, entry.digest)), corrupt);
        await rm(path.join(casPath, entry.digest));
        await symlink('absent', path.join(casPath, entry.digest));
        await assert.rejects(importVerifiedPackageEntryToCas(source, cas, entry),
          /CAS artifact is unsafe or changed/);
        assert.deepEqual(await readdir(casPath), [entry.digest]);
      } finally { cas.close(); source.close(); }
    } finally {
      await rm(rootPath, { recursive: true, force: true });
      await rm(casPath, { recursive: true, force: true });
    }
  });

test('native CAS import preserves an empty signed object without a temporary residue',
  { skip: !supported }, async () => {
    const rootPath = await packageFixture();
    const casPath = await packageFixture();
    try {
      const bytes = Buffer.alloc(0);
      const entry = signedEntry('empty', bytes);
      await writeFile(path.join(rootPath, 'empty'), bytes, { mode: 0o400 });
      const binding = await loadNativePackageReader(helperDigest());
      const source = openPackageRoot(binding, rootPath);
      const cas = openNativeCasRoot(binding, casPath);
      try {
        await importVerifiedPackageEntryToCas(source, cas, entry);
        assert.deepEqual(await readdir(casPath), [entry.digest]);
        assert.deepEqual(await new ContentAddressedStore(casPath).read(entry.digest), bytes);
      } finally { cas.close(); source.close(); }
    } finally {
      await rm(rootPath, { recursive: true, force: true });
      await rm(casPath, { recursive: true, force: true });
    }
  });

test('native CAS root and staged inode reject locator or mode substitution',
  { skip: !supported }, async () => {
    const casPath = await packageFixture();
    const moved = `${casPath}-moved`;
    const alias = `${casPath}-alias`;
    try {
      const binding = await loadNativePackageReader(helperDigest());
      await symlink(casPath, alias);
      assert.throws(() => openNativeCasRoot(binding, alias), /CAS root is unsafe or changed/);
      const cas = openNativeCasRoot(binding, casPath);
      try {
        await chmod(casPath, 0o755);
        assert.throws(() => cas.beginStage('0'.repeat(64), 1, '0'.repeat(32)), /invalid CAS stage request/);
        await chmod(casPath, 0o700);
        const bytes = Buffer.from('staged');
        const ref = sha256Bytes(bytes);
        const nonce = '0'.repeat(32);
        const stage = cas.beginStage(ref, bytes.byteLength, nonce);
        stage.writeChunk(bytes);
        stage.seal();
        const stageName = `.tmp-${ref}-${nonce}`;
        await rename(path.join(casPath, stageName), path.join(casPath, 'displaced-stage'));
        await writeFile(path.join(casPath, stageName), bytes, { mode: 0o400 });
        assert.deepEqual(stage.readChunk(bytes.byteLength), bytes);
        assert.throws(() => stage.assertStable(), /CAS stage is incomplete or changed/);
        assert.throws(() => stage.abort(), /cleanup is uncertain/);
        await rename(casPath, moved);
        await mkdir(casPath, { mode: 0o700 });
        assert.throws(() => cas.beginStage(ref, bytes.byteLength, '1'.repeat(32)), /invalid CAS stage request/);
      } finally { cas.close(); }
    } finally {
      await rm(alias, { force: true });
      await rm(casPath, { recursive: true, force: true });
      await rm(moved, { recursive: true, force: true });
    }
  });
