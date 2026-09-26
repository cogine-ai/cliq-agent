import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { policyProfile, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { loadNativeStateOwner } from '../state/native-owner.js';
import {
  inspectSelectedRuntimeBundle, publishInitialRuntimeSelection, type ActiveRuntimeSelectionV1
} from './installed-selection.js';
import {
  loadNativePackageReader, openInitialSelectionWriter, openRuntimeSelectionRoot,
  PACKAGE_READER_NATIVE_RELATIVE_PATH
} from './native-package-reader.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';
const helper = fileURLToPath(new URL(`../../dist/${PACKAGE_READER_NATIVE_RELATIVE_PATH}`, import.meta.url));

async function fixture(selected = true) {
  const home = await mkdtemp(path.join(await realpath('/tmp'), 'cliq-installed-'));
  await chmod(home, 0o700);
  const stateRoot = path.join(home, 'state');
  const runtime = path.join(stateRoot, 'runtime');
  const bundles = path.join(runtime, 'bundles');
  await mkdir(bundles, { recursive: true, mode: 0o700 });
  const key = generateKeyPairSync('ed25519');
  const releaseKeys = [{ keyId: 'installed-fixture',
    publicKeyPem: key.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const profile = policyProfile();
  const payloads = [
    ['supervisor', 'supervisor', Buffer.from('sealed SEA fixture'), true],
    ['worker', 'worker', Buffer.from('sealed worker fixture'), true],
    ['policy', 'policy_engine', canonicalJsonBytes(profile), false],
    ['default_https_trust_store', 'trust_store', Buffer.from('fixture roots'), false],
    ['sandbox-root', 'sandbox_root_profile', Buffer.from('fixture root profile'), false]
  ] as const;
  const entries: RuntimeBundleManifest['entries'] = payloads.map(([entryId, role, bytes, executable]) => ({
    entryId, role, version: '1', relativePath: `payload/${entryId}`,
    digest: sha256Bytes(bytes), byteCount: bytes.length, executable
  }));
  const core: Omit<RuntimeBundleManifest, 'manifestDigest' | 'signature'> = {
    schemaVersion: 1, bundleVersion: 'installed-fixture-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: 2 }, workerProtocolRange: { min: 1, max: 1 },
    entries, structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'policy',
      rootEntryId: 'policy', artifactRef: entries[2]!.digest,
      semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId
  };
  const manifestDigest = canonicalSha256(core);
  const bundle: RuntimeBundleManifest = { ...core, manifestDigest,
    signature: sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${manifestDigest}`),
      key.privateKey).toString('base64') };
  const manifestBytes = canonicalJsonBytes(bundle);
  const bundleDigest = sha256Bytes(manifestBytes);
  const bundlePath = path.join(bundles, bundleDigest);
  const payloadDir = path.join(bundlePath, 'payload');
  await mkdir(payloadDir, { recursive: true, mode: 0o700 });
  for (const [entryId, , bytes, executable] of payloads) {
    await writeFile(path.join(payloadDir, entryId), bytes, { mode: executable ? 0o500 : 0o400 });
  }
  await writeFile(path.join(bundlePath, 'runtime-bundle.json'), manifestBytes, { mode: 0o400 });
  await chmod(payloadDir, 0o500);
  await chmod(bundlePath, 0o500);
  const selection: ActiveRuntimeSelectionV1 = {
    schemaVersion: 1, format: 'cliq-runtime-active-selection-v1', bundleDigest, manifestDigest
  };
  const activePath = path.join(runtime, 'active.json');
  if (selected) await writeFile(activePath, canonicalJsonBytes(selection), { mode: 0o400 });
  const reader = await loadNativePackageReader(sha256Bytes(readFileSync(helper)));
  return { home, stateRoot, bundlePath, payloadDir, activePath, selection, releaseKeys, reader };
}

async function cleanup(f: Awaited<ReturnType<typeof fixture>>): Promise<void> {
  await chmod(f.payloadDir, 0o700);
  await chmod(f.bundlePath, 0o700);
  await rm(f.home, { recursive: true, force: true });
}

test('initial selection publishes canonical 0400 bytes only once after complete signed-tree verification',
  { skip: !supported }, async () => {
    const f = await fixture(false);
    try {
      const policy = path.join(f.payloadDir, 'policy');
      await chmod(policy, 0o600);
      await assert.rejects(publishInitialRuntimeSelection(f.reader, f.stateRoot, f.releaseKeys,
        f.selection.bundleDigest), /installed bundle inventory is unsafe or changed/);
      await assert.rejects(readFile(f.activePath), { code: 'ENOENT' });
      await chmod(policy, 0o400);
      await symlink(f.bundlePath, f.activePath);
      await assert.rejects(publishInitialRuntimeSelection(f.reader, f.stateRoot, f.releaseKeys,
        f.selection.bundleDigest), /already present/);
      assert.equal((await lstat(f.activePath)).isSymbolicLink(), true);
      await rm(f.activePath);
      assert.deepEqual(await publishInitialRuntimeSelection(f.reader, f.stateRoot, f.releaseKeys,
        f.selection.bundleDigest), f.selection);
      assert.deepEqual(await readFile(f.activePath), canonicalJsonBytes(f.selection));
      assert.equal((await stat(f.activePath)).mode & 0o7777, 0o400);
      await assert.rejects(publishInitialRuntimeSelection(f.reader, f.stateRoot, f.releaseKeys,
        f.selection.bundleDigest), /already present/);
      assert.deepEqual(await readFile(f.activePath), canonicalJsonBytes(f.selection));
    } finally { await cleanup(f); }
  });

test('held initial-selection writer refuses a substituted runtime directory',
  { skip: !supported }, async () => {
    const f = await fixture(false);
    const runtimePath = path.join(f.stateRoot, 'runtime');
    const displaced = path.join(f.stateRoot, 'runtime-displaced');
    const held = openInitialSelectionWriter(f.reader, runtimePath);
    try {
      await rename(runtimePath, displaced);
      await mkdir(runtimePath, { mode: 0o700 });
      assert.throws(() => held.publishInitialActive(canonicalJsonBytes(f.selection), '0'.repeat(32)),
        /initial runtime selection is unsafe/);
      await assert.rejects(readFile(f.activePath), { code: 'ENOENT' });
    } finally {
      held.close();
      await rm(runtimePath, { recursive: true, force: true });
      await rename(displaced, runtimePath);
      await cleanup(f);
    }
  });

test('held initial-selection writer does not replace a preexisting stage name',
  { skip: !supported }, async () => {
    const f = await fixture(false);
    const nonce = '1'.repeat(32);
    const stagePath = path.join(f.stateRoot, 'runtime', `.active-${nonce}`);
    const held = openInitialSelectionWriter(f.reader, path.join(f.stateRoot, 'runtime'));
    try {
      await symlink(f.bundlePath, stagePath);
      assert.throws(() => held.publishInitialActive(canonicalJsonBytes(f.selection), nonce),
        /publication is unsafe or incomplete/);
      assert.equal((await lstat(stagePath)).isSymbolicLink(), true);
      await assert.rejects(readFile(f.activePath), { code: 'ENOENT' });
    } finally {
      held.close();
      await cleanup(f);
    }
  });

test('runtime inspection handle exposes no initial-selection write capability',
  { skip: !supported }, async () => {
    const f = await fixture(false);
    const held = openRuntimeSelectionRoot(f.reader, path.join(f.stateRoot, 'runtime'));
    try {
      assert.equal(Object.hasOwn(held, 'publishInitialActive'), false);
    } finally { held.close(); await cleanup(f); }
  });

test('read-only installed selection verifies its signed tree and refuses unsigned paths',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      const inspected = await inspectSelectedRuntimeBundle(f.reader, f.stateRoot, f.releaseKeys);
      assert.deepEqual(inspected.selection, f.selection);
      assert.equal(inspected.bundlePath, f.bundlePath);
      assert.equal(inspected.bundle.manifestDigest, f.selection.manifestDigest);
      const opening = inspectSelectedRuntimeBundle(f.reader, f.stateRoot, f.releaseKeys);
      const originalKey = f.releaseKeys[0]!.publicKeyPem;
      f.releaseKeys[0]!.publicKeyPem = 'mutated after inspection began';
      assert.equal((await opening).selection.bundleDigest, f.selection.bundleDigest);
      f.releaseKeys[0]!.publicKeyPem = originalKey;
      await assert.rejects(inspectSelectedRuntimeBundle(f.reader, f.stateRoot, []),
        /trusted release signature/);
      await chmod(f.payloadDir, 0o700);
      await writeFile(path.join(f.payloadDir, 'unsigned'), 'not in manifest', { mode: 0o400 });
      await chmod(f.payloadDir, 0o500);
      await assert.rejects(inspectSelectedRuntimeBundle(f.reader, f.stateRoot, f.releaseKeys),
        /missing or unsigned paths/);
      await chmod(f.payloadDir, 0o700);
      await rm(path.join(f.payloadDir, 'unsigned'));
      await chmod(f.payloadDir, 0o500);
      await chmod(f.bundlePath, 0o700);
      await mkdir(path.join(f.bundlePath, 'empty-extra'), { mode: 0o500 });
      await chmod(f.bundlePath, 0o500);
      await assert.rejects(inspectSelectedRuntimeBundle(f.reader, f.stateRoot, f.releaseKeys),
        /missing or unsigned paths/);
    } finally { await cleanup(f); }
  });

test('installed selection rejects writable bytes, a mutable bundle root and symlinked active file',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      const policy = path.join(f.payloadDir, 'policy');
      await chmod(policy, 0o600);
      await assert.rejects(inspectSelectedRuntimeBundle(f.reader, f.stateRoot, f.releaseKeys),
        /installed bundle inventory is unsafe or changed/);
      await chmod(policy, 0o400);
      await chmod(f.bundlePath, 0o700);
      await assert.rejects(inspectSelectedRuntimeBundle(f.reader, f.stateRoot, f.releaseKeys),
        /package root is unsafe or changed/);
      await chmod(f.bundlePath, 0o500);
      const saved = `${f.activePath}.saved`;
      await rename(f.activePath, saved);
      await symlink(saved, f.activePath);
      await assert.rejects(inspectSelectedRuntimeBundle(f.reader, f.stateRoot, f.releaseKeys),
        /active runtime selection is unsafe or missing/);
      await rm(f.activePath);
      await rename(saved, f.activePath);
      assert.deepEqual(await readFile(f.activePath), canonicalJsonBytes(f.selection));
      await chmod(f.activePath, 0o600);
      await writeFile(f.activePath, JSON.stringify(f.selection));
      await chmod(f.activePath, 0o400);
      await assert.rejects(inspectSelectedRuntimeBundle(f.reader, f.stateRoot, f.releaseKeys),
        /active runtime selection is not canonical/);
      await chmod(f.activePath, 0o600);
      await writeFile(f.activePath, canonicalJsonBytes(f.selection));
      await chmod(f.activePath, 0o400);
      assert.equal((await inspectSelectedRuntimeBundle(f.reader, f.stateRoot, f.releaseKeys))
        .selection.bundleDigest, f.selection.bundleDigest);
    } finally { await cleanup(f); }
  });

test('pinned package reader and StateOwner addons keep distinct loaded interfaces',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      assert.equal(typeof f.reader.openInstalledRoot, 'function');
      const owner = await loadNativeStateOwner();
      assert.match(owner.processStartToken(), /^(?:darwin-proc-start-time|linux-proc-start-ticks):/u);
    } finally { await cleanup(f); }
  });
