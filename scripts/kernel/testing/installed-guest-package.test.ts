// Real file/hash/Ed25519 closure only. Sparse inert bytes are deliberately not
// ext4/ELF, a native extractor success, or installed execution qualification.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { chmod, link, mkdir, mkdtemp, open, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { GUEST_EXTRACTOR_RECIPE } from '../../../src/sandbox/guest-toolchain.js';
import { validateGuestToolchainMetadata } from '../../../src/state/guest-toolchain.js';
import { writeInstalledGuestToolchain } from './installed-guest-package.js';

async function fixture(compact = false) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-guest-package-'));
  const guestImageRoot = path.join(directory, 'build'), packageRoot = path.join(directory, 'package');
  await mkdir(guestImageRoot, { mode: 0o700 }); await mkdir(packageRoot, { mode: 0o700 });
  const filename = path.join(guestImageRoot, 'guest-toolchain.ext4');
  const image = await open(filename, 'wx', 0o600);
  const imageByteCount = compact ? 33_554_432 : GUEST_EXTRACTOR_RECIPE.maxImageBytes;
  try { await image.truncate(imageByteCount); await image.chmod(0o400); } finally { await image.close(); }
  const hash = createHash('sha256'), zeroes = Buffer.alloc(65_536);
  for (let count = 0; count < imageByteCount; count += zeroes.length) hash.update(zeroes);
  const digest = hash.digest('hex');
  const executable = (logicalName: string, canonicalGuestPath: string, version: string) =>
    ({ logicalName, canonicalGuestPath, version, digest: sha256Bytes(Buffer.from(logicalName)) });
  const worker = executable('cliq-worker', '/runtime/cliq-linux-worker', '1'), shell = executable('sh', '/bin/sh', 'inert-shell'),
    git = executable('git', '/usr/bin/git', 'git version inert'), node = executable('node', '/usr/bin/node', '24.21.0');
  const files = [worker, shell, git, node].map(value => ({ path: value.canonicalGuestPath, digest: value.digest, byteCount: 1 }))
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const metadata = { schemaVersion: 1, format: 'cliq-guest-toolchain-publisher-input-v1', guestImageRef: digest, guestImageDigest: digest,
    guestImageByteCount: imageByteCount, guestImageFormat: 'raw-ext4-v1', architecture: 'x86_64',
    kernelAbi: 'linux-x86_64-v1', userspaceAbi: 'linux-x86_64-glibc-v1', worker, shell, git, node,
    searchTools: [], verifiers: [], admittedExecutables: [], files, extractedFileBytes: 4,
    imageLayout: { profile: 'cliq-guest-image-layout-v1', kind: compact ? 'compact' : 'qualification_max', contentBytes: 4,
      reserveBytes: 16_777_216, alignmentBytes: 16_777_216, imageByteCount },
    scope: 'actual build bytes only; not release-signed, execution-qualified or a Run proof' };
  const metadataPath = path.join(guestImageRoot, 'guest-toolchain-input.json');
  await writeFile(metadataPath, JSON.stringify(metadata), { flag: 'wx', mode: 0o400 });
  const extractorPath = path.join(directory, 'inert-extractor.node');
  await writeFile(extractorPath, 'opaque addon data, not an executable qualification', { flag: 'wx', mode: 0o500 });
  const keys = generateKeyPairSync('ed25519');
  return { directory, guestImageRoot, packageRoot, filename, metadata, metadataPath, extractorPath, keys,
    input: { packageRoot, guestImageRoot, extractorPath, publisherKeyId: 'installed-guest-data-test', privateKey: keys.privateKey } };
}

test('guest packaging preserves the complete signed compact image instead of requiring unused maximum padding', async () => {
  const current = await fixture(true);
  try {
    const result = await writeInstalledGuestToolchain(current.input);
    assert.equal(result.manifest.guestImageByteCount, 33_554_432);
    assert.deepEqual(result.imageLayout, current.metadata.imageLayout);
    assert.equal(result.entries.find(entry => entry.digest === result.manifest.guestImageRef)?.byteCount, 33_554_432);
    assert.deepEqual(result.root.memberRefs, [result.manifest.signatureRef, result.manifest.guestImageRef].sort());
    const retained = result.entries.find(entry => entry.digest === result.manifest.guestImageRef)!;
    const bytes = await readFile(path.join(current.packageRoot, retained.relativePath));
    assert.equal(bytes.length, 33_554_432); assert.equal(sha256Bytes(bytes), result.manifest.guestImageDigest);
  } finally { await rm(current.directory, { recursive: true, force: true }); }
});

test('guest packaging streams the complete fixed image and produces the exact production-verifiable signed metadata closure', async () => {
  const current = await fixture();
  try {
    const result = await writeInstalledGuestToolchain(current.input);
    assert.deepEqual(result.imageLayout, current.metadata.imageLayout);
    assert.equal(result.manifestId, 'installed-node-test-toolchain');
    assert.notEqual(result.root.rootEntryId, result.manifestId);
    assert.deepEqual(result.root.memberRefs, [result.manifest.signatureRef, result.manifest.guestImageRef].sort());
    assert.equal(result.entries.find(entry => entry.entryId === GUEST_EXTRACTOR_RECIPE.entryId)?.relativePath, GUEST_EXTRACTOR_RECIPE.relativePath);
    assert.equal(result.entries.find(entry => entry.digest === result.manifest.guestImageRef)?.byteCount, 268_435_456);
    assert.equal('contents' in result, false); assert.equal('imageBytes' in result, false);
    const extra = ['supervisor', 'worker', 'policy_engine', 'trust_store', 'sandbox_root_profile'].map(role => ({
      entryId: role === 'trust_store' ? 'default_https_trust_store' : `inert-${role}`, role, version: '1', relativePath: `inert/${role}`,
      digest: sha256Bytes(Buffer.from(role)), byteCount: role.length, executable: ['supervisor', 'worker'].includes(role) }));
    const bundle: RuntimeBundleManifest = { schemaVersion: 1, bundleVersion: 'data-test', controlProtocolRange: { min: 1, max: 1 },
      headlessSchemaRange: { min: 1, max: 1 }, stateSchemaRange: { min: 1, max: 1 }, workerProtocolRange: { min: 1, max: 1 },
      entries: [...extra, ...result.entries], structuredArtifacts: [result.root], guestToolchainManifestRefs: [result.manifestRef],
      publisherKeyId: current.input.publisherKeyId, manifestDigest: '', signature: '' };
    const resign = () => { const { manifestDigest: _, signature: __, ...core } = bundle; bundle.manifestDigest = canonicalSha256(core);
      bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), current.keys.privateKey).toString('base64'); };
    resign();
    const manifestBytes = await readFile(path.join(current.packageRoot, result.entries.find(entry => entry.entryId === result.root.rootEntryId)!.relativePath));
    const signatureEntry = result.entries.find(entry => entry.digest === result.manifest.signatureRef)!;
    const signature = await readFile(path.join(current.packageRoot, signatureEntry.relativePath));
    const releaseKeys = [{ keyId: current.input.publisherKeyId, publicKeyPem: current.keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
    assert.deepEqual(validateGuestToolchainMetadata(bundle, result.manifestRef, manifestBytes, signature, releaseKeys).manifest, result.manifest);
    const wrong = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${result.manifest.manifestDigest}`), current.keys.privateKey);
    const changed = { ...result.manifest, signatureRef: sha256Bytes(wrong) }, bytes = canonicalJsonBytes(changed), ref = sha256Bytes(bytes);
    bundle.entries = bundle.entries.map(entry => entry.entryId === result.root.rootEntryId ? { ...entry, digest: ref, byteCount: bytes.length } :
      entry.digest === result.manifest.signatureRef ? { ...entry, digest: changed.signatureRef,
        entryId: identityHash('runtime-bundle-object-v1', changed.signatureRef),
        relativePath: `objects/sha256/${changed.signatureRef.slice(0, 2)}/${changed.signatureRef}` } : entry);
    bundle.structuredArtifacts = [{ ...result.root, artifactRef: ref, memberRefs: [changed.signatureRef, changed.guestImageRef].sort() }];
    bundle.guestToolchainManifestRefs = [ref]; resign();
    // A wrong detached domain must remain rejected even when its outer bundle
    // is re-signed; the positive production reader above is not our own verifier.
    assert.throws(() => validateGuestToolchainMetadata(bundle, ref, bytes, wrong, releaseKeys), /guest manifest release signature is invalid/);
  } finally { await rm(current.directory, { recursive: true, force: true }); }
});

test('guest packaging refuses unknown publisher data and identities outside the fixed recipe before signing', async () => {
  const current = await fixture();
  const replace = async (value: unknown) => { await chmod(current.metadataPath, 0o600); await writeFile(current.metadataPath, JSON.stringify(value)); await chmod(current.metadataPath, 0o400); };
  try {
    for (const metadata of [
      { ...current.metadata, extraAuthority: 'not accepted' },
      { ...current.metadata, node: { ...current.metadata.node, version: '24.22.0' } },
      { ...current.metadata, node: { ...current.metadata.node, runtimeFallback: '/usr/bin/node' } },
      { ...current.metadata, guestImageByteCount: 268_435_455 },
      { ...current.metadata, files: current.metadata.files.map((entry, index) => index ? entry : { ...entry, unmeasuredAbi: true }) },
      { ...current.metadata, extractedFileBytes: 5 },
      { ...current.metadata, files: [...current.metadata.files].reverse() }
    ]) {
      await replace(metadata);
      await assert.rejects(writeInstalledGuestToolchain(current.input), /publisher|guest toolchain/);
    }
    await replace({ ...current.metadata, guestImageRef: '0'.repeat(64), guestImageDigest: '0'.repeat(64) });
    await assert.rejects(writeInstalledGuestToolchain(current.input), /complete publisher image digest differs/);
    await chmod(current.metadataPath, 0o600); await writeFile(current.metadataPath, Buffer.alloc(1_048_577)); await chmod(current.metadataPath, 0o400);
    await assert.rejects(writeInstalledGuestToolchain(current.input), /protected single-link regular file/);
  } finally { await rm(current.directory, { recursive: true, force: true }); }
});

test('compact packaging refuses non-recomputable layouts, incomplete bytes and a changed final byte before signing', async () => {
  const current = await fixture(true);
  const replace = async (value: unknown) => { await chmod(current.metadataPath, 0o600); await writeFile(current.metadataPath, JSON.stringify(value)); await chmod(current.metadataPath, 0o400); };
  try {
    const { imageLayout: _, ...missing } = current.metadata;
    const { reserveBytes: __, ...incomplete } = current.metadata.imageLayout;
    for (const metadata of [missing, { ...current.metadata, imageLayout: incomplete },
      { ...current.metadata, guestImageByteCount: 16_777_216 },
      { ...current.metadata, guestImageByteCount: 50_331_648 },
      ...[
        { extra: true }, { profile: 'other' }, { kind: 'other' }, { kind: ['compact'] },
        { contentBytes: 3 }, { contentBytes: 5 }, { contentBytes: '4' },
        { reserveBytes: 0 }, { alignmentBytes: 1 }, { imageByteCount: 16_777_216 },
        { imageByteCount: 50_331_648 }, { imageByteCount: 33_554_432.5 },
        { kind: 'qualification_max', imageByteCount: 33_554_432 },
      ].map(change => ({ ...current.metadata, imageLayout: { ...current.metadata.imageLayout, ...change } })),
      { ...current.metadata, files: current.metadata.files.slice(1), extractedFileBytes: 3 },
    ]) {
      await replace(metadata);
      await assert.rejects(writeInstalledGuestToolchain(current.input), /publisher|guest toolchain/);
    }
    await replace(current.metadata);
    await chmod(current.filename, 0o600);
    const incompleteImage = await open(current.filename, 'r+');
    try { await incompleteImage.truncate(33_554_431); await incompleteImage.chmod(0o400); } finally { await incompleteImage.close(); }
    await assert.rejects(writeInstalledGuestToolchain(current.input), /protected single-link regular file/);
    await chmod(current.filename, 0o600);
    const changedImage = await open(current.filename, 'r+');
    try { await changedImage.write(Buffer.from([1]), 0, 1, 33_554_431); await changedImage.chmod(0o400); } finally { await changedImage.close(); }
    await assert.rejects(writeInstalledGuestToolchain(current.input), /complete publisher image digest differs/);
    assert.deepEqual(await readdir(current.packageRoot), [],
      'refused layout or incomplete bytes cannot produce a partial signed package');
  } finally { await rm(current.directory, { recursive: true, force: true }); }
});

test('guest packaging refuses a writable, incomplete, linked or symlinked image instead of signing a pathname', async () => {
  const current = await fixture();
  try {
    await chmod(current.filename, 0o600);
    await assert.rejects(writeInstalledGuestToolchain(current.input), /protected single-link regular file/);
    const handle = await open(current.filename, 'r+');
    try { await handle.truncate(268_435_455); await handle.chmod(0o400); } finally { await handle.close(); }
    await assert.rejects(writeInstalledGuestToolchain(current.input), /protected single-link regular file/);
    await chmod(current.filename, 0o600);
    const restored = await open(current.filename, 'r+');
    try { await restored.truncate(268_435_456); await restored.chmod(0o400); } finally { await restored.close(); }
    const linked = path.join(current.guestImageRoot, 'linked-image'); await link(current.filename, linked);
    await assert.rejects(writeInstalledGuestToolchain(current.input), /protected single-link regular file/);
    await rm(linked);
    const held = path.join(current.guestImageRoot, 'actual-image'); await rename(current.filename, held);
    await symlink(held, current.filename);
    await assert.rejects(writeInstalledGuestToolchain(current.input), (error: NodeJS.ErrnoException) => error.code === 'ELOOP');
  } finally { await rm(current.directory, { recursive: true, force: true }); }
});


test('fixed Bash publisher keeps one measured admitted root, exact inventory and unchanged image bounds', async () => {
  const current = await fixture(true);
  const bashDigest = sha256Bytes(Buffer.from('opaque Bash inventory data; not an executable'));
  const bash = { logicalName: 'bash', canonicalGuestPath: '/bin/bash', digest: bashDigest, version: bashDigest };
  const files = [...current.metadata.files, { path: bash.canonicalGuestPath, digest: bash.digest, byteCount: 1 }]
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const metadata = { ...current.metadata, admittedExecutables: [bash], files, extractedFileBytes: 5,
    imageLayout: { ...current.metadata.imageLayout, contentBytes: 5 } };
  const replace = async (value: unknown) => {
    await chmod(current.metadataPath, 0o600); await writeFile(current.metadataPath, JSON.stringify(value)); await chmod(current.metadataPath, 0o400);
  };
  try {
    for (const changed of [
      { ...metadata, admittedExecutables: [{ ...bash, logicalName: 'other' }] },
      { ...metadata, admittedExecutables: [{ ...bash, canonicalGuestPath: '/usr/bin/bash' }] },
      { ...metadata, admittedExecutables: [{ ...bash, version: 'unmeasured-host-version' }] },
      { ...metadata, admittedExecutables: [bash, { ...bash, logicalName: 'other', canonicalGuestPath: '/bin/other' }] },
      { ...metadata, files: current.metadata.files, extractedFileBytes: 4, imageLayout: current.metadata.imageLayout },
      { ...metadata, files: files.map(file => file.path === '/bin/bash' ? { ...file, digest: 'f'.repeat(64) } : file) },
      { ...metadata, searchTools: [bash] }, { ...metadata, verifiers: [bash] },
    ]) { await replace(changed); await assert.rejects(writeInstalledGuestToolchain(current.input), /publisher|guest toolchain/); }
    await replace(metadata);
    const result = await writeInstalledGuestToolchain(current.input);
    assert.deepEqual(result.manifest.admittedExecutables, [bash]);
    assert.equal(result.manifest.guestImageByteCount, current.metadata.guestImageByteCount);
    assert(result.manifest.guestImageByteCount <= GUEST_EXTRACTOR_RECIPE.maxImageBytes);
  } finally { await rm(current.directory, { recursive: true, force: true }); }
});
