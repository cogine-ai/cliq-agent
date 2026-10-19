import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { channel } from 'node:diagnostics_channel';
import { constants, fstatSync } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rm, writeFile, type FileHandle } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { rootCertificates } from 'node:tls';
import { Worker } from 'node:worker_threads';

import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, sha256Bytes } from '../kernel/identity.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ARTIFACT_CHUNK_BYTES, ContentAddressedStore } from './cas.js';
import { assertInstalledManagerObservationAvailable, createInstalledRuntime, loadInstalledCredentialPlatform, loadInstalledManagerObserver,
  type HeldInstalledRuntime, withHeldInstalledRuntime } from './installed-runtime.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH } from './native-owner.js';
import { openInstalledLinuxWorkerLauncher } from '../sandbox/linux-worker.js';
import { KernelStorageError } from './errors.js';
import { GUEST_EXTRACTOR_RECIPE } from '../sandbox/guest-toolchain.js';
import { observeInstalledCredentialSupervisor } from './installed-services.js';
import { INSTALLED_WORK_CHANNEL, type InstalledWorkSnapshot } from './installed-work-diagnostics.js';

/** Real signed files for installer/CAS semantics only. The opaque executable
 * entries are deliberately not running Supervisor/worker/addon images and are
 * never spawned or dlopened. They establish no execution qualification. */
async function writeInstallerOnlyPackage(packageRoot: string, unclosedPromptRole?: 'system_prompt' | 'compaction_prompt',
  supervisorBytes?: Buffer, guestImageBytes?: Buffer) {
  await mkdir(packageRoot, { mode: 0o700 });
  const profile = policyProfile();
  const rootCore = {
    schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
    filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'],
    persistent: false, networkConfiguration: 'none',
  };
  const rootRecipe = { ...rootCore, profileDigest: canonicalSha256(rootCore) };
  const contents = [
    { entryId: 'installer-only-supervisor', role: 'supervisor', relativePath: 'supervisor', executable: true,
      bytes: supervisorBytes ?? Buffer.from('installer-only opaque Supervisor bytes; not a runnable image\n') },
    { entryId: 'installer-only-worker', role: 'worker', relativePath: 'workers/worker', executable: true,
      bytes: Buffer.from('installer-only opaque worker bytes; not a runnable image\n') },
    { entryId: STATE_OWNER_NATIVE_ENTRY_ID, role: 'platform_helper', relativePath: STATE_OWNER_NATIVE_RELATIVE_PATH,
      executable: true, bytes: Buffer.from('installer-only opaque addon bytes; not a loadable native module\n') },
    { entryId: 'policy-v1', role: 'policy_engine', relativePath: 'profiles/policy.json', executable: false,
      bytes: canonicalJsonBytes(profile) },
    { entryId: 'default_https_trust_store', role: 'trust_store', relativePath: 'profiles/https-trust.pem', executable: false,
      bytes: Buffer.from(rootCertificates.join('\n')) },
    { entryId: 'installer-only-empty-root', role: 'sandbox_root_profile', relativePath: 'profiles/empty-root.json', executable: false,
      bytes: canonicalJsonBytes(rootRecipe) },
  ];
  if (unclosedPromptRole) contents.push({
    entryId: `installer-only-${unclosedPromptRole}`, role: unclosedPromptRole,
    relativePath: `prompts/${unclosedPromptRole}.txt`, executable: false,
    bytes: Buffer.from(`legitimately signed ${unclosedPromptRole} bytes without a structured root\n`),
  });
  const keys = generateKeyPairSync('ed25519');
  let guestRoot: RuntimeBundleManifest['structuredArtifacts'][number] | undefined;
  let guestManifestRef: string | undefined;
  if (guestImageBytes) {
    // Opaque signed data only: these bytes are neither ext4/ELF nor an
    // executable qualification. The installer must still retain their exact
    // complete signed closure through the real bounded CAS stream.
    const imageRef = sha256Bytes(guestImageBytes);
    const executable = (logicalName: string, canonicalGuestPath: string) => ({ logicalName, canonicalGuestPath,
      version: 'installer-data-only', digest: sha256Bytes(Buffer.from(logicalName)) });
    const core = { schemaVersion: 1, format: 'cliq-guest-toolchain-v1', guestImageRef: imageRef,
      guestImageDigest: imageRef, guestImageByteCount: guestImageBytes.length, guestImageFormat: 'raw-ext4-v1',
      architecture: 'x86_64', kernelAbi: 'linux-x86_64-v1', userspaceAbi: 'linux-x86_64-glibc-v1',
      worker: executable('cliq-worker', '/runtime/cliq-linux-worker'), shell: executable('sh', '/bin/sh'),
      git: executable('git', '/usr/bin/git'), node: executable('node', '/usr/bin/node'),
      searchTools: [], verifiers: [], admittedExecutables: [], publisherKeyId: 'explicit-installer-unit-test-root' };
    const manifestDigest = canonicalSha256(core);
    const signature = sign(null, Buffer.from(`cliq-guest-toolchain-v1\0${manifestDigest}`), keys.privateKey);
    const signatureRef = sha256Bytes(signature);
    const manifestBytes = canonicalJsonBytes({ ...core, manifestDigest, signatureRef });
    guestManifestRef = sha256Bytes(manifestBytes);
    const rootEntryId = 'installer-only-guest-root';
    guestRoot = { kind: 'guest_toolchain', artifactId: 'installer-only-guest', rootEntryId,
      artifactRef: guestManifestRef, semanticDigest: manifestDigest, memberRefs: [imageRef, signatureRef].sort() };
    contents.push({ entryId: rootEntryId, role: 'guest_toolchain', relativePath: 'profiles/guest.json',
      executable: false, bytes: manifestBytes },
    { entryId: GUEST_EXTRACTOR_RECIPE.entryId, role: 'platform_helper', relativePath: GUEST_EXTRACTOR_RECIPE.relativePath,
      executable: true, bytes: Buffer.from('installer-only opaque guest extractor; never loaded\n') },
    ...[{ ref: imageRef, bytes: guestImageBytes }, { ref: signatureRef, bytes: signature }].map(({ ref, bytes }) => ({
      entryId: identityHash('runtime-bundle-object-v1', ref), role: 'bundle_object',
      relativePath: `objects/sha256/${ref.slice(0, 2)}/${ref}`, executable: false, bytes })));
  }
  const entries: RuntimeBundleManifest['entries'] = [];
  for (const { bytes, ...entry } of contents) {
    const filename = path.join(packageRoot, entry.relativePath);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, bytes, { flag: 'wx', mode: entry.executable ? 0o500 : 0o400 });
    entries.push({ ...entry, version: '1', digest: sha256Bytes(bytes), byteCount: bytes.byteLength });
  }
  const bundle: RuntimeBundleManifest = {
    schemaVersion: 1, bundleVersion: 'installer-file-verification-only-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION }, workerProtocolRange: { min: 1, max: 1 },
    entries,
    // The empty-root recipe is an acyclic sandbox_root_profile entry, not
    // resource/permission policy or a new structured-artifact kind. The sole
    // supported structured policy root is self-contained.
    structuredArtifacts: [...(guestRoot ? [guestRoot] : []), { kind: 'policy_engine_profile', artifactId: 'policy-v1', rootEntryId: 'policy-v1',
      artifactRef: canonicalSha256(profile), semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: guestManifestRef ? [guestManifestRef] : [], publisherKeyId: 'explicit-installer-unit-test-root', manifestDigest: '', signature: '',
  };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  const releaseKeys = [{ keyId: bundle.publisherKeyId,
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  verifyRuntimeBundle(bundle, releaseKeys);
  await writeFile(path.join(packageRoot, 'manifest.json'), canonicalJsonBytes(bundle), { flag: 'wx', mode: 0o400 });
  return { bundle, releaseKeys, profile, rootRecipe, contents };
}

test('installed read-only manager observation rejects structural selections before inspecting caller properties', () => {
  let inspected = false;
  const fake = new Proxy({}, { get() { inspected = true; throw new Error('caller property was inspected'); } });
  assert.throws(() => loadInstalledManagerObserver(fake as HeldInstalledRuntime), { code: 'ARTIFACT_MISMATCH' });
  assert.throws(() => assertInstalledManagerObservationAvailable(fake as HeldInstalledRuntime), { code: 'ARTIFACT_MISMATCH' });
  assert.equal(inspected, false);
});

if (process.platform === 'linux') test('installed work measurements count the real complete package and both independent guest copies without changing validation', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-work-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  const diagnostic = channel(INSTALLED_WORK_CHANNEL), observed: InstalledWorkSnapshot[] = [];
  const subscriber = (value: unknown) => { if (typeof value === 'object') observed.push(value as InstalledWorkSnapshot); };
  let selected: HeldInstalledRuntime | undefined;
  try {
    const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61);
    image.fill(0x63, 1_048_576, 2 * 1_048_576); image[image.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installation = await runtime.installInitial({ packageRoot, stateRoot });
    const manifestBytes = canonicalJsonBytes(signed.bundle).length;
    const packageBytes = manifestBytes + signed.contents.reduce((sum, entry) => sum + entry.bytes.length, 0);
    const activeBytes = (await readFile(path.join(stateRoot, 'runtime/active.json'))).length;
    const casRoot = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
    let casBytes = 0;
    for (const name of await readdir(casRoot)) casBytes += (await readFile(path.join(casRoot, name))).length;
    const supervisorBytes = signed.contents.find(entry => entry.role === 'supervisor')!.bytes.length;
    const revalidationBytes = activeBytes + packageBytes + supervisorBytes + casBytes;
    diagnostic.subscribe(subscriber);
    selected = await runtime.openSelected(stateRoot);
    const opened = observed.at(-1)!;
    assert.deepEqual({ ...opened.package, spanElapsedMs: 0 }, { started: 1, completed: 1, bytesRead: packageBytes, spanElapsedMs: 0 });
    assert.deepEqual({ ...opened.revalidate, spanElapsedMs: 0 }, { started: 1, completed: 1, bytesRead: revalidationBytes, spanElapsedMs: 0 });
    await selected.assertHeld();
    assert.equal(observed.at(-1)!.revalidate.bytesRead, revalidationBytes * 2);
    const supervisor = path.join(stateRoot, 'runtime/bundles', installation.bundleDigest, 'supervisor');
    await chmod(supervisor, 0o700); await writeFile(supervisor, 'changed'); await chmod(supervisor, 0o500);
    await assert.rejects(selected.assertHeld(), { code: 'ARTIFACT_MISMATCH' });
    assert.equal(observed.at(-1)!.revalidate.started, 3); assert.equal(observed.at(-1)!.revalidate.completed, 3);
  } finally {
    diagnostic.unsubscribe(subscriber); await selected?.close(); await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') for (const copy of ['bundle', 'cas'] as const) {
  test(`a newly opened selection rejects the last corrupted byte of its independent ${copy} guest image`, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), `cliq-installed-${copy}-tail-`)));
    const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
    let selected: HeldInstalledRuntime | undefined;
    try {
      const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61);
      image.fill(0x63, 1_048_576, 2 * 1_048_576); image[image.length - 1] = 0x7a;
      const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
      const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
      const installation = await runtime.installInitial({ packageRoot, stateRoot }), ref = sha256Bytes(image);
      const entry = signed.bundle.entries.find(value => value.digest === ref)!;
      const installedImage = path.join(stateRoot, 'runtime/bundles', installation.bundleDigest, entry.relativePath);
      const casImage = path.join(stateRoot, KERNEL_CAS_DIRECTORY, ref);
      const installedInfo = await lstat(installedImage), casInfo = await lstat(casImage);
      assert.equal(installedInfo.nlink, 1); assert.equal(casInfo.nlink, 1);
      assert.notEqual(`${installedInfo.dev}:${installedInfo.ino}`, `${casInfo.dev}:${casInfo.ino}`);
      // This owner-controlled corruption precedes openSelected's fresh stat.
      // Refusal must therefore reach the full signed digest, not an old mtime.
      const filename = copy === 'bundle' ? installedImage : casImage;
      await chmod(filename, 0o600);
      const handle = await open(filename, constants.O_WRONLY | constants.O_NOFOLLOW);
      try {
        const { bytesWritten } = await handle.write(Buffer.from([0x62]), 0, 1, image.length - 1);
        assert.equal(bytesWritten, 1); await handle.sync();
      } finally { await handle.close(); }
      await chmod(filename, 0o400);
      assert.deepEqual(await readFile(copy === 'bundle' ? casImage : installedImage), image,
        'the independent original copy remains complete and cannot validate the changed inode');
      await assert.rejects(async () => { selected = await runtime.openSelected(stateRoot); }, error =>
        error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
        error.message === 'installed runtime signed file digest differs');
    } finally { await selected?.close(); await rm(fixture, { recursive: true, force: true }); }
  });
}

if (process.platform === 'linux') test('successive installed borrows re-read every byte while sharing only idle hash threads, and close joins them', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-hash-reuse-')));
  const diagnostic = channel(INSTALLED_WORK_CHANNEL), observed: InstalledWorkSnapshot[] = [];
  const subscriber = (value: unknown) => { if (value && typeof value === 'object') observed.push(value as InstalledWorkSnapshot); };
  const descriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage')!;
  const workers = new Set<Worker>(), exited = new Set<Worker>(), ids = new Set<number>();
  let selected: HeldInstalledRuntime | undefined, other: HeldInstalledRuntime | undefined, armed = false;
  try {
    const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
    const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61);
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    Object.defineProperty(Worker.prototype, 'postMessage', { ...descriptor, value: function (this: Worker, ...args: unknown[]) {
      const message = args[0] as { fd?: number; id?: number } | undefined;
      if (armed && typeof message?.fd === 'number') {
        if (!workers.has(this)) { workers.add(this); this.once('exit', () => exited.add(this)); }
        assert(Number.isSafeInteger(message.id)); assert(!ids.has(message.id!)); ids.add(message.id!);
      }
      return Reflect.apply(descriptor.value, this, args);
    } });
    diagnostic.subscribe(subscriber); armed = true;
    selected = await runtime.openSelected(stateRoot);
    const initial = observed.at(-1)!.revalidate, bytes = initial.bytesRead - observed[0]!.revalidate.bytesRead;
    assert.equal(workers.size, 2); assert.equal(exited.size, 0);
    for (let round = 1; round <= 16; round++) {
      await selected.assertHeld();
      const current = observed.at(-1)!.revalidate;
      assert.equal(current.bytesRead - initial.bytesRead, round * bytes);
      assert.equal(current.completed - initial.completed, round);
      assert.equal(workers.size, 2, 'threads, not results or observations, may be retained');
      assert.equal(exited.size, 0);
    }
    other = await runtime.openSelected(stateRoot);
    assert.equal(workers.size, 4, 'fresh package verification retires the old pool before its standalone scratch');
    assert.equal(exited.size, 2);
    await selected.assertHeld();
    assert.equal(workers.size, 4, 'two live original Scopes share only the current idle executor');
    await selected.close(); selected = undefined;
    assert.equal(exited.size, workers.size, 'idle threads are genuine resources owned until selected close');
    await other.assertHeld();
    assert.equal(workers.size, 6, 'a still-live Scope starts fresh threads after the shared close barrier');
    await other.close(); other = undefined;
    assert.equal(exited.size, workers.size);
  } finally {
    armed = false; diagnostic.unsubscribe(subscriber);
    Object.defineProperty(Worker.prototype, 'postMessage', descriptor);
    await other?.close(); await selected?.close(); await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') test('a cancelled original revalidation job joins before selected close and a fresh selection verifies all image bytes', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-image-cancel-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  const diagnostic = channel(INSTALLED_WORK_CHANNEL), abort = new AbortController();
  const reason = new Error('complete image verification cancelled');
  let selected: HeldInstalledRuntime | undefined, reopened: HeldInstalledRuntime | undefined;
  let closing: Promise<void> | undefined, armed = false, scheduled = false;
  let baselineStarted = 0, initialReadBase: number | undefined, last: InstalledWorkSnapshot | undefined;
  const subscriber = (value: unknown) => {
    if (!value || typeof value !== 'object') return;
    last = value as InstalledWorkSnapshot;
    initialReadBase ??= last.revalidate.bytesRead;
    if (armed && !scheduled && last.revalidate.started > baselineStarted) {
      scheduled = true;
      // The real original job is registered, not a fabricated I/O owner. This
      // checks entry cancellation/close, not an in-flight pread fault seam.
      abort.abort(reason); closing = selected!.close();
    }
  };
  try {
    const image = Buffer.alloc(3 * 1_048_576 + 17, 0x61);
    image.fill(0x63, 1_048_576, 2 * 1_048_576); image[image.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    diagnostic.subscribe(subscriber);
    selected = await runtime.openSelected(stateRoot);
    const opened = last!;
    const completeBytes = opened.revalidate.bytesRead - initialReadBase!;
    baselineStarted = opened.revalidate.started; armed = true;
    let borrowed = false;
    await assert.rejects(withHeldInstalledRuntime(selected, async () => { borrowed = true; }, abort.signal), error => error === reason);
    assert.equal(borrowed, false, 'a cancelled prefix is not a successful verified borrow');
    assert.equal(scheduled, true);
    await closing;
    assert.equal(last!.revalidate.started, opened.revalidate.started + 1);
    assert.equal(last!.revalidate.completed, opened.revalidate.completed + 1);
    armed = false;
    const beforeReopen = last!;
    reopened = await runtime.openSelected(stateRoot);
    assert.equal(last!.revalidate.bytesRead - beforeReopen.revalidate.bytesRead, completeBytes,
      'a fresh selection repeats the entire original bundle and independent CAS image');
    await reopened.assertHeld();
    assert.equal(last!.revalidate.bytesRead - beforeReopen.revalidate.bytesRead, completeBytes * 2);
  } finally {
    armed = false; diagnostic.unsubscribe(subscriber);
    await closing; await reopened?.close(); await selected?.close();
    await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') test('selected close waits for a submitted real image read to deliver after cancellation', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-image-read-join-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined, reopened: HeldInstalledRuntime | undefined;
  let verification: Promise<void> | undefined, closing: Promise<void> | undefined;
  let prototype: object | undefined, readDescriptor: PropertyDescriptor | undefined;
  let captured: FileHandle | undefined, closeDescriptor: PropertyDescriptor | undefined;
  let releaseDelivery!: () => void, actualReturned!: (bytesRead: number) => void;
  const delivery = new Promise<void>(resolve => { releaseDelivery = resolve; });
  const returned = new Promise<number>(resolve => { actualReturned = resolve; });
  const diagnostic = channel(INSTALLED_WORK_CHANNEL);
  let initialReadBase: number | undefined, observed: InstalledWorkSnapshot | undefined;
  const subscriber = (value: unknown) => {
    if (!value || typeof value !== 'object') return;
    observed = value as InstalledWorkSnapshot; initialReadBase ??= observed.revalidate.bytesRead;
  };
  let reads = 0, closeAttempts = 0, verificationSettled = false, closeSettled = false, borrowed = false;
  const restore = () => {
    if (prototype && readDescriptor) Object.defineProperty(prototype, 'read', readDescriptor);
    if (captured && closeDescriptor) Object.defineProperty(captured, 'close', closeDescriptor);
  };
  try {
    const image = Buffer.alloc(3 * 1_048_576 + 17, 0x61);
    image.fill(0x63, 1_048_576, 2 * 1_048_576); image[image.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installation = await runtime.installInitial({ packageRoot, stateRoot });
    diagnostic.subscribe(subscriber);
    selected = await runtime.openSelected(stateRoot);
    const completeBytes = observed!.revalidate.bytesRead - initialReadBase!;
    const imageRef = sha256Bytes(image), entry = signed.bundle.entries.find(value => value.digest === imageRef)!;
    const filename = path.join(stateRoot, 'runtime/bundles', installation.bundleDigest, entry.relativePath);
    const expected = await lstat(filename, { bigint: true });
    const probe = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { prototype = Object.getPrototypeOf(probe); }
    finally { await probe.close(); }
    readDescriptor = Object.getOwnPropertyDescriptor(prototype!, 'read')!;
    const originalRead = readDescriptor.value as FileHandle['read'];
    Object.defineProperty(prototype!, 'read', { ...readDescriptor, value: function (this: FileHandle, ...args: unknown[]) {
      // Complete every potentially throwing identity/descriptor check before
      // submitting I/O, so a test observer failure cannot orphan a real read.
      const actual = fstatSync(this.fd, { bigint: true });
      if (actual.dev !== expected.dev || actual.ino !== expected.ino || ++reads !== 2)
        return Reflect.apply(originalRead, this, args);
      captured = this;
      closeDescriptor = Object.getOwnPropertyDescriptor(this, 'close')!;
      assert(closeDescriptor?.configurable && typeof closeDescriptor.value === 'function');
      const originalClose = closeDescriptor.value as FileHandle['close'];
      Object.defineProperty(this, 'close', { ...closeDescriptor, value: function (this: FileHandle, ...closeArgs: unknown[]) {
        closeAttempts++; return Reflect.apply(originalClose, this, closeArgs);
      } });
      // Now the original genuine FileHandle submits the real system I/O. Its
      // unchanged result promise is immediately owned by the returned chain.
      const result = Reflect.apply(originalRead, this, args) as ReturnType<FileHandle['read']>;
      return result.then(async value => {
        // The OS read has already returned. Only JS delivery is delayed; this
        // is explicitly not a physical slow-disk or stalled-kernel fixture.
        actualReturned(value.bytesRead); await delivery; return value;
      });
    } });
    const abort = new AbortController(), reason = new Error('submitted image read cancelled');
    verification = withHeldInstalledRuntime(selected, async () => { borrowed = true; }, abort.signal);
    void verification.then(() => { verificationSettled = true; }, () => { verificationSettled = true; });
    assert((await Promise.race([returned, verification.then(() => { throw new Error('real image read was not observed'); })])) > 0);
    abort.abort(reason); closing = selected.close();
    void closing.then(() => { closeSettled = true; }, () => { closeSettled = true; });
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(verificationSettled, false, 'the submitted original read has not delivered');
    assert.equal(closeAttempts, 0, 'the original FileHandle must not close before its read delivers');
    assert.equal(closeSettled, false);
    releaseDelivery();
    await assert.rejects(verification, error => error === reason); await closing;
    assert.equal(borrowed, false);
    assert.equal(closeAttempts, 1, 'the original image descriptor retires once, after the read joins');
    restore();
    const beforeReopen = observed!.revalidate.bytesRead;
    reopened = await runtime.openSelected(stateRoot);
    assert.equal(observed!.revalidate.bytesRead - beforeReopen, completeBytes);
    await reopened.assertHeld();
    assert.equal(observed!.revalidate.bytesRead - beforeReopen, completeBytes * 2);
  } finally {
    releaseDelivery();
    await Promise.allSettled([...(verification ? [verification] : []), ...(closing ? [closing] : [])]);
    restore();
    await reopened?.close(); await selected?.close();
    diagnostic.unsubscribe(subscriber);
    await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') for (const laneCount of [2, 4] as const) test(`discard batches join all ${laneCount} actual hash Workers before original image FDs close`, async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-hash-exit-')));
  let selected: HeldInstalledRuntime | undefined, reopened: HeldInstalledRuntime | undefined;
  let checking: Promise<void> | undefined, closing: Promise<void> | undefined;
  let prototype: object | undefined, statDescriptor: PropertyDescriptor | undefined;
  const postDescriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage')!;
  const actual = new Map<number, FileHandle>(), workers = new Set<Worker>(), exited = new Set<Worker>();
  const closes = new Map<FileHandle, { descriptor: PropertyDescriptor; attempts: number }>();
  const delayed: Array<{ worker: Worker; args: unknown[] }> = [];
  let armed = false, borrowed = false, earlyClose = false, firstReply = false, ready!: () => void;
  const abort = new AbortController(), reason = new Error('owned parallel verification cancelled');
  const bothClosing = new Promise<void>(resolve => { ready = resolve; });
  const release = () => { for (const job of delayed.splice(0)) Reflect.apply(postDescriptor.value, job.worker, job.args); };
  const restore = () => {
    Object.defineProperty(Worker.prototype, 'postMessage', postDescriptor);
    if (prototype && statDescriptor) Object.defineProperty(prototype, 'stat', statDescriptor);
    for (const [handle, value] of closes) Object.defineProperty(handle, 'close', value.descriptor);
  };
  try {
    const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
    const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61); image[image.length - 1] = 0x7a;
    const supervisor = laneCount === 4 ? Buffer.alloc(8 * 1_048_576 + 31, 0x73) : undefined;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, supervisor, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    const probe = await open(path.join(stateRoot, 'runtime/active.json'), constants.O_RDONLY | constants.O_NOFOLLOW);
    try { prototype = Object.getPrototypeOf(probe); } finally { await probe.close(); }
    statDescriptor = Object.getOwnPropertyDescriptor(prototype!, 'stat')!;
    Object.defineProperty(prototype!, 'stat', { ...statDescriptor, value: function (this: FileHandle, ...args: unknown[]) {
      if (armed) actual.set(this.fd, this);
      return Reflect.apply(statDescriptor!.value, this, args);
    } });
    Object.defineProperty(Worker.prototype, 'postMessage', { ...postDescriptor, value: function (this: Worker, ...args: unknown[]) {
      const message = args[0] as { fd?: number; kind?: string } | undefined;
      if (typeof message?.fd === 'number') {
        if (!workers.has(this)) { workers.add(this); this.once('exit', () => exited.add(this)); }
      }
      if (armed && typeof message?.fd === 'number') {
        if (!firstReply) {
          firstReply = true;
          // Cancel only after an original Worker has returned its actual hash
          // packet. No bytes/syscall/positive proof are fabricated or paused.
          this.prependOnceListener('message', () => abort.abort(reason));
        }
        const handle = actual.get(message.fd); assert(handle, 'the real original parent FileHandle preceded dispatch');
        if (!closes.has(handle)) {
          const descriptor = Object.getOwnPropertyDescriptor(handle, 'close')!;
          const record = { descriptor, attempts: 0 }; closes.set(handle, record);
          Object.defineProperty(handle, 'close', { ...descriptor, value: function (this: FileHandle, ...closeArgs: unknown[]) {
            record.attempts++; if ([...workers].some(worker => !exited.has(worker))) earlyClose = true;
            return Reflect.apply(descriptor.value, this, closeArgs);
          } });
        }
      }
      if (armed && workers.has(this) && message?.kind === 'close') {
        // Real hashing has completed; delay only JS delivery of shutdown to
        // the original Worker. This does not claim physically blocked I/O.
        delayed.push({ worker: this, args }); if (delayed.length === laneCount) ready(); return;
      }
      return Reflect.apply(postDescriptor.value, this, args);
    } });
    selected = await runtime.openSelected(stateRoot); armed = true;
    checking = withHeldInstalledRuntime(selected, async () => { borrowed = true; }, abort.signal);
    await Promise.race([bothClosing, checking.then(() => { throw new Error('actual hash Workers were not observed'); })]);
    assert.equal(workers.size, laneCount); assert.equal(exited.size, 0);
    abort.abort(reason); closing = selected.close(); await new Promise<void>(resolve => setImmediate(resolve));
    assert([...closes.values()].every(value => value.attempts === 0));
    release(); await assert.rejects(checking, error => error === reason); await closing;
    assert.equal(borrowed, false); assert.equal(earlyClose, false); assert.equal(exited.size, laneCount);
    assert([...closes.values()].every(value => value.attempts === 1));
    armed = false; restore(); reopened = await runtime.openSelected(stateRoot); await reopened.assertHeld();
  } finally {
    armed = false; release(); await Promise.allSettled([...(checking ? [checking] : []), ...(closing ? [closing] : [])]);
    restore(); await reopened?.close(); await selected?.close(); await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') for (const fault of ['nonplain', 'unsolicited_cancelled', 'undefined_dispatch'] as const) {
  test(`actual hash Worker ${fault} refuses verification, joins, and cannot clear its failure`, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-hash-refusal-')));
    let selected: HeldInstalledRuntime | undefined, armed = false, injected = false, borrowed = false;
    const descriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage')!;
    const workers = new Set<Worker>(), exited = new Set<Worker>();
    try {
      const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
      const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61); image[image.length - 1] = 0x7a;
      const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
      const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
      await runtime.installInitial({ packageRoot, stateRoot }); selected = await runtime.openSelected(stateRoot);
      Object.defineProperty(Worker.prototype, 'postMessage', { ...descriptor, value: function (this: Worker, ...args: unknown[]) {
        const message = args[0] as { fd?: number } | undefined;
        if (armed && typeof message?.fd === 'number') {
          if (!workers.has(this)) { workers.add(this); this.once('exit', () => exited.add(this)); }
          if (!injected) {
            injected = true;
            if (fault === 'undefined_dispatch') throw undefined;
            // Only alter a genuine child's returned inert packet. No positive
            // proof/Worker/FD is fabricated and no private runtime export exists.
            this.prependOnceListener('message', (reply: { code: string; digest?: string }) => {
              if (fault === 'nonplain') Object.setPrototypeOf(reply, null);
              else { reply.code = 'cancelled'; delete reply.digest; }
            });
          }
        }
        return Reflect.apply(descriptor.value, this, args);
      } });
      armed = true;
      let rejected = false, reason: unknown;
      await withHeldInstalledRuntime(selected, async () => { borrowed = true; }).then(
        () => undefined, error => { rejected = true; reason = error; });
      assert.equal(injected, true); assert.equal(rejected, true); assert.equal(borrowed, false);
      assert.equal(exited.size, workers.size, 'every observed real thread exited before rejection returned');
      if (fault === 'undefined_dispatch') assert.equal(reason, undefined);
      else assert(reason instanceof KernelStorageError && reason.code === 'ARTIFACT_MISMATCH');
      const before = workers.size; rejected = false;
      await selected.assertHeld().then(() => undefined, error => { rejected = true; assert.equal(error, reason); });
      assert.equal(rejected, true); assert.equal(workers.size, before, 'sticky failure never silently starts replacement work');
    } finally {
      armed = false; Object.defineProperty(Worker.prototype, 'postMessage', descriptor);
      await selected?.close(); await rm(fixture, { recursive: true, force: true });
    }
  });
}

if (process.platform === 'linux') for (const fault of ['idle_exit', 'idle_exit_close', 'stale_reply'] as const) {
  test(`an actual idle hash Worker ${fault} is retained as a failure, never silently replaced`, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-hash-idle-failure-')));
    const descriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage')!;
    const workers = new Set<Worker>(), exited = new Set<Worker>();
    let selected: HeldInstalledRuntime | undefined, packet: unknown, original: Worker | undefined;
    try {
      const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
      const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, Buffer.alloc(8 * 1_048_576 + 17, 0x61));
      const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
      await runtime.installInitial({ packageRoot, stateRoot });
      Object.defineProperty(Worker.prototype, 'postMessage', { ...descriptor, value: function (this: Worker, ...args: unknown[]) {
        const message = args[0] as { fd?: number } | undefined;
        if (typeof message?.fd === 'number' && !workers.has(this)) {
          workers.add(this); this.once('exit', () => exited.add(this));
          if (!original) { original = this; this.once('message', reply => { packet = structuredClone(reply); }); }
        }
        return Reflect.apply(descriptor.value, this, args);
      } });
      selected = await runtime.openSelected(stateRoot);
      assert(original && packet); assert.equal(workers.size, 2); assert.equal(exited.size, 0);
      if (fault !== 'stale_reply') await original.terminate();
      else {
        // Replay only an already returned inert packet from this real Worker.
        // This malicious negative response creates no positive authority/proof.
        original.emit('message', packet);
      }
      if (fault === 'idle_exit_close') {
        await assert.rejects(selected.close(), { code: 'ARTIFACT_MISMATCH' }); selected = undefined;
        assert.equal(exited.size, workers.size, 'close reports the original idle failure after every actual exit');
        return;
      }
      let borrowed = false;
      await assert.rejects(withHeldInstalledRuntime(selected, async () => { borrowed = true; }), { code: 'ARTIFACT_MISMATCH' });
      assert.equal(borrowed, false); assert.equal(workers.size, 2);
      assert.equal(exited.size, workers.size, 'all original threads actually exit before refusal');
      await assert.rejects(selected.assertHeld(), { code: 'ARTIFACT_MISMATCH' });
      assert.equal(workers.size, 2, 'the failed selection cannot transparently start a replacement executor');
    } finally {
      Object.defineProperty(Worker.prototype, 'postMessage', descriptor);
      await selected?.close(); await rm(fixture, { recursive: true, force: true });
    }
  });
}

if (process.platform === 'linux') test('readiness hints cannot outlive a genuine selected runtime close', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-readiness-close-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined;
  try {
    const signed = await writeInstallerOnlyPackage(packageRoot);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    selected = await runtime.openSelected(stateRoot);
    // This is only a genuine held-selection lifetime/metadata gate. Opaque
    // fixture executables are never loaded or treated as manager readiness.
    assert.doesNotThrow(() => assertInstalledManagerObservationAvailable(selected!));
    const closing = selected.close();
    assert.throws(() => assertInstalledManagerObservationAvailable(selected!), {
      code: 'ARTIFACT_MISMATCH', message: 'installed runtime handle is closed'
    });
    await closing;
    assert.throws(() => assertInstalledManagerObservationAvailable(selected!), { code: 'ARTIFACT_MISMATCH' });
    selected = undefined;
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
  } finally { await selected?.close(); await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux' && process.arch === 'x64') test('ordinary installed manager observation requires its actual signed addon without granting credential authority', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-manager-observer-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined;
  try {
    // Genuine signed installation, deliberately without a native platform.
    // No successful manager observation or native qualification is asserted.
    const signed = await writeInstallerOnlyPackage(packageRoot);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    selected = await runtime.openSelected(stateRoot);
    const noPlatform = (error: unknown) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
      error.message === 'fixed signed credential platform module is missing';
    // This must reach the actual signed-entry check, not the unrelated SEA
    // credential-authority gate that formerly rejected every ordinary client.
    await assert.rejects(loadInstalledManagerObserver(selected), noPlatform);
    await assert.rejects(observeInstalledCredentialSupervisor(selected), noPlatform);
    await assert.rejects(observeInstalledCredentialSupervisor(selected, true), { code: 'UNSUPPORTED_PLATFORM' });
    await assert.rejects(loadInstalledCredentialPlatform(selected), { code: 'UNSUPPORTED_PLATFORM' });
    const copy = { ...selected };
    assert.throws(() => loadInstalledManagerObserver(copy), { code: 'ARTIFACT_MISMATCH' });
    await selected.close(); selected = undefined;
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
  } finally { await selected?.close(); await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux') test('initial installation streams a complete signed guest image across the unchanged CAS chunk bound', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-guest-stream-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  try {
    const image = Buffer.alloc(ARTIFACT_CHUNK_BYTES + 17, 0x61);
    image.fill(0x62, ARTIFACT_CHUNK_BYTES); image[image.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installed = await runtime.installInitial({ packageRoot, stateRoot });
    const imageRef = sha256Bytes(image);
    const entry = signed.bundle.entries.find(entry => entry.digest === imageRef)!;
    const installedFile = path.join(stateRoot, 'runtime/bundles', installed.bundleDigest, entry.relativePath);
    const cas = new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY));
    assert.deepEqual(await readFile(installedFile), image);
    assert.deepEqual(await cas.verify(imageRef), { ref: imageRef, byteLength: image.length });
    assert.deepEqual(await cas.read(imageRef), image);
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, 'runtime/state-owner.lock')), { code: 'ENOENT' });
    await rm(packageRoot, { recursive: true });
    const selected = await runtime.openSelected(stateRoot);
    try {
      await selected.assertHeld();
      assert.deepEqual(selected.bundle, signed.bundle);
      assert.deepEqual(await cas.read(imageRef), image);
    } finally { await selected.close(); }
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux') test('initial installation retains the complete signed package and CAS roots independently of its source, without owning state', async () => {
  // Resolve macOS's /var alias so the fixture itself never requires a symlink
  // traversal. The StateRoot does not exist before the initial installer call.
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-runtime-first-')));
  await chmod(fixture, 0o700);
  const packageRoot = path.join(fixture, 'package');
  const stateRoot = path.join(fixture, 'state');
  try {
    // Exercise complete streaming copy/hash and a partial final batch using opaque
    // signed data, never an executable or installed execution qualification.
    const supervisorBytes = Buffer.alloc(2 * 1_048_576 + 17, 0x61);
    supervisorBytes.fill(0x63, 1_048_576, 2 * 1_048_576);
    supervisorBytes[supervisorBytes.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, supervisorBytes);
    // This factory seam is trusted composition, not a client key/path override.
    // The final SEA bootstrap supplies its compiled-in root; this file does not
    // claim to qualify that entry, actual process images or native execution.
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const bundleBytes = canonicalJsonBytes(signed.bundle);
    const bundleDigest = sha256Bytes(bundleBytes);
    assert.notEqual(bundleDigest, signed.bundle.manifestDigest, 'complete-byte and semantic digest domains are distinct');
    assert.deepEqual(await runtime.installInitial({ packageRoot, stateRoot }), {
      bundleDigest, manifestDigest: signed.bundle.manifestDigest,
    });

    const installation = path.join(stateRoot, 'runtime', 'bundles', bundleDigest);
    const uid = process.geteuid!();
    for (const directory of [stateRoot, path.join(stateRoot, 'runtime'), path.join(stateRoot, KERNEL_CAS_DIRECTORY),
      path.join(stateRoot, 'runtime', 'bundles'), installation]) {
      const metadata = await lstat(directory);
      assert(metadata.isDirectory());
      assert.equal(metadata.uid, uid);
      assert.equal(metadata.mode & 0o7777, 0o700);
    }
    const activePath = path.join(stateRoot, 'runtime', 'active.json');
    const active = await lstat(activePath);
    assert(active.isFile());
    assert.equal(active.uid, uid);
    assert.equal(active.nlink, 1);
    assert.equal(active.mode & 0o7777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(activePath, 'utf8')), { schemaVersion: 1, bundleDigest });
    assert.deepEqual(await readFile(path.join(installation, 'manifest.json')), bundleBytes);
    assert.equal((await lstat(path.join(installation, 'manifest.json'))).mode & 0o7777, 0o400);
    const bootstrapPath = path.join(stateRoot, 'runtime', 'bootstrap');
    const bootstrap = await lstat(bootstrapPath);
    assert(bootstrap.isFile());
    assert.equal(bootstrap.uid, uid);
    assert.equal(bootstrap.nlink, 1);
    assert.equal(bootstrap.mode & 0o7777, 0o500);
    assert.deepEqual(await readFile(bootstrapPath), signed.contents.find(entry => entry.role === 'supervisor')!.bytes);
    for (const entry of signed.contents) {
      const filename = path.join(installation, entry.relativePath);
      const metadata = await lstat(filename);
      assert(metadata.isFile());
      assert.equal(metadata.uid, uid);
      assert.equal(metadata.nlink, 1);
      assert.equal(metadata.mode & 0o7777, entry.executable ? 0o500 : 0o400);
      assert.deepEqual(await readFile(filename), entry.bytes);
    }

    const cas = new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY));
    for (const bytes of [bundleBytes, canonicalJsonBytes(signed.profile), canonicalJsonBytes(signed.rootRecipe)]) {
      const ref = sha256Bytes(bytes);
      assert.deepEqual(await cas.read(ref), bytes);
      assert.deepEqual(await cas.verify(ref), { ref, byteLength: bytes.byteLength });
    }
    const assertNoStateOwner = async () => {
      await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
      await assert.rejects(lstat(path.join(stateRoot, 'runtime', 'state-owner.lock')), { code: 'ENOENT' });
    };
    await assertNoStateOwner();
    const selected = await runtime.openSelected(stateRoot);
    try {
      assert.equal(selected.bundleDigest, bundleDigest);
      assert.deepEqual(selected.bundle, signed.bundle);
      await selected.assertHeld();
      let observed = 0;
      const untrusted = () => { observed++; throw new Error('untrusted anchor property'); };
      const proxy = new Proxy({}, { get: untrusted, getPrototypeOf: untrusted, ownKeys: untrusted,
        getOwnPropertyDescriptor: untrusted });
      const anchorShape = { assertHeld() {}, close() {} };
      for (const anchor of [undefined, {}, proxy, { ...anchorShape }, structuredClone({})]) {
        // The selection is genuine but these anchors are not. Refusal must
        // precede dlopen of this deliberately opaque installer-only package.
        await assert.rejects(() => openInstalledLinuxWorkerLauncher(selected, anchor as never),
          error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
            error.message === 'installed anchor does not belong to this exact held selection');
      }
      for (const copy of [{ ...selected }, structuredClone({ bundle: selected.bundle, bundleDigest: selected.bundleDigest })]) {
        await assert.rejects(() => openInstalledLinuxWorkerLauncher(copy as never, proxy as never),
          error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
            error.message === 'installed runtime is not a verified held selection');
      }
      assert.equal(observed, 0);
      await rm(packageRoot, { recursive: true });
      await selected.assertHeld();
    } finally { await selected.close(); }
    const reopened = await runtime.openSelected(stateRoot);
    try {
      assert.equal(reopened.bundleDigest, bundleDigest);
      assert.deepEqual(reopened.bundle, signed.bundle);
      await reopened.assertHeld();
    } finally { await reopened.close(); }
    await assertNoStateOwner();
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
else test('unsupported platforms refuse trusted installed-runtime construction without writing a StateRoot', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-runtime-unsupported-')));
  await chmod(fixture, 0o700);
  const packageRoot = path.join(fixture, 'package');
  const stateRoot = path.join(fixture, 'state');
  try {
    const signed = await writeInstallerOnlyPackage(packageRoot);
    const manifestBefore = await readFile(path.join(packageRoot, 'manifest.json'));
    // A real unsupported-platform contract, not a skipped Linux success case.
    // Construction refuses before returning install/open authority or doing IO.
    assert.throws(() => createInstalledRuntime({ releaseKeys: signed.releaseKeys }), { code: 'UNSUPPORTED_PLATFORM' });
    await assert.rejects(lstat(stateRoot), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, 'runtime', 'active.json')), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
    assert.deepEqual(await readFile(path.join(packageRoot, 'manifest.json')), manifestBefore);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux') test('initial installation rejects corruption at the end of a large signed entry before creating StateRoot', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-runtime-tail-')));
  await chmod(fixture, 0o700);
  const packageRoot = path.join(fixture, 'package');
  const stateRoot = path.join(fixture, 'state');
  try {
    const bytes = Buffer.alloc(2 * 1_048_576 + 17, 0x61);
    bytes.fill(0x63, 1_048_576, 2 * 1_048_576);
    bytes[bytes.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, bytes);
    const filename = path.join(packageRoot, 'supervisor');
    const corrupt = Buffer.from(bytes);
    corrupt[corrupt.length - 1] = 0x62;
    await chmod(filename, 0o700);
    await writeFile(filename, corrupt);
    await chmod(filename, 0o500);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await assert.rejects(runtime.installInitial({ packageRoot, stateRoot }), error =>
      error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
      error.message === 'installed runtime signed file digest differs');
    await assert.rejects(lstat(stateRoot), { code: 'ENOENT' });
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux') for (const role of ['system_prompt', 'compaction_prompt'] as const) {
  test(`initial installation rejects a signed ${role} entry without a supported structured closure before creating StateRoot`, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), `cliq-installed-runtime-${role}-`)));
    await chmod(fixture, 0o700);
    const packageRoot = path.join(fixture, 'package');
    const stateRoot = path.join(fixture, 'state');
    try {
      // All entry bytes, counts and the full manifest are honestly signed. The
      // unchanged sole-policy graph cannot authorize this additional root.
      const signed = await writeInstallerOnlyPackage(packageRoot, role);
      const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
      await assert.rejects(runtime.installInitial({ packageRoot, stateRoot }), { code: 'ARTIFACT_MISMATCH' });
      await assert.rejects(lstat(stateRoot), { code: 'ENOENT' });
    } finally { await rm(fixture, { recursive: true, force: true }); }
  });
}
