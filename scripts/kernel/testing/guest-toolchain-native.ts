import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { constants, fstatSync, readdirSync, readlinkSync } from 'node:fs';
import { copyFile, open, readFile, rm, type FileHandle } from 'node:fs/promises';
import { Module } from 'node:module';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { GUEST_EXTRACTOR_RECIPE, type NativeGuestExtractionInput, type NativeGuestExtractorBinding,
  type NativeGuestToolchain } from '../../../src/sandbox/guest-toolchain.js';
import { verifyRuntimeBundle, type RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import type { NativeWorkerBinding } from '../../../src/sandbox/linux-worker.js';

/** Actual signed test extractor, owned complete raw image and real native-owned joins. No StateOwner,
 * release authority, admission proof or child execution is fabricated here. */
export async function qualifyGuestToolchainExtraction(input: { installationRoot: string; guestImageRoot: string }) {
  assert.equal(process.platform, 'linux', 'native guest qualification cannot be skipped');
  const bytes = await readFile(path.join(input.installationRoot, 'linux-guest-extractor.node'));
  const digest = createHash('sha256').update(bytes).digest('hex');
  const keys = generateKeyPairSync('ed25519');
  const bundle: RuntimeBundleManifest = { schemaVersion: 1, bundleVersion: 'actual-guest-extractor-ci-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: 1 }, workerProtocolRange: { min: 1, max: 1 },
    entries: [{ entryId: GUEST_EXTRACTOR_RECIPE.entryId, role: 'platform_helper',
      relativePath: GUEST_EXTRACTOR_RECIPE.relativePath, digest, byteCount: bytes.length, executable: true, version: '1' }],
    structuredArtifacts: [], guestToolchainManifestRefs: [], publisherKeyId: 'actual-guest-extractor-ci', manifestDigest: '', signature: '' };
  const { manifestDigest: _digest, signature: _signature, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  verifyRuntimeBundle(bundle, [{ keyId: bundle.publisherKeyId,
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }]);
  const handles: FileHandle[] = [];
  async function hold(filename: string) {
    const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    handles.push(handle); return handle;
  }
  const jobs = new Set<NativeGuestToolchain>();
  const malformedPath = path.join(input.guestImageRoot, 'guest-open-failure.ext4');
  let malformedCreated = false;
  let image: ReturnType<NativeWorkerBinding['sealImage']> | undefined;
  try {
    const addon = await hold(path.join(input.installationRoot, 'linux-guest-extractor.node'));
    const workerAddon = await hold(path.join(input.installationRoot, 'linux-worker.node'));
    const source = await hold(path.join(input.guestImageRoot, 'guest-toolchain.ext4'));
    const info = await addon.stat();
    assert.ok(info.isFile() && !(info.mode & 0o022)); assert.equal(info.size, bytes.length);
    assert.equal(createHash('sha256').update(await addon.readFile()).digest('hex'), digest);
    const loaded = new Module('cliq-actual-guest-extractor-campaign');
    process.dlopen(loaded, `/proc/self/fd/${addon.fd}`);
    const native = loaded.exports as NativeGuestExtractorBinding;
    assert.equal(native.interfaceVersion, 1); assert.equal(typeof native.begin, 'function');
    const loadedWorker = new Module('cliq-actual-guest-sealer-campaign');
    process.dlopen(loadedWorker, `/proc/self/fd/${workerAddon.fd}`);
    const workerNative = loadedWorker.exports as NativeWorkerBinding;
    assert.equal(workerNative.verifierInterfaceVersion, 1);
    assert.deepEqual(Object.getOwnPropertyDescriptor(workerNative, 'verifierInterfaceVersion'),
      { value: 1, writable: false, enumerable: false, configurable: false }, 'the fixed capability marker is inert read-only data');
    image = workerNative.sealImage(source.fd);
    const sourceIdentity = await source.stat({ bigint: true }), sealedIdentity = fstatSync(image.descriptor(), { bigint: true });
    const assertOriginalDescriptors = async () => {
      const original = await source.stat({ bigint: true }), sealed = fstatSync(image!.descriptor(), { bigint: true });
      for (const key of ['dev', 'ino', 'size', 'mode', 'mtimeNs', 'ctimeNs'] as const) {
        assert.equal(original[key], sourceIdentity[key]); assert.equal(sealed[key], sealedIdentity[key]);
      }
    };
    const raw = await readFile(path.join(input.guestImageRoot, 'guest-toolchain-input.json'));
    assert.ok(raw.length > 0 && raw.length <= 1_048_576);
    const metadata = parseJsonStrict(raw.toString('utf8')) as Record<string, any>;
    assert.equal(metadata.format, 'cliq-guest-toolchain-publisher-input-v1');
    assert.equal(metadata.guestImageByteCount, GUEST_EXTRACTOR_RECIPE.maxImageBytes);
    const request: NativeGuestExtractionInput = { imageDigest: metadata.guestImageDigest,
      imageByteCount: metadata.guestImageByteCount, nodePath: metadata.node.canonicalGuestPath,
      nodeDigest: metadata.node.digest, architecture: 'x86_64',
      pinnedExecutables: [metadata.worker, metadata.shell, metadata.git, metadata.node].map(entry =>
        ({ path: entry.canonicalGuestPath, digest: entry.digest })) };
    async function ready(job: NativeGuestToolchain) {
      const started = performance.now();
      while (!job.pollReady()) {
        assert.ok(performance.now() - started < 10_000, 'actual bounded image extraction must finish');
        await delay(1);
      }
      return job.describe();
    }
    async function close(job: NativeGuestToolchain) {
      const started = performance.now(); await job.close();
      assert.ok(performance.now() - started <= 2_000, 'native extraction close must really join within the existing stop bound');
      jobs.delete(job);
    }
    const begin = (value: NativeGuestExtractionInput, descriptor = image!.descriptor()) => {
      const job = native.begin(descriptor, value); jobs.add(job); return job;
    };
    const successful = begin(request), result = await ready(successful);
    assert.equal(result.imageDigest, request.imageDigest); assert.equal(result.nodePath, request.nodePath);
    assert.equal(result.nodeDigest, request.nodeDigest); assert.ok(result.files.length > 1 && result.files.length <= 32);
    assert.ok(result.files.some(file => file.path === request.nodePath && file.digest === request.nodeDigest));
    assert.ok(result.files.some(file => file.path === '/lib64/ld-linux-x86-64.so.2'));
    assert.equal(new Set(result.files.map(file => file.path)).size, result.files.length);
    for (const file of result.files) {
      const original = metadata.files.find((value: any) => value.path === file.path);
      assert.ok(original, 'every executable mapping must originate in the actual same image');
      assert.equal(file.digest, original.digest); assert.equal(file.byteCount, original.byteCount);
      assert.deepEqual(Object.keys(file).sort(), ['byteCount', 'digest', 'path'], 'the public description cannot leak file descriptors');
    }
    await close(successful); assert.throws(() => successful.describe());
    await assertOriginalDescriptors();
    assert.throws(() => successful.pollReady());
    assert.strictEqual(successful.close(), successful.close(), 'close replay retains the same actual join promise');
    assert.equal((await source.stat()).mode & 0o7777, 0o400, 'the installed CAS input is a protected read-only source');
    const copied = await (async () => {
      const borrowed = await open(path.join(input.guestImageRoot, 'guest-toolchain.ext4'), constants.O_RDONLY | constants.O_NOFOLLOW);
      try { return begin(request, borrowed.fd); } finally { await borrowed.close(); }
    })();
    assert.deepEqual(await ready(copied), result, 'the owned regular source must be copied, hashed and sealed by the real asynchronous owner');
    await close(copied);
    await assertOriginalDescriptors();
    // Exercise an actual libext2fs open failure, not an earlier digest or
    // layout rejection: change only the superblock's measured mount time,
    // preserving layout but invalidating its ext4 metadata checksum. This is
    // an owned malformed-image input, never a signed execution authority.
    await copyFile(path.join(input.guestImageRoot, 'guest-toolchain.ext4'), malformedPath, constants.COPYFILE_EXCL);
    malformedCreated = true;
    const protectedCopy = await open(malformedPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { await protectedCopy.chmod(0o600); } finally { await protectedCopy.close(); }
    const malformedWriter = await open(malformedPath, constants.O_RDWR | constants.O_NOFOLLOW);
    try {
      const byte = Buffer.alloc(1); assert.equal((await malformedWriter.read(byte, 0, 1, 1024 + 44)).bytesRead, 1);
      byte[0] = byte[0]! ^ 1; assert.equal((await malformedWriter.write(byte, 0, 1, 1024 + 44)).bytesWritten, 1);
      await malformedWriter.sync(); await malformedWriter.chmod(0o400);
    } finally { await malformedWriter.close(); }
    const malformed = await hold(malformedPath), malformedHash = createHash('sha256');
    for await (const chunk of malformed.createReadStream({ autoClose: false, start: 0 })) malformedHash.update(chunk);
    const priorDescriptors = new Set(readdirSync('/proc/self/fd'));
    const rejectedOpen = begin({ ...request, imageDigest: malformedHash.digest('hex') }, malformed.fd);
    const borrowedCopies = readdirSync('/proc/self/fd').filter(fd => !priorDescriptors.has(fd)).filter(fd => {
      try { return readlinkSync(`/proc/self/fd/${fd}`) === malformedPath; }
      catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; }
    }).map(Number);
    assert.equal(borrowedCopies.length, 1, 'begin synchronously retains exactly one private source descriptor');
    await assert.rejects(() => ready(rejectedOpen), /guest_ext4_open/u);
    const sentinels: FileHandle[] = [];
    try {
      for (let count = 0; count < 64 && !sentinels.some(handle => handle.fd === borrowedCopies[0]); count++)
        sentinels.push(await open('/dev/null', constants.O_RDONLY | constants.O_NOFOLLOW));
      assert.ok(sentinels.some(handle => handle.fd === borrowedCopies[0]), 'the completed failed task descriptor must really be reused');
      await close(rejectedOpen);
      for (const sentinel of sentinels) assert.equal((await sentinel.stat()).isCharacterDevice(), true,
        'later close cannot consume a descriptor reused after a real filesystem-open failure');
      assert.equal((await malformed.stat()).size, request.imageByteCount);
      await assertOriginalDescriptors();
    } finally { for (const sentinel of sentinels.reverse()) await sentinel.close(); }
    const rejectedCopy = begin({ ...request, imageDigest: '0'.repeat(64) }, source.fd);
    await assert.rejects(async () => ready(rejectedCopy), 'the protected source is still verified against the complete signed image digest');
    await close(rejectedCopy);
    const cancelledCopy = begin(request, source.fd); await close(cancelledCopy);
    assert.throws(() => cancelledCopy.pollReady(), 'cancelled source copying cannot publish an execution owner');
    for (const invalid of [
      { ...request, imageDigest: '0'.repeat(64) },
      { ...request, nodeDigest: '0'.repeat(64) },
      { ...request, pinnedExecutables: request.pinnedExecutables.map((entry, index) => index === 0 ? { ...entry, digest: '0'.repeat(64) } : entry) },
      { ...request, nodePath: '/usr/bin/../bin/node' },
      { ...request, nodePath: '/runtime/cliq-linux-worker' },
      { ...request, imageByteCount: request.imageByteCount - 1 },
      { ...request, pinnedExecutables: [] },
      { ...request, pinnedExecutables: request.pinnedExecutables.filter(entry => entry.path !== request.nodePath) },
      { ...request, pinnedExecutables: [...request.pinnedExecutables, request.pinnedExecutables[0]!] },
      { ...request, pinnedExecutables: Array.from({ length: 33 }, () => request.pinnedExecutables[0]!) },
      { ...request, pinnedExecutables: request.pinnedExecutables.map((entry, index) => index ? entry : { ...entry, path: '/runtime/../runtime/cliq-linux-worker' }) },
      { ...request, descriptor: image.descriptor() },
    ]) {
      let job: NativeGuestToolchain | undefined;
      await assert.rejects(async () => { job = begin(invalid); await ready(job); });
      if (job) await close(job);
    }
    const cancelled = begin(request); await close(cancelled);
    assert.throws(() => cancelled.pollReady(), 'joined cancellation cannot be revived');
    await source.chmod(0o600);
    try { assert.throws(() => native.begin(source.fd, request), 'a writable source cannot enter the installed CAS copy contract'); }
    finally { await source.chmod(0o400); }
    return { scope: 'actual signed extractor, frozen complete raw-ext4, same-image Node/loader/library identity, bounded cancel-and-join only',
      source: 'injected Ed25519 CI test root; not a Cliq release or installed Run qualification',
      imageDigest: request.imageDigest, imageByteCount: request.imageByteCount, mappedFiles: result.files.length,
      mappedBytes: result.files.reduce((sum, file) => sum + file.byteCount, 0),
      filesystemOpenFailureJoined: true, originalDescriptorsPreserved: true, reusedDescriptorPreserved: true, qualified: true };
  } finally {
    let failure: unknown;
    for (const job of jobs) try { await job.close(); } catch (error) { failure ??= error; }
    try { image?.close(); } catch (error) { failure ??= error; }
    for (const handle of handles.reverse()) try { await handle.close(); } catch (error) { failure ??= error; }
    if (malformedCreated) try { await rm(malformedPath); } catch (error) { failure ??= error; }
    if (failure) throw failure;
  }
}
