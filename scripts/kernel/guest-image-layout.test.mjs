// Publisher arithmetic and source wiring only; no ext4/native/install proof.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { guestImageLayout, GUEST_IMAGE_MAX_BYTES } from './guest-image-layout.mjs';

test('compact construction retains every measured byte plus the original reserve at a fixed alignment', () => {
  assert.equal(GUEST_IMAGE_MAX_BYTES, 268_435_456);
  for (const [contentBytes, imageByteCount] of [[1, 33_554_432], [16_777_216, 33_554_432],
    [16_777_217, 50_331_648], [136_000_000, 167_772_160], [251_658_240, 268_435_456]]) {
    const layout = guestImageLayout(contentBytes);
    assert.deepEqual(layout, { profile: 'cliq-guest-image-layout-v1', kind: 'compact', contentBytes,
      reserveBytes: 16_777_216, alignmentBytes: 16_777_216, imageByteCount });
    assert(Object.isFrozen(layout));
  }
});

test('qualification construction keeps the original maximum image without relaxing the complete file budget', () => {
  for (const contentBytes of [1, 136_000_000, 251_658_240]) {
    assert.deepEqual(guestImageLayout(contentBytes, 'qualification_max'), {
      profile: 'cliq-guest-image-layout-v1', kind: 'qualification_max', contentBytes,
      reserveBytes: 16_777_216, alignmentBytes: 16_777_216, imageByteCount: 268_435_456 });
  }
});

test('neither construction profile admits unknown sizes, overflow, reserve changes or arbitrary profiles', () => {
  for (const contentBytes of [0, -1, 1.5, 251_658_241, Number.MAX_SAFE_INTEGER, Infinity, NaN, '4', 4n])
    for (const profile of ['compact', 'qualification_max'])
      assert.throws(() => guestImageLayout(contentBytes, profile), TypeError);
  for (const profile of ['', 'max', 'runtime', 1, ['compact'], new String('compact'), null])
    assert.throws(() => guestImageLayout(4, profile), TypeError);
});

const source = name => readFileSync(new URL(name, import.meta.url), 'utf8');
test('the actual shared builder defaults to compact while only fixed qualification callers select maximum construction', () => {
  const builder = source('./build-linux-guest-toolchain.mjs'), publisher = source('./testing/installed-guest-package.ts');
  const installed = source('./testing/installed-supervisor-package.ts'), journey = source('./testing/installed-node-journey.ts');
  const native = source('./run-linux-guest-verifier-campaign.ts');
  assert(builder.includes("guestImageLayout(totalBytes, extra.length ? 'qualification_max' : 'compact')"));
  assert(builder.includes("extra[0] !== '--qualification-max'"));
  assert(publisher.includes('guestImageLayout(total,'));
  assert(installed.includes("guestImageProfile?: 'qualification_max'"));
  assert(installed.includes("...(options.guestImageProfile ? ['--qualification-max'] : [])"));
  assert(journey.includes("...(journeyKind === 'verifier' ? { guestImageProfile: 'qualification_max' as const } : {})"));
  assert(native.includes("[builder, guestRoot, installationRoot, carrier, '--qualification-max']"));
  assert(!/process\.env/u.test(builder + publisher), 'no environment-driven image construction override');
  assert.equal(installed.match(/process\.env\b/gu)?.length, 1);
  assert.deepEqual(installed.match(/process\.env(?:\.[A-Za-z_$][\w$]*|\[[^\]]*\])/gu),
    ['process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE'], 'the sole environment input is the fixed official archive cache, never size or authority');
  assert(installed.includes('await sea.prepareInstalledSupervisorSeaCarrier(\n    fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE)'));
  const carrier = source('./testing/supervisor-sea-builder.ts');
  const cached = carrier.indexOf('const archive = cachedArchive ? await readFile(cachedArchive)'),
    checksum = carrier.indexOf("assert.equal(createHash('sha256').update(archive).digest('hex'), checksum, 'official carrier checksum mismatch')", cached),
    extraction = carrier.indexOf("run(fixture, 'tar', ['--no-same-owner', '-xJf', archivePath, '-C', fixture])", checksum);
  assert(cached >= 0 && checksum > cached && extraction > checksum, 'cached bytes retain the full pinned checksum before fresh extraction');
  const imageCreation = builder.slice(builder.indexOf('const imageLayout ='), builder.indexOf('const handle = await open(filename'));
  assert.equal((imageCreation.match(/command\('\/usr\/sbin\/mke2fs'/gu) ?? []).length, 1);
  assert(!/catch|while|retry|\.filter\(/u.test(imageCreation), 'capacity failure cannot grow the image or drop files');
});

test('maximum native and full-corpus qualification retain their original workload, safety and scanner limits', () => {
  const native = source('./testing/guest-toolchain-native.ts'), worker = source('../../src/sandbox/testing/worker-runtime.ts');
  const journey = source('./testing/installed-node-journey.ts'), corpus = source('./testing/credential-secret-corpus.ts');
  assert(native.includes('assert.equal(metadata.guestImageByteCount, GUEST_EXTRACTOR_RECIPE.maxImageBytes)'));
  assert(worker.includes('metadata.guestImageByteCount !== GUEST_EXTRACTOR_RECIPE.maxImageBytes'));
  assert(journey.includes('assert.equal(imageCopies.length, 3)'));
  assert(journey.includes('await verifyIndependentDataCopies(imageCopies, imageRef, signed.guestToolchain.manifest.guestImageByteCount)'));
  assert(journey.includes("installedLayout: 'single_cas_streams_v1', manifestSchemaVersion: 2, completeImageCopiesVerified: true"));
  assert(journey.includes("runtime/bundles', bundleDigest, guestImageEntry[0]!.relativePath)), { code: 'ENOENT' }"));
  assert(journey.includes('imageCopies.length * signed.guestToolchain.manifest.guestImageByteCount'));
  assert(journey.includes('maxBytes: 512 * 1024 * 1024, maxStreams: 4096'));
  assert(journey.includes('unchangedCorpusByteLimit: 512 * 1024 * 1024, unchangedCorpusStreamLimit: 4096'));
  assert(corpus.includes('fileLimit = 512 * 1024 * 1024'));
  assert(corpus.includes('const deadline = performance.now() + 60000'));
});
