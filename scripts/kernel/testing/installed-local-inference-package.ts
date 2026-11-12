// Controlled qualification publisher only. Inputs acquire runtime authority
// solely through the ordinary complete signed Bundle and model enrollment.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, sign } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, open, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { assertArtifactRef, sha256Bytes } from '../../../src/kernel/identity.js';
import { decodeLocalModelManifest, type LocalModelManifestV1 } from '../../../src/kernel/local-inference.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { decodeLocalInferenceRuntime } from '../../../src/state/local-inference-runtime.js';
import { joinResourceOperations } from '../../../src/state/errors.js';
import { qualificationPublisherMaterial, type InstalledQualificationPublisher } from '../../../src/state/testing/qualification-publisher.js';

type Source = Readonly<{ filename: string; digest: string; byteCount: number }>;
type CodeSource = Source & Readonly<{ guestPath: string }>;
type Content = Omit<RuntimeBundleManifest['entries'][number], 'digest' | 'byteCount'> & Readonly<{ bytes: Buffer }>;
type ModelInput = Readonly<{
  model: string; architecture: string; claims: LocalModelManifestV1['claims']; tokenizer: Source;
  files: readonly (Source & Readonly<{ canonicalRelativePath: string }>)[];
}>;
const MAX_FILE_BYTES = 268_435_456;
const identityFields = ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const;
function same(a: BigIntStats, b: BigIntStats) { return identityFields.every(field => a[field] === b[field]); }
function sourceSize(source: Source) {
  assertArtifactRef(source.digest);
  assert(path.isAbsolute(source.filename) && Number.isSafeInteger(source.byteCount) && source.byteCount > 0 && source.byteCount <= MAX_FILE_BYTES);
}
async function readSource(source: Source, consume: (bytes: Buffer) => Promise<void>): Promise<void> {
  sourceSize(source);
  const held = await open(source.filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const original = await held.stat({ bigint: true });
    assert(original.isFile() && original.nlink === 1n && original.size === BigInt(source.byteCount) &&
      (original.mode & 0o022n) === 0n && (original.uid === 0n || original.uid === BigInt(process.getuid!())) &&
      same(original, await lstat(source.filename, { bigint: true })));
    const hash = createHash('sha256'), scratch = Buffer.alloc(65_536);
    let offset = 0;
    while (offset < source.byteCount) {
      const count = Math.min(scratch.length, source.byteCount - offset);
      const { bytesRead } = await held.read(scratch, 0, count, offset);
      assert(bytesRead > 0); const bytes = scratch.subarray(0, bytesRead);
      hash.update(bytes); await consume(bytes); offset += bytesRead;
    }
    assert.equal((await held.read(scratch, 0, 1, offset)).bytesRead, 0);
    assert.equal(hash.digest('hex'), source.digest);
    assert(same(original, await held.stat({ bigint: true })) && same(original, await lstat(source.filename, { bigint: true })));
  } finally { await held.close(); }
}
async function codeBytes(source: Source): Promise<Buffer> {
  const parts: Buffer[] = []; await readSource(source, async bytes => { parts.push(Buffer.from(bytes)); });
  return Buffer.concat(parts, source.byteCount);
}
async function copyObject(directory: string, source: Source): Promise<void> {
  const destination = path.join(directory, source.digest);
  const writer = await open(destination, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    let offset = 0;
    await readSource(source, async bytes => {
      let consumed = 0;
      while (consumed < bytes.length) {
        const { bytesWritten } = await writer.write(bytes, consumed, bytes.length - consumed, offset + consumed);
        assert(bytesWritten > 0); consumed += bytesWritten;
      }
      offset += bytes.length;
    });
    await writer.sync(); await writer.chmod(0o400);
  } finally { await writer.close(); }
  // Reopen a genuinely readonly descriptor after the writer has joined.
  await readSource({ ...source, filename: destination }, async () => {});
}
async function syncDirectory(directory: string): Promise<void> {
  const held = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await held.sync(); } finally { await held.close(); }
}

export async function buildInstalledLocalInferencePackage(input: Readonly<{
  fixture: string; publisher: InstalledQualificationPublisher;
  code: readonly CodeSource[]; loaderVersion: string; model: ModelInput;
}>) {
  assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
  const publisher = qualificationPublisherMaterial(input.publisher);
  assert.equal(publisher.releaseKeys.length, 1);
  const keyId = publisher.releaseKeys[0]!.keyId;
  assert(path.isAbsolute(input.fixture) && input.loaderVersion.length > 0);
  const original = await lstat(input.fixture, { bigint: true });
  assert(original.isDirectory() && !original.isSymbolicLink() && (original.mode & 0o7777n) === 0o700n &&
    original.uid === BigInt(process.getuid!()));
  const staging = await mkdtemp(path.join(input.fixture, 'local-inference-build-'));
  await chmod(staging, 0o700);
  const repository = fileURLToPath(new URL('../../../', import.meta.url));
  const bootstrapFile = path.join(staging, 'ollama-local-inference');
  const compiled = spawnSync('musl-gcc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-fno-ident',
    `-ffile-prefix-map=${repository}=.`, '-Wl,--build-id=none', '-s',
    path.join(repository, 'native/linux/cliq-linux-local-inference.c'), '-o', bootstrapFile],
  { cwd: staging, env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, encoding: 'utf8', timeout: 60_000, maxBuffer: 65_536 });
  assert.equal(compiled.error, undefined, 'the actual fixed bootstrap compiler must join');
  assert.equal(compiled.signal, null); assert.equal(compiled.status, 0, 'the actual static bootstrap must compile under original Werror');
  await chmod(bootstrapFile, 0o500);
  const bootstrapInfo = await lstat(bootstrapFile);
  assert(bootstrapInfo.isFile() && !bootstrapInfo.isSymbolicLink() && bootstrapInfo.nlink === 1 &&
    bootstrapInfo.size > 0 && bootstrapInfo.size <= MAX_FILE_BYTES);
  const bootstrapHandle = await open(bootstrapFile, constants.O_RDONLY | constants.O_NOFOLLOW);
  let bootstrap: Buffer;
  try { bootstrap = await bootstrapHandle.readFile(); } finally { await bootstrapHandle.close(); }
  const bootstrapSource = { filename: bootstrapFile, digest: sha256Bytes(bootstrap), byteCount: bootstrapInfo.size };
  assert.deepEqual(await codeBytes(bootstrapSource), bootstrap);
  const contents: Content[] = [{ entryId: 'ollama_local_inference', role: 'local_inference', version: '1',
    relativePath: 'helpers/ollama-local-inference', executable: true, bytes: bootstrap }];
  const required = new Map([
    ['/runtime/bin/ollama', { entryId: 'ollama_local_inference_engine', relativePath: 'local-inference/bin/ollama', version: '0.40.14' }],
    ['/runtime/lib/ollama/llama-server', { entryId: 'ollama_local_inference_llama_server', relativePath: 'local-inference/lib/ollama/llama-server', version: '0.40.14' }],
    ['/lib64/ld-linux-x86-64.so.2', { entryId: 'ollama_local_inference_loader', relativePath: 'local-inference/loader/ld-linux-x86-64.so.2', version: input.loaderVersion }],
  ]);
  const libraries: Array<{ entryId: string; guestPath: string }> = [], byDigest = new Map<string, string>();
  const seen = new Set<string>(), fixedDigests = new Set([bootstrapSource.digest]);
  const sorted = [...input.code].sort((a, b) => Buffer.compare(Buffer.from(a.guestPath), Buffer.from(b.guestPath)));
  // The model files, manifest and independent tokenizer consume real bindings.
  assert(sorted.length + input.model.files.length + 3 <= 32);
  for (const source of sorted) {
    assert(!seen.has(source.guestPath)); seen.add(source.guestPath);
    const fixed = required.get(source.guestPath);
    if (fixed) {
      assert(!fixedDigests.has(source.digest)); fixedDigests.add(source.digest);
      contents.push({ ...fixed, role: 'platform_helper', executable: true, bytes: await codeBytes(source) });
    } else {
      let entryId = byDigest.get(source.digest);
      if (!entryId) {
        entryId = `ollama_local_inference_library_${byDigest.size + 1}`; byDigest.set(source.digest, entryId);
        contents.push({ entryId, role: 'platform_helper', version: '0.40.14', executable: true,
          relativePath: `local-inference/libraries/${byDigest.size}`, bytes: await codeBytes(source) });
      } else await readSource(source, async () => {});
      libraries.push({ entryId, guestPath: source.guestPath });
    }
  }
  assert([...required.keys()].every(name => seen.has(name)));
  assert([...byDigest.keys()].every(digest => !fixedDigests.has(digest)));
  const core = { schemaVersion: 1, format: 'cliq-local-inference-runtime-v1', engineVersion: '0.40.14',
    bootstrapEntryId: 'ollama_local_inference', engineEntryId: 'ollama_local_inference_engine',
    helperEntryId: 'ollama_local_inference_llama_server', loaderEntryId: 'ollama_local_inference_loader', libraries };
  const profile = decodeLocalInferenceRuntime({ ...core, runtimeDigest: canonicalSha256(core) });
  const members = [...new Set(contents.map(entry => sha256Bytes(entry.bytes)))].sort();
  const profileBytes = canonicalJsonBytes(profile);
  contents.push({ entryId: 'ollama_local_inference_runtime', role: 'bundle_object', version: '1',
    relativePath: 'local-inference/runtime.json', executable: false, bytes: profileBytes });
  const root: RuntimeBundleManifest['structuredArtifacts'][number] = { kind: 'local_inference_runtime',
    artifactId: 'ollama_local_inference_runtime', rootEntryId: 'ollama_local_inference_runtime',
    artifactRef: sha256Bytes(profileBytes), semanticDigest: profile.runtimeDigest, memberRefs: members };

  const modelCore = { schemaVersion: 1, format: 'cliq-local-model-manifest-v1', signerKeyId: keyId,
    signatureAlgorithm: 'ed25519', provider: 'ollama', model: input.model.model, architecture: input.model.architecture,
    tokenizerRef: input.model.tokenizer.digest, tokenizerDigest: input.model.tokenizer.digest,
    files: input.model.files.map(file => ({ canonicalRelativePath: file.canonicalRelativePath,
      contentRef: file.digest, contentDigest: file.digest, sizeBytes: file.byteCount })), claims: input.model.claims };
  const modelManifestDigest = canonicalSha256(modelCore);
  const signature = sign(null, Buffer.from(`cliq-local-model-manifest-v1\0${modelManifestDigest}`, 'utf8'), publisher.privateKey);
  const modelManifest = decodeLocalModelManifest({ ...modelCore, signatureRef: sha256Bytes(signature), modelManifestDigest });
  const modelPackageRoot = path.join(staging, 'model-package'), objects = path.join(modelPackageRoot, 'objects');
  await mkdir(modelPackageRoot, { mode: 0o700 }); await mkdir(objects, { mode: 0o700 });
  for (const source of [input.model.tokenizer, ...input.model.files]) await copyObject(objects, source);
  await writeFile(path.join(objects, modelManifest.signatureRef), signature, { flag: 'wx', mode: 0o400 });
  const signatureFile = await open(path.join(objects, modelManifest.signatureRef), constants.O_RDONLY | constants.O_NOFOLLOW);
  try { assert.deepEqual(await signatureFile.readFile(), signature); await signatureFile.sync(); }
  finally { await signatureFile.close(); }
  const modelBytes = canonicalJsonBytes(modelManifest), manifestFile = path.join(modelPackageRoot, 'model-manifest.json');
  await writeFile(manifestFile, modelBytes, { flag: 'wx', mode: 0o400 });
  const manifestHandle = await open(manifestFile, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { assert.deepEqual(await manifestHandle.readFile(), modelBytes); await manifestHandle.sync(); }
  finally { await manifestHandle.close(); }
  await joinResourceOperations([syncDirectory(objects), syncDirectory(modelPackageRoot)]);
  const current = await lstat(input.fixture, { bigint: true });
  // Creating this original staging child legitimately updates directory times.
  assert(original.dev === current.dev && original.ino === current.ino && original.mode === current.mode &&
    original.uid === current.uid && original.gid === current.gid);
  return { contents, root, profile, modelPackageRoot, modelManifest,
    modelManifestRef: sha256Bytes(modelBytes), qualification: false as const };
}
