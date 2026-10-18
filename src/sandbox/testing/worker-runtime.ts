import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, copyFile, mkdir, open, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { KERNEL_STATE_SCHEMA_VERSION } from '../../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { identityHash, sha256Bytes } from '../../kernel/identity.js';
import type { GuestToolchainManifest, SandboxProfileV1 } from '../../kernel/execution.js';
import { parseJsonStrict } from '../../kernel/json.js';
import type { RunAssemblyV1, ToolContractManifestV1 } from '../../kernel/types.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_PATH, STATE_OWNER_NATIVE_RELATIVE_PATH } from '../../state/native-owner.js';
import { LINUX_WORKER_RECIPE } from '../linux-worker.js';
import { OFFLINE_MODEL_TRUST_STORE_PEM } from '../../state/testing/tool-authority.js';
import { decodeGuestToolchainManifest } from '../../state/guest-toolchain.js';
import { GUEST_EXTRACTOR_RECIPE } from '../guest-toolchain.js';

async function actualFileDigest(filename: string, expectedBytes: number) {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size !== BigInt(expectedBytes) || before.mode & 0o022n) throw new Error('campaign image is not protected complete regular data');
    const hash = createHash('sha256'); let count = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false, start: 0 })) { hash.update(chunk); count += chunk.length; }
    const after = await handle.stat({ bigint: true });
    if (count !== expectedBytes || ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'mtimeNs', 'ctimeNs'].some(key =>
      before[key as keyof typeof before] !== after[key as keyof typeof after])) throw new Error('campaign image changed while hashing');
    return hash.digest('hex');
  } finally { await handle.close(); }
}

/** Actual built worker/controller/edit/bwrap/addon bytes under an explicitly
 * injected CI Ed25519 test root. This is not a Cliq release signature, an
 * installed-provider qualification, or a containment success receipt. */
export async function signedLinuxWorkerTestRuntime(input: {
  installationRoot: string; assembly: RunAssemblyV1; tools: ToolContractManifestV1['entries']; sandboxProfile: SandboxProfileV1;
  guestImageRoot?: string;
}) {
  if (process.platform !== 'linux') throw new Error('actual Linux worker image fixtures require Linux');
  if (input.tools.length !== 1 || input.tools[0]?.name !== 'edit' || input.tools[0].execution.kind !== 'builtin') {
    throw new Error('this campaign admits only the existing builtin edit contract');
  }
  const entries: RuntimeBundleManifest['entries'] = [];
  const fromBytes = (entryId: string, role: string, relativePath: string, bytes: Buffer, executable: boolean, version = '1') => {
    const entry = { entryId, role, relativePath, digest: sha256Bytes(bytes), byteCount: bytes.byteLength, executable, version };
    entries.push(entry); return entry;
  };
  for (const [id, role, filename] of [
    [LINUX_WORKER_RECIPE.nativeModuleId, 'platform_helper', 'linux-worker.node'],
    [LINUX_WORKER_RECIPE.launcherId, 'platform_helper', 'cliq-linux-worker-controller'],
    [LINUX_WORKER_RECIPE.bubblewrapId, 'platform_helper', 'cliq-linux-bubblewrap'],
    [LINUX_WORKER_RECIPE.workerId, 'worker', 'cliq-linux-worker'],
    [LINUX_WORKER_RECIPE.editId, 'tool_adapter', 'cliq-linux-edit']
  ] as const) fromBytes(id, role, filename, await readFile(path.join(input.installationRoot, filename)), true);
  fromBytes('supervisor-test', 'supervisor', 'test/supervisor', await readFile(process.execPath), true);
  fromBytes(STATE_OWNER_NATIVE_ENTRY_ID, 'platform_helper', STATE_OWNER_NATIVE_RELATIVE_PATH, await readFile(STATE_OWNER_NATIVE_PATH), true);
  const profile = policyProfile(), profileRef = canonicalSha256(profile);
  fromBytes('policy-v1', 'policy_engine', 'test/policy-v1', canonicalJsonBytes(profile), false);
  fromBytes('default_https_trust_store', 'trust_store', 'test/https-trust', Buffer.from(OFFLINE_MODEL_TRUST_STORE_PEM), false);
  fromBytes('linux-root-recipe-test', 'sandbox_root_profile', 'test/root-recipe', canonicalJsonBytes(input.sandboxProfile), false);
  // The campaign uses retained offline model facts, not productive provider I/O.
  const provider = input.assembly.provider.adapter;
  entries.push({ entryId: provider.adapterId, role: 'provider_adapter', relativePath: 'test/offline-provider',
    digest: provider.codeDigest, byteCount: 1, executable: true, version: provider.version });
  const worker = entries.find(entry => entry.entryId === LINUX_WORKER_RECIPE.workerId)!;
  const edit = entries.find(entry => entry.entryId === LINUX_WORKER_RECIPE.editId)!;
  input.assembly.runtime.workerExecutableId = worker.entryId;
  input.assembly.runtime.workerExecutableDigest = worker.digest;
  input.assembly.runtime.sandboxBackend = 'linux_namespace';
  input.tools[0].execution.adapterId = edit.entryId;
  input.tools[0].execution.adapterCodeDigest = edit.digest;
  input.tools[0].execution.adapterVersion = edit.version;
  const keys = generateKeyPairSync('ed25519');
  let guest: { manifest: GuestToolchainManifest; manifestRef: string; manifestId: string; imagePath: string;
    objects: Array<{ ref: string; bytes: Buffer }> } | undefined;
  if (input.guestImageRoot) {
    const metadataBytes = await readFile(path.join(input.guestImageRoot, 'guest-toolchain-input.json'));
    if (!metadataBytes.length || metadataBytes.length > 1_048_576) throw new Error('guest publisher input exceeds its bound');
    const metadata = parseJsonStrict(metadataBytes.toString('utf8')) as Record<string, any>;
    if (metadata.format !== 'cliq-guest-toolchain-publisher-input-v1' || metadata.guestImageByteCount !== GUEST_EXTRACTOR_RECIPE.maxImageBytes)
      throw new Error('campaign requires the actual fixed-size raw-ext4 publisher image');
    const originalImage = path.join(input.guestImageRoot, 'guest-toolchain.ext4');
    if (await actualFileDigest(originalImage, metadata.guestImageByteCount) !== metadata.guestImageDigest)
      throw new Error('actual guest image does not match its complete publisher input');
    const manifest: GuestToolchainManifest = { schemaVersion: 1, format: 'cliq-guest-toolchain-v1',
      guestImageRef: metadata.guestImageDigest, guestImageDigest: metadata.guestImageDigest,
      guestImageByteCount: metadata.guestImageByteCount, guestImageFormat: 'raw-ext4-v1', architecture: metadata.architecture,
      kernelAbi: metadata.kernelAbi, userspaceAbi: metadata.userspaceAbi, worker: metadata.worker, shell: metadata.shell,
      git: metadata.git, node: metadata.node, searchTools: [], verifiers: [], admittedExecutables: [],
      publisherKeyId: 'actual-linux-worker-ci', manifestDigest: '', signatureRef: '' };
    const { manifestDigest: _manifestDigest, signatureRef: _signatureRef, ...manifestCore } = manifest;
    manifest.manifestDigest = canonicalSha256(manifestCore);
    const signature = sign(null, Buffer.from(`cliq-guest-toolchain-v1\0${manifest.manifestDigest}`), keys.privateKey);
    manifest.signatureRef = sha256Bytes(signature); decodeGuestToolchainManifest(manifest);
    const manifestBytes = canonicalJsonBytes(manifest), manifestRef = sha256Bytes(manifestBytes), manifestId = 'actual-node-test-toolchain';
    const imageRelativePath = `objects/sha256/${manifest.guestImageRef.slice(0, 2)}/${manifest.guestImageRef}`;
    const imagePath = path.join(input.installationRoot, imageRelativePath);
    await mkdir(path.dirname(imagePath), { recursive: true, mode: 0o700 });
    try { await copyFile(originalImage, imagePath, constants.COPYFILE_EXCL); await chmod(imagePath, 0o400); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    if (await actualFileDigest(imagePath, manifest.guestImageByteCount) !== manifest.guestImageDigest)
      throw new Error('campaign retained image differs from the signed complete image');
    const objects = [{ ref: manifestRef, bytes: manifestBytes }, { ref: manifest.signatureRef, bytes: signature }];
    const manifestRelativePath = `profiles/guest-${manifestRef}.json`;
    await mkdir(path.join(input.installationRoot, 'profiles'), { recursive: true, mode: 0o700 });
    await writeFile(path.join(input.installationRoot, manifestRelativePath), manifestBytes, { flag: 'wx', mode: 0o400 });
    fromBytes('actual-guest-root-entry', 'guest_toolchain', manifestRelativePath, manifestBytes, false);
    for (const object of [{ ref: manifest.signatureRef, bytes: signature }]) {
      const relativePath = `objects/sha256/${object.ref.slice(0, 2)}/${object.ref}`;
      await mkdir(path.dirname(path.join(input.installationRoot, relativePath)), { recursive: true, mode: 0o700 });
      await writeFile(path.join(input.installationRoot, relativePath), object.bytes, { flag: 'wx', mode: 0o400 });
      fromBytes(identityHash('runtime-bundle-object-v1', object.ref), 'bundle_object', relativePath, object.bytes, false);
    }
    entries.push({ entryId: identityHash('runtime-bundle-object-v1', manifest.guestImageRef), role: 'bundle_object', version: '1',
      relativePath: imageRelativePath, executable: false, digest: manifest.guestImageRef, byteCount: manifest.guestImageByteCount });
    const extractorBytes = await readFile(path.join(input.installationRoot, 'linux-guest-extractor.node'));
    const extractorPath = path.join(input.installationRoot, GUEST_EXTRACTOR_RECIPE.relativePath);
    await mkdir(path.dirname(extractorPath), { recursive: true, mode: 0o700 });
    try { await writeFile(extractorPath, extractorBytes, { flag: 'wx', mode: 0o500 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    if (await actualFileDigest(extractorPath, extractorBytes.length) !== sha256Bytes(extractorBytes))
      throw new Error('campaign extractor path differs from its real signed native bytes');
    fromBytes(GUEST_EXTRACTOR_RECIPE.entryId, 'platform_helper', GUEST_EXTRACTOR_RECIPE.relativePath, extractorBytes, true);
    guest = { manifest, manifestRef, manifestId, imagePath, objects };
    Object.assign(input.assembly.runtime, { guestToolchainManifestRef: manifestRef, guestToolchainManifestDigest: manifest.manifestDigest });
  }
  const bundle: RuntimeBundleManifest = { schemaVersion: 1, bundleVersion: 'actual-linux-worker-ci-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 }, stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION },
    workerProtocolRange: { min: 1, max: 1 }, entries,
    structuredArtifacts: [...(guest ? [{ kind: 'guest_toolchain', artifactId: guest.manifestId, rootEntryId: 'actual-guest-root-entry',
      artifactRef: guest.manifestRef, semanticDigest: guest.manifest.manifestDigest,
      memberRefs: [guest.manifest.signatureRef, guest.manifest.guestImageRef].sort() }] : []),
      { kind: 'policy_engine_profile', artifactId: 'policy-v1', rootEntryId: 'policy-v1', artifactRef: profileRef,
      semanticDigest: profile.profileDigest, memberRefs: [] }], guestToolchainManifestRefs: guest ? [guest.manifestRef] : [],
    publisherKeyId: 'actual-linux-worker-ci', manifestDigest: '', signature: '' };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  const releaseKeys = [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  verifyRuntimeBundle(bundle, releaseKeys);
  const bundleRef = canonicalSha256(bundle);
  input.assembly.runtime.runtimeBundleRef = bundleRef;
  input.assembly.runtime.runtimeBundleManifestDigest = bundle.manifestDigest;
  return { bundle, releaseKeys, profile, guest, trustStorePem: OFFLINE_MODEL_TRUST_STORE_PEM,
    engine: { id: 'cliq-policy-v1' as const, version: '1', runtimeBundleRef: bundleRef,
    profileEntryId: 'policy-v1', profileRef, profileDigest: profile.profileDigest } };
}
