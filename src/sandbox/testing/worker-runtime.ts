import { generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { rootCertificates } from 'node:tls';
import { KERNEL_STATE_SCHEMA_VERSION } from '../../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { sha256Bytes } from '../../kernel/identity.js';
import type { SandboxProfileV1 } from '../../kernel/execution.js';
import type { RunAssemblyV1, ToolContractManifestV1 } from '../../kernel/types.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_PATH, STATE_OWNER_NATIVE_RELATIVE_PATH } from '../../state/native-owner.js';
import { LINUX_WORKER_RECIPE } from '../linux-worker.js';

/** Actual built worker/controller/edit/bwrap/addon bytes under an explicitly
 * injected CI Ed25519 test root. This is not a Cliq release signature, an
 * installed-provider qualification, or a containment success receipt. */
export async function signedLinuxWorkerTestRuntime(input: {
  installationRoot: string; assembly: RunAssemblyV1; tools: ToolContractManifestV1['entries']; sandboxProfile: SandboxProfileV1;
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
  fromBytes('default_https_trust_store', 'trust_store', 'test/https-trust', Buffer.from(rootCertificates.join('\n')), false);
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
  const bundle: RuntimeBundleManifest = { schemaVersion: 1, bundleVersion: 'actual-linux-worker-ci-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 }, stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION },
    workerProtocolRange: { min: 1, max: 1 }, entries,
    structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'policy-v1', rootEntryId: 'policy-v1', artifactRef: profileRef,
      semanticDigest: profile.profileDigest, memberRefs: [] }], guestToolchainManifestRefs: [],
    publisherKeyId: 'actual-linux-worker-ci', manifestDigest: '', signature: '' };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  const releaseKeys = [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  verifyRuntimeBundle(bundle, releaseKeys);
  const bundleRef = canonicalSha256(bundle);
  input.assembly.runtime.runtimeBundleRef = bundleRef;
  input.assembly.runtime.runtimeBundleManifestDigest = bundle.manifestDigest;
  return { bundle, releaseKeys, profile, engine: { id: 'cliq-policy-v1' as const, version: '1', runtimeBundleRef: bundleRef,
    profileEntryId: 'policy-v1', profileRef, profileDigest: profile.profileDigest } };
}
