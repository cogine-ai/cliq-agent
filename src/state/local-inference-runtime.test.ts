import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { bindLocalInferenceRuntime, decodeLocalInferenceRuntime, localInferenceRuntimeRoots, type LocalInferenceRuntimeV1 } from './local-inference-runtime.js';

function profile(): LocalInferenceRuntimeV1 {
  const value: LocalInferenceRuntimeV1 = { schemaVersion: 1, format: 'cliq-local-inference-runtime-v1', engineVersion: '0.40.14',
    bootstrapEntryId: 'ollama_local_inference', engineEntryId: 'ollama_local_inference_engine', helperEntryId: 'ollama_local_inference_llama_server',
    loaderEntryId: 'ollama_local_inference_loader', libraries: [
      { entryId: 'ollama_local_inference_library_1', guestPath: '/lib/x86_64-linux-gnu/libc.so.6' },
      { entryId: 'ollama_local_inference_library_2', guestPath: '/runtime/lib/ollama/libggml-base.so' },
      { entryId: 'ollama_local_inference_library_2', guestPath: '/runtime/lib/ollama/libggml-base.so.0' },
    ], runtimeDigest: '0'.repeat(64) };
  return { ...value, runtimeDigest: digestOmitting(value, 'runtimeDigest') };
}
function fixture(value = profile()): RuntimeBundleManifest {
  const entry = (entryId: string, relativePath: string, role = 'platform_helper', version = '0.40.14') =>
    ({ entryId, relativePath, role, version, executable: true, byteCount: 64, digest: sha256Bytes(Buffer.from(entryId)) });
  const entries = [entry('ollama_local_inference', 'helpers/ollama-local-inference', 'local_inference', '1'),
    entry('ollama_local_inference_engine', 'local-inference/bin/ollama'), entry('ollama_local_inference_llama_server', 'local-inference/lib/ollama/llama-server'),
    entry('ollama_local_inference_loader', 'local-inference/loader/ld-linux-x86-64.so.2', 'platform_helper', 'actual-retained-loader-version'),
    entry('ollama_local_inference_library_1', 'local-inference/libraries/1'), entry('ollama_local_inference_library_2', 'local-inference/libraries/2')];
  const raw = canonicalJsonBytes(value), ref = sha256Bytes(raw), members = entries.map(entry => entry.digest).sort();
  entries.push({ entryId: 'ollama_local_inference_runtime', role: 'bundle_object', version: '1', relativePath: 'local-inference/runtime.json',
    executable: false, byteCount: raw.length, digest: ref });
  // This is a pure metadata fixture, deliberately not signed or installed.
  return { schemaVersion: 2, installedLayout: 'single_cas_streams_v1', bundleVersion: 'data-fixture', controlProtocolRange: { min: 1, max: 1 },
    headlessSchemaRange: { min: 1, max: 1 }, stateSchemaRange: { min: 1, max: 1 }, workerProtocolRange: { min: 9, max: 9 }, entries,
    structuredArtifacts: [{ kind: 'local_inference_runtime', artifactId: 'ollama_local_inference_runtime', rootEntryId: 'ollama_local_inference_runtime',
      artifactRef: ref, semanticDigest: value.runtimeDigest, memberRefs: members }], guestToolchainManifestRefs: [], publisherKeyId: 'not-a-release-key',
    manifestDigest: '0'.repeat(64), signature: 'not-a-signature' };
}
test('fixed CPU runtime binds regular SONAME aliases to one signed code entry without duplicating content entries', () => {
  const value = profile(), bundle = fixture(value), root = bundle.structuredArtifacts[0]; assert.ok(root);
  assert.deepEqual(bindLocalInferenceRuntime(bundle, root.artifactRef, value), value);
  assert.equal(localInferenceRuntimeRoots(bundle).length, 1);
});
test('fixed runtime rejects caller environment, unsupported engine and executable/path confusion even with recomputed semantic digest', () => {
  for (const change of [
    { environment: { PATH: '/host' } }, { engineVersion: '0.40.15' }, { helperEntryId: 'other-helper' },
    { libraries: [{ entryId: 'ollama_local_inference_library_1', guestPath: '/host/libc.so' }] },
    { libraries: [{ entryId: 'ollama_local_inference_library_1', guestPath: '/lib64/ld-linux-x86-64.so.2' }] },
    { libraries: [{ entryId: 'ollama_local_inference_library_1', guestPath: '/lib/../bin/engine' }] },
    { libraries: [...profile().libraries].reverse() },
  ]) {
    const candidate = { ...profile(), ...change };
    candidate.runtimeDigest = digestOmitting(candidate, 'runtimeDigest');
    assert.throws(() => decodeLocalInferenceRuntime(candidate));
  }
});
test('runtime discovery is all-and-only and libraries are signed executable code authorities', () => {
  const value = profile();
  for (const mutate of [
    (bundle: RuntimeBundleManifest) => { bundle.entries.find(entry => entry.entryId === 'ollama_local_inference_library_1')!.executable = false; },
    (bundle: RuntimeBundleManifest) => { bundle.entries.find(entry => entry.entryId === 'ollama_local_inference_library_1')!.role = 'bundle_object'; },
    (bundle: RuntimeBundleManifest) => { bundle.structuredArtifacts[0]!.memberRefs.pop(); },
    (bundle: RuntimeBundleManifest) => { bundle.entries.push({ ...bundle.entries[1]!, entryId: 'ollama_local_inference_unreferenced' }); },
  ]) {
    const bundle = fixture(value); mutate(bundle);
    assert.throws(() => bindLocalInferenceRuntime(bundle, bundle.structuredArtifacts[0]!.artifactRef, value));
  }
});
