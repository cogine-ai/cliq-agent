// Fixed signed CPU runtime composition. This decodes data; only the original
// installed image/source owners may seal, inspect or execute these entries.
import { canonicalSha256 } from '../kernel/canonical.js';
import type { LocalInferenceNativeFile, LocalInferenceNativeImage } from '../kernel/local-inference-native-input.js';
import type { LocalModelObjectClosureV1 } from '../kernel/local-inference.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, type RuntimeBundleManifest } from '../policy/runtime-authority.js';

export const LOCAL_INFERENCE_RUNTIME_ENTRY = 'ollama_local_inference_runtime';
export const LOCAL_INFERENCE_RUNTIME_KIND = 'local_inference_runtime';
export type LocalInferenceRuntimeV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-local-inference-runtime-v1'; engineVersion: '0.40.14';
  bootstrapEntryId: 'ollama_local_inference'; engineEntryId: 'ollama_local_inference_engine';
  helperEntryId: 'ollama_local_inference_llama_server'; loaderEntryId: 'ollama_local_inference_loader';
  libraries: readonly Readonly<{ entryId: string; guestPath: string }>[]; runtimeDigest: string;
}>;
/** The original bundle and model closures select each mount. Aliased signed
 * library bytes use the same ArtifactRef with distinct fixed guest paths. */
export function localInferenceRuntimeInputs(bundle: RuntimeBundleManifest, runtime: LocalInferenceRuntimeV1,
  closure: LocalModelObjectClosureV1): Readonly<{
  bootstrap: LocalInferenceNativeImage; controller: LocalInferenceNativeImage; bubblewrap: LocalInferenceNativeImage;
  files: readonly LocalInferenceNativeFile[];
}> {
  const image = (entryId: string): LocalInferenceNativeImage => {
    const entry = bundle.entries.find(value => value.entryId === entryId);
    if (!entry || !entry.executable || entry.byteCount < 1 || entry.byteCount > 268_435_456)
      invalid('original local service image is absent from its signed fixed recipe');
    return { digest: entry.digest, byteCount: entry.byteCount };
  };
  const member = (kind: LocalInferenceNativeFile['kind'], entryId: string, guestPath: string): LocalInferenceNativeFile => {
    const selected = image(entryId);
    return { kind, guestPath, artifactRef: selected.digest, byteCount: selected.byteCount };
  };
  const files: LocalInferenceNativeFile[] = [];
  for (const object of closure.objects) {
    if (object.kind === 'model_signature') continue;
    const mount = object.kind === 'model_manifest' ? { kind: 'model_manifest' as const, guestPath: '/models/model-manifest.json' }
      : object.kind === 'tokenizer' ? { kind: 'model_tokenizer' as const, guestPath: '/models/tokenizer' }
      : { kind: 'model_file' as const, guestPath: '/models/files/' + object.logicalPath };
    files.push({ ...mount, artifactRef: object.artifactRef, byteCount: object.sizeBytes });
  }
  files.push(member('engine', runtime.engineEntryId, '/runtime/bin/ollama'),
    member('helper', runtime.helperEntryId, '/runtime/lib/ollama/llama-server'),
    member('loader', runtime.loaderEntryId, '/lib64/ld-linux-x86-64.so.2'));
  for (const library of runtime.libraries) files.push(member('library', library.entryId, library.guestPath));
  return immutableSnapshot({ bootstrap: image(runtime.bootstrapEntryId), controller: image('linux_worker_controller'),
    bubblewrap: image('linux_bubblewrap'), files });
}
function invalid(message: string): never { throw new TypeError(message); }
function guestPath(value: unknown): string {
  if (typeof value !== 'string' || value.normalize('NFC') !== value || Buffer.byteLength(value) > 4095 ||
      !['/runtime/lib/ollama/', '/lib/', '/lib64/', '/usr/lib/'].some(root => value.startsWith(root)) ||
      value.split('/').slice(1).some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255) ||
      /[\u0000-\u001f\u007f\\]/u.test(value)) invalid('local runtime library binding is not a supported canonical guest path');
  return value;
}
export function decodeLocalInferenceRuntime(value: unknown): LocalInferenceRuntimeV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !exactKeys(value, ['schemaVersion', 'format', 'engineVersion', 'bootstrapEntryId', 'engineEntryId', 'helperEntryId', 'loaderEntryId', 'libraries', 'runtimeDigest']))
    invalid('local runtime profile must have its exact closed fields');
  const profile = value as Record<string, unknown>;
  if (profile.schemaVersion !== 1 || profile.format !== 'cliq-local-inference-runtime-v1' || profile.engineVersion !== '0.40.14' ||
      profile.bootstrapEntryId !== 'ollama_local_inference' || profile.engineEntryId !== 'ollama_local_inference_engine' ||
      profile.helperEntryId !== 'ollama_local_inference_llama_server' || profile.loaderEntryId !== 'ollama_local_inference_loader' ||
      !Array.isArray(profile.libraries) || profile.libraries.length > 26 || typeof profile.runtimeDigest !== 'string')
    invalid('local runtime does not name the fixed supported engine recipe');
  assertArtifactRef(profile.runtimeDigest);
  const paths = ['/runtime/bin/cliq-local-inference', '/runtime/bin/ollama', '/runtime/lib/ollama/llama-server', '/lib64/ld-linux-x86-64.so.2'];
  let previous: Buffer | undefined;
  const libraries = profile.libraries.map((item: unknown) => {
    if (!item || typeof item !== 'object' || Array.isArray(item) || !exactKeys(item, ['entryId', 'guestPath']))
      invalid('local runtime library binding must have its exact fields');
    const binding = item as Record<string, unknown>, path = guestPath(binding.guestPath);
    if (typeof binding.entryId !== 'string' || !/^ollama_local_inference_library_[1-9][0-9]*$/u.test(binding.entryId))
      invalid('local runtime library has no fixed signed-entry identity');
    const key = Buffer.from(path);
    if (previous && Buffer.compare(previous, key) >= 0 || paths.some(other => other === path || other.startsWith(`${path}/`) || path.startsWith(`${other}/`)))
      invalid('local runtime bindings are unordered, duplicate or overlapping');
    previous = key; paths.push(path); return { entryId: binding.entryId, guestPath: path };
  });
  const result: LocalInferenceRuntimeV1 = { schemaVersion: 1, format: 'cliq-local-inference-runtime-v1', engineVersion: '0.40.14',
    bootstrapEntryId: 'ollama_local_inference', engineEntryId: 'ollama_local_inference_engine',
    helperEntryId: 'ollama_local_inference_llama_server', loaderEntryId: 'ollama_local_inference_loader', libraries,
    runtimeDigest: profile.runtimeDigest };
  if (digestOmitting(result, 'runtimeDigest') !== result.runtimeDigest) invalid('local runtime semantic digest differs');
  return immutableSnapshot(result);
}
export function localInferenceRuntimeRoots(bundle: RuntimeBundleManifest): RuntimeBundleManifest['structuredArtifacts'] {
  const roots = bundle.structuredArtifacts.filter(root => root.kind === LOCAL_INFERENCE_RUNTIME_KIND);
  const profiles = bundle.entries.filter(entry => entry.entryId === LOCAL_INFERENCE_RUNTIME_ENTRY);
  const bootstraps = bundle.entries.filter(entry => entry.entryId === 'ollama_local_inference');
  if (!roots.length && !profiles.length && !bootstraps.length && !bundle.entries.some(entry => entry.entryId.startsWith('ollama_local_inference_'))) return [];
  if (roots.length !== 1 || profiles.length !== 1 || bootstraps.length !== 1) invalid('managed local runtime has no unique complete signed discovery root');
  const root = roots[0], profile = profiles[0], bootstrap = bootstraps[0];
  if (!root || !profile || !bootstrap || root.artifactId !== LOCAL_INFERENCE_RUNTIME_ENTRY || root.rootEntryId !== LOCAL_INFERENCE_RUNTIME_ENTRY ||
      root.artifactRef !== profile.digest || profile.role !== 'bundle_object' || profile.executable || profile.version !== '1' ||
      profile.relativePath !== 'local-inference/runtime.json' || profile.byteCount < 1 || profile.byteCount > 1_048_576 ||
      bootstrap.role !== 'local_inference' || !bootstrap.executable || bootstrap.version !== '1' ||
      bootstrap.relativePath !== 'helpers/ollama-local-inference' || bootstrap.byteCount < 1 || bootstrap.byteCount > 268_435_456)
    invalid('managed local runtime discovery differs from its exact signed entries');
  return roots;
}
export function bindLocalInferenceRuntime(bundle: RuntimeBundleManifest, rootRef: string, value: unknown): LocalInferenceRuntimeV1 {
  const roots = localInferenceRuntimeRoots(bundle), root = roots[0], profile = decodeLocalInferenceRuntime(value);
  if (!root || root.artifactRef !== rootRef || root.semanticDigest !== profile.runtimeDigest) invalid('local runtime profile does not bind its original discovery root');
  const required = new Map<string, { path: string; version?: string }>([
    [profile.bootstrapEntryId, { path: 'helpers/ollama-local-inference', version: '1' }],
    [profile.engineEntryId, { path: 'local-inference/bin/ollama', version: profile.engineVersion }],
    [profile.helperEntryId, { path: 'local-inference/lib/ollama/llama-server', version: profile.engineVersion }],
    [profile.loaderEntryId, { path: 'local-inference/loader/ld-linux-x86-64.so.2' }],
  ]);
  const ordinals = new Map<string, number>();
  for (const library of profile.libraries) {
    if (!ordinals.has(library.entryId)) ordinals.set(library.entryId, ordinals.size + 1);
    const ordinal = ordinals.get(library.entryId);
    if (library.entryId !== `ollama_local_inference_library_${ordinal}`) invalid('local runtime library ids differ from their canonical first-binding order');
    required.set(library.entryId, { path: `local-inference/libraries/${ordinal}`, version: profile.engineVersion });
  }
  const members: string[] = [];
  for (const [id, expected] of required) {
    const matches = bundle.entries.filter(entry => entry.entryId === id), entry = matches[0];
    if (matches.length !== 1 || !entry || entry.role !== (id === profile.bootstrapEntryId ? 'local_inference' : 'platform_helper') ||
        !entry.executable || entry.relativePath !== expected.path || expected.version !== undefined && entry.version !== expected.version ||
        entry.byteCount < 1 || entry.byteCount > 268_435_456) invalid('local runtime executable closure differs from its original signed recipe');
    members.push(entry.digest);
  }
  if (bundle.entries.some(entry => entry.entryId.startsWith('ollama_local_inference_') && entry.entryId !== LOCAL_INFERENCE_RUNTIME_ENTRY && !required.has(entry.entryId)) ||
      canonicalSha256([...new Set(members)].sort()) !== canonicalSha256(root.memberRefs))
    invalid('local runtime discovery does not bind its all-and-only signed code closure');
  return profile;
}
