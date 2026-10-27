import { canonicalSha256 } from '../kernel/canonical.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { NPM_DEPENDENCY_RECIPE, isNpmAdapterEntry, isNpmDataEntry } from '../sandbox/dependency-recipe.js';
import { assertBuiltinScriptGuest } from '../tools/execution-identity.js';
import type { ArtifactCatalog } from './artifacts.js';
import { guestToolchainRoots, readRetainedVerifierToolchain } from './guest-toolchain.js';
import { assertBuiltinScriptResources } from './tool-runtime-authority.js';

/** Signed immutable execution data, never a native scope or launch grant. */
export async function readDependencySignedAssets(artifacts: ArtifactCatalog, input: {
  bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[]; resources: SandboxResourceSpec; allowScripts: boolean;
}, signal?: AbortSignal) {
  verifyRuntimeBundle(input.bundle, input.releaseKeys);
  const adapter = input.bundle.entries.find(isNpmAdapterEntry), image = input.bundle.entries.find(isNpmDataEntry);
  const roots = guestToolchainRoots(input.bundle);
  if (!adapter || !image || roots.length !== 1) throw new TypeError('dependency npm requires one exact signed Node, adapter and data root');
  const toolchain = await readRetainedVerifierToolchain(artifacts, { bundle: input.bundle, releaseKeys: input.releaseKeys,
    guestToolchainManifestRef: roots[0]!.artifactRef, signal });
  if (toolchain.manifest.architecture !== 'x86_64' || toolchain.manifest.node.logicalName !== 'node' ||
      toolchain.manifest.node.canonicalGuestPath !== '/usr/bin/node' || toolchain.manifest.git.canonicalGuestPath !== '/usr/bin/git')
    throw new TypeError('dependency npm requires its exact signed Linux Node identity');
  assertBuiltinScriptGuest(toolchain.manifest, input.allowScripts ? ['bash'] : []);
  assertBuiltinScriptResources(toolchain.manifest.guestImageByteCount, input.resources);
  for (const entry of [adapter, image]) {
    let count = 0;
    for await (const bytes of artifacts.readChunks(entry.digest, entry.byteCount)) { artifacts.assertReadActive(); count += bytes.length; }
    if (count !== entry.byteCount) throw new TypeError('dependency signed data differs from its complete original bytes');
  }
  artifacts.assertReadActive();
  return { adapter, image, toolchain, execution: {
    runtimeBundleRef: canonicalSha256(input.bundle), runtimeBundleManifestDigest: input.bundle.manifestDigest,
    guestToolchainManifestRef: toolchain.manifestRef, guestToolchainManifestDigest: toolchain.manifest.manifestDigest,
    nodeExecutionPath: '/usr/bin/node' as const, nodeExecutableDigest: toolchain.manifest.node.digest,
    adapterCodeRef: adapter.digest, npmDataRef: image.digest, environmentDigest: canonicalSha256(NPM_DEPENDENCY_RECIPE.environment)
  } };
}
