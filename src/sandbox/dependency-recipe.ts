import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { NPM_DATA_RECIPE } from './npm-data-image.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import type { SandboxMountV1 } from '../kernel/execution.js';
import { immutableSnapshot } from '../model/immutable.js';

/** A separate fixed dependency recipe. None of these declarations changes
 * the existing tool/verifier/source executable or 32-file contracts. */
export const NPM_DEPENDENCY_RECIPE = Object.freeze({
  recipe: 'cliq-dependency-npm-v1', adapterId: 'npm_dependency_adapter', adapterVersion: '1',
  adapterPath: 'adapters/npm-dependency.mjs', dataId: 'npm_package_data', dataVersion: '10.9.2',
  dataPath: 'runtime/npm-10.9.2.image', nodePath: '/usr/bin/node',
  environment: Object.freeze({ PATH: '/usr/bin:/bin', HOME: '/home/cliq', TMPDIR: '/tmp',
    LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC', GIT_OPTIONAL_LOCKS: '0',
    NODE_EXTRA_CA_CERTS: '', NPM_CONFIG_USERCONFIG: '/runtime/npm-config/user',
    NPM_CONFIG_GLOBALCONFIG: '/runtime/npm-config/global' })
} as const);

const sandboxEnvironment = {
  schemaVersion: 1 as const, format: 'cliq-sanitized-sandbox-environment-v1' as const,
  home: '/home/cliq', tmpdir: '/tmp', controlledPath: ['/usr/bin', '/bin'], locale: { lang: 'C.UTF-8', lcAll: 'C.UTF-8' },
  variables: ['GIT_OPTIONAL_LOCKS', 'NODE_EXTRA_CA_CERTS', 'NPM_CONFIG_GLOBALCONFIG', 'NPM_CONFIG_USERCONFIG', 'TZ'].map(name =>
    ({ name, value: { kind: 'non_secret_literal' as const, value: NPM_DEPENDENCY_RECIPE.environment[name as keyof typeof NPM_DEPENDENCY_RECIPE.environment] } })),
  networkMode: 'none' as const, inheritedHostEnvironment: false as const, secretMaterial: 'none' as const, brokerAccessAtSpawn: 'none' as const
};
/** This exact new recipe alone accepts the fixed empty Node CA setting. The
 * ordinary executable/environment decoder keeps its existing NODE_* refusal. */
export const NPM_DEPENDENCY_SANDBOX_ENVIRONMENT = immutableSnapshot({ ...sandboxEnvironment,
  environmentDigest: canonicalSha256(sandboxEnvironment) });
export function npmDependencyMounts(dispatchId: string, generationRef: string, adapterRef: string, dataRef: string): readonly SandboxMountV1[] {
  return immutableSnapshot([
    { kind: 'private_ephemeral', privateRootId: identityHash(dispatchId, 'home'), targetPath: '/home/cliq', access: 'read_write', purpose: 'home' },
    { kind: 'cas_artifact', artifactRef: adapterRef, artifactDigest: adapterRef, targetPath: '/runtime/cliq-npm-dependency.mjs', access: 'read_only', purpose: 'input' },
    { kind: 'cas_artifact', artifactRef: dataRef, artifactDigest: dataRef, targetPath: '/runtime/npm.image', access: 'read_only', purpose: 'runtime' },
    { kind: 'private_ephemeral', privateRootId: identityHash(dispatchId, 'cache'), targetPath: '/scratch', access: 'read_write', purpose: 'cache' },
    { kind: 'private_ephemeral', privateRootId: identityHash(dispatchId, 'tmp'), targetPath: '/tmp', access: 'read_write', purpose: 'tmp' },
    { kind: 'run_generation', generationRef, canonicalRootRelativePath: 'node_modules', targetPath: '/work/node_modules', access: 'read_write', purpose: 'dependency' }
  ] as SandboxMountV1[]);
}

export function isNpmAdapterEntry(entry: RuntimeBundleManifest['entries'][number]): boolean {
  return entry.entryId === NPM_DEPENDENCY_RECIPE.adapterId && entry.role === 'tool_adapter' && !entry.executable &&
    entry.version === NPM_DEPENDENCY_RECIPE.adapterVersion && entry.relativePath === NPM_DEPENDENCY_RECIPE.adapterPath &&
    entry.byteCount >= 1 && entry.byteCount <= 1_048_576;
}
export function isNpmDataEntry(entry: RuntimeBundleManifest['entries'][number]): boolean {
  return entry.entryId === NPM_DATA_RECIPE.entryId && entry.role === 'bundle_object' && !entry.executable &&
    entry.version === NPM_DATA_RECIPE.version && entry.relativePath === NPM_DATA_RECIPE.relativePath &&
    entry.byteCount === NPM_DATA_RECIPE.completeImageBytes && entry.digest === NPM_DATA_RECIPE.completeImageDigest;
}
