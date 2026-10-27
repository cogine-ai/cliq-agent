import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeEndpointRegistration, type EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { decodeDependencyAcquisitionPlan, decodeDependencyPolicy, decodeDependencyGypSource,
  type DependencyAcquisitionPlan, type DependencyPolicy, type DependencyGypSourceV1 } from '../kernel/dependency.js';
import { assertArtifactRef, digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { immutableSnapshot } from '../model/immutable.js';
import semver from 'semver';
import { createHash } from 'node:crypto';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { decodePackageCacheManifest, packageCacheKey } from '../kernel/dependency.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { decodeSourceManifest, decodeWorkspaceEntries } from './decoders.js';
import { checkEntries, checkSourceManifest } from './source-validation.js';
import type { SourceManifest, WorkspaceEntryManifest } from '../kernel/types.js';
import { dependencyDescriptorSequence } from '../kernel/dependency-descriptors.js';
import { assertDependencyCacheManifestCapacity } from '../kernel/dependency-cache-capacity.js';

export type LockedPackageV1 = Readonly<{ packageName: string; packageVersion: string; endpointRegistrationRef: string;
  canonicalPackagePath: string; integrityAlgorithm: 'sha256' | 'sha512'; integrityDigest: string }>;
export type NpmLockData = Readonly<{ packageManifestRef: string; lockfileRef: string; packages: readonly LockedPackageV1[];
  registryEndpoints: DependencyPolicy['registryEndpoints']; bindingGyp: DependencyGypSourceV1 }>;
function fail(reason: string): never { throw new TypeError(`dependency ${reason}`); }
const compare = (left: string, right: string) => Buffer.compare(Buffer.from(left), Buffer.from(right));
const packageName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/u;
const jsonBytes = 1_048_576;
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('package JSON must be an object');
  return value as Record<string, unknown>;
}
function json(bytes: Buffer, maximum: number): Record<string, unknown> {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > Math.min(maximum, jsonBytes)) fail('package JSON exceeds its byte limit');
  // Do not strip BOM or replace bad encoding before lock/source identity checks.
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  if (!Buffer.from(text).equals(bytes)) fail('package JSON encoding differs');
  return object(parseJsonStrict(text));
}
function manifestLayout(data: Record<string, unknown>): void {
  for (const field of ['workspaces', 'bundledDependencies', 'bundleDependencies', 'overrides']) if (Object.hasOwn(data, field)) fail('workspace, override or bundled package layout is unsupported');
  for (const field of ['name', 'version']) if (typeof data[field] !== 'string' || !data[field]) fail('package identity is missing');
  if (!packageName.test(data.name as string) || Buffer.byteLength(data.name as string) > 214 || ['node_modules', 'favicon.ico'].includes(data.name as string) ||
      semver.valid(data.version as string) !== data.version) fail('package identity is outside the fixed profile');
}
function dependencyFields(data: Record<string, unknown>): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta']) {
    if (!Object.hasOwn(data, field)) continue;
    const values = object(data[field]);
    for (const [name, constraint] of Object.entries(values)) {
      if (!packageName.test(name) || field !== 'peerDependenciesMeta' && (typeof constraint !== 'string' || !constraint ||
          semver.validRange(constraint) === null)) fail('package dependency is not a registry version constraint');
    }
    output[field] = values;
  }
  return output;
}
function integrity(value: unknown): Pick<LockedPackageV1, 'integrityAlgorithm' | 'integrityDigest'> {
  if (typeof value !== 'string') fail('package integrity is missing');
  const match = /^(sha256|sha512)-([A-Za-z0-9+/]+={0,2})$/u.exec(value);
  if (!match) fail('package integrity must contain one supported exact digest');
  const bytes = Buffer.from(match[2]!, 'base64'), algorithm = match[1] as 'sha256' | 'sha512';
  if (bytes.length !== (algorithm === 'sha256' ? 32 : 64) || bytes.toString('base64') !== match[2]) fail('package integrity digest is not canonical');
  return { integrityAlgorithm: algorithm, integrityDigest: match[2]! };
}
function target(resolved: unknown, endpoints: readonly EndpointRegistrationV1[]): Pick<LockedPackageV1, 'endpointRegistrationRef' | 'canonicalPackagePath'> {
  if (typeof resolved !== 'string' || resolved.length > 4096) fail('package registry URL is invalid');
  let url: URL;
  try { url = new URL(resolved); } catch { fail('package registry URL is invalid'); }
  if (url!.protocol !== 'https:' || url!.username || url!.password || url!.search || url!.hash || url!.toString() !== resolved ||
      !/^\/[A-Za-z0-9_~.@+/-]+$/u.test(url!.pathname) || url!.pathname.split('/').slice(1).some(segment => !segment || segment === '.' || segment === '..'))
    fail('package registry URL is not a canonical HTTPS artifact path');
  const matches = endpoints.filter(endpoint => endpoint.target.hostAscii === url!.hostname && endpoint.target.port === Number(url!.port || 443) &&
    (endpoint.target.basePath === '/' || url!.pathname.startsWith(`${endpoint.target.basePath.replace(/\/$/u, '')}/`)));
  if (matches.length !== 1) fail('package registry target has no unique frozen endpoint');
  const endpoint = matches[0]!, base = endpoint.target.basePath === '/' ? '' : endpoint.target.basePath.replace(/\/$/u, '');
  return { endpointRegistrationRef: canonicalSha256(endpoint), canonicalPackagePath: url!.pathname.slice(base.length) };
}
export function lockedPackageKey(item: LockedPackageV1): string {
  return [item.packageName, item.packageVersion, item.endpointRegistrationRef, item.canonicalPackagePath, item.integrityAlgorithm, item.integrityDigest].join('\0');
}
function platformList(value: unknown, expected: string): boolean {
  if (!Array.isArray(value) || value.length > 64 || value.some(item => typeof item !== 'string' || !/^!?[a-z0-9_-]{1,64}$/u.test(item)))
    fail('lockfile package platform constraint is invalid');
  if (value.includes(`!${expected}`) || value.includes('!any')) return false;
  return value.length === 0 || value.includes(expected) || value.includes('any') || value.every(item => item.startsWith('!'));
}
function supportedPlatform(entry: Record<string, unknown>): boolean {
  return (entry.os === undefined || platformList(entry.os, 'linux')) &&
    (entry.cpu === undefined || platformList(entry.cpu, 'x64')) && (entry.libc === undefined || platformList(entry.libc, 'glibc'));
}
function parentLocation(location: string): string {
  const index = location.lastIndexOf('/node_modules/');
  return index < 0 ? '' : location.slice(0, index);
}
function lockedGraph(root: Record<string, unknown>, locations: Map<string, { data: Record<string, unknown>; package: LockedPackageV1 }>): LockedPackageV1[] {
  const selected = new Set<string>(), packages = new Map<string, LockedPackageV1>();
  const pending = [{ location: '', data: root }];
  for (let index = 0; index < pending.length; index++) {
    const current = pending[index]!;
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const) {
      // npm does not install a dependency's own development dependencies.
      if (field === 'devDependencies' && current.location !== '' || !Object.hasOwn(current.data, field)) continue;
      const dependencies = object(current.data[field]);
      for (const [name, range] of Object.entries(dependencies)) {
        if (field !== 'optionalDependencies' && field !== 'peerDependencies' && current.data.optionalDependencies !== undefined &&
            Object.hasOwn(object(current.data.optionalDependencies), name)) continue;
        if (!packageName.test(name) || typeof range !== 'string' || semver.validRange(range) === null) fail('lockfile dependency range is invalid');
        const metadata = current.data.peerDependenciesMeta === undefined ? undefined : object(current.data.peerDependenciesMeta)[name];
        const optional = field === 'optionalDependencies' || field === 'peerDependencies' && metadata !== undefined && object(metadata).optional === true;
        let ancestor = field === 'peerDependencies' ? parentLocation(current.location) : current.location;
        let found: { location: string; entry: { data: Record<string, unknown>; package: LockedPackageV1 } } | undefined;
        for (;;) {
          const location = `${ancestor ? `${ancestor}/` : ''}node_modules/${name}`, entry = locations.get(location);
          if (entry) { found = { location, entry }; break; }
          if (!ancestor) break;
          ancestor = parentLocation(ancestor);
        }
        if (!found) { if (optional) continue; fail('lockfile dependency package is missing'); }
        if (!semver.satisfies(found.entry.package.packageVersion, range)) fail('lockfile dependency version does not satisfy its declared range');
        if (!supportedPlatform(found.entry.data)) { if (optional) continue; fail('lockfile required package is unsupported on the fixed guest platform'); }
        if (!selected.has(found.location)) {
          selected.add(found.location); pending.push({ location: found.location, data: found.entry.data });
          packages.set(lockedPackageKey(found.entry.package), found.entry.package);
        }
      }
    }
  }
  // Do not make an unrelated lock entry an acquired capability. A package
  // manager's later heuristic cannot supply missing immutable provenance.
  for (const [location, entry] of locations) if (!selected.has(location) && supportedPlatform(entry.data) && entry.data.optional !== true)
    fail('lockfile contains an unreachable package outside the complete dependency graph');
  return [...packages.values()].sort((left, right) => compare(lockedPackageKey(left), lockedPackageKey(right)));
}
/** Complete original bytes are the input. This projection provides no execution, endpoint registration or credential authority. */
export function readNpmLockData(input: { packageJsonBytes: Buffer; packageLockBytes: Buffer; registryEndpoints: readonly EndpointRegistrationV1[];
  maxPackages: number; maxSingleFileBytes: number; bindingGyp: DependencyGypSourceV1 }): NpmLockData {
  if (!Number.isSafeInteger(input.maxPackages) || input.maxPackages < 1 || input.maxPackages > 200_000 ||
      !Number.isSafeInteger(input.maxSingleFileBytes) || input.maxSingleFileBytes < 1 || input.maxSingleFileBytes > 268_435_456) fail('package limits are invalid');
  const packageJson = json(input.packageJsonBytes, input.maxSingleFileBytes), lock = json(input.packageLockBytes, input.maxSingleFileBytes);
  manifestLayout(packageJson);
  if (lock.lockfileVersion !== 3 || lock.name !== packageJson.name || lock.version !== packageJson.version) fail('lockfile does not bind the root package or supported version');
  const entries = object(lock.packages), root = object(entries['']);
  manifestLayout(root);
  if (!supportedPlatform(packageJson) || !supportedPlatform(root)) fail('root package is unsupported on the fixed guest platform');
  if (root.name !== packageJson.name || root.version !== packageJson.version ||
      canonicalSha256(dependencyFields(root)) !== canonicalSha256(dependencyFields(packageJson))) fail('lockfile root dependency declarations differ from package.json');
  const endpoints = input.registryEndpoints.map(value => decodeEndpointRegistration(value));
  if (!endpoints.length || endpoints.length > 128 || endpoints.some(value => !value.purposes.includes('dependency_registry')) ||
      new Set(endpoints.map(canonicalSha256)).size !== endpoints.length) fail('registry endpoint set is invalid');
  const locations = new Map<string, { data: Record<string, unknown>; package: LockedPackageV1 }>();
  for (const [location, value] of Object.entries(entries)) {
    if (location === '') continue;
    if (!/^(?:node_modules\/(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*)(?:\/node_modules\/(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*)*$/u.test(location)) fail('lockfile package path is outside the registry layout');
    const entry = object(value), name = location.slice(location.lastIndexOf('node_modules/') + 13);
    if (!packageName.test(name) || Buffer.byteLength(name) > 214 || ['node_modules', 'favicon.ico'].includes(name) || entry.name !== undefined && entry.name !== name || typeof entry.version !== 'string' || semver.valid(entry.version) !== entry.version ||
        entry.link !== undefined || entry.inBundle !== undefined || entry.hasShrinkwrap !== undefined || entry.bundleDependencies !== undefined)
      fail('lockfile package identity, link or bundled layout is unsupported');
    const item = { packageName: name, packageVersion: entry.version, ...target(entry.resolved, endpoints), ...integrity(entry.integrity) };
    dependencyFields(entry); supportedPlatform(entry);
    locations.set(location, { data: entry, package: item });
  }
  const packages = lockedGraph(root, locations);
  if (packages.length > input.maxPackages) fail('lockfile package count exceeds its bound');
  return immutableSnapshot({ packageManifestRef: sha256Bytes(input.packageJsonBytes), lockfileRef: sha256Bytes(input.packageLockBytes), bindingGyp: decodeDependencyGypSource(input.bindingGyp),
    packages,
    registryEndpoints: endpoints.map(endpoint => ({ endpointRegistrationRef: canonicalSha256(endpoint), endpointIdentityDigest: endpoint.endpointIdentityDigest,
      tlsPolicyDigest: endpoint.tlsPolicyDigest })).sort((left, right) => compare(left.endpointRegistrationRef, right.endpointRegistrationRef)) });
}
/** Rebuilt at every candidate; policy refs cannot be replaced by the current registry. */
export function deriveDependencyPlan(data: NpmLockData, policyInput: DependencyPolicy, guestToolchainManifestRef: string): DependencyAcquisitionPlan {
  // A valid small lock/descriptor sequence does not guarantee that the
  // complete success history (including all three GET observations) fits.
  // Refuse that original JSON budget before creating a claim or network I/O.
  const policy = decodeDependencyPolicy(policyInput);
  assertDependencyCacheManifestCapacity(data.packages, 67_108_864, policy.maxDownloadBytes);
  assertArtifactRef(guestToolchainManifestRef);
  if (policy.mode !== 'locked_node' || policy.allowedAdapters.length !== 1 || policy.allowedAdapters[0] !== 'npm-ci-v1' ||
      policy.credentialGrantRefs.length !== 0 || canonicalSha256(policy.registryEndpoints) !== canonicalSha256(data.registryEndpoints) || data.packages.length > policy.maxPackages)
    fail('candidate registry endpoint or package set differs from the frozen supported policy');
  const plan: DependencyAcquisitionPlan = { schemaVersion: 1, format: 'cliq-dependency-acquisition-plan-v1', ecosystem: 'node',
    adapter: 'npm-ci-v1', lockfilePath: 'package-lock.json', guestToolchainManifestRef,
    packageManifest: { canonicalRootRelativePath: 'package.json', contentRef: data.packageManifestRef, contentDigest: data.packageManifestRef },
    bindingGyp: data.bindingGyp,
    lockfileRef: data.lockfileRef, lockfileDigest: data.lockfileRef, registryEndpoints: policy.registryEndpoints,
    credentialGrantRefs: policy.credentialGrantRefs, allowInstallScripts: policy.installScriptsPolicy === 'exact_lockfile_grant',
    maxPackages: policy.maxPackages, maxDownloadBytes: policy.maxDownloadBytes,
    ...(() => { const { pages: _pages, ...root } = dependencyDescriptorSequence(data.packages); return root; })(), planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  return immutableSnapshot(decodeDependencyAcquisitionPlan(plan));
}

/** Reads the complete retained source projection, not mutable workspace paths.
 * The owning admission/candidate transaction separately rechecks its SQL cut. */
export async function readCandidateDependencyPlan(artifacts: ArtifactCatalog, input: {
  sourceRef: string; policy: DependencyPolicy; guestToolchainManifestRef: string;
  registryEndpoints: readonly EndpointRegistrationV1[]; maxSingleFileBytes: number;
}) {
  input = immutableSnapshot(input); artifacts.assertReadActive(); assertArtifactRef(input.sourceRef);
  const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, input.sourceRef));
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, source.entriesRef));
  return readDependencyPlanForProjectedSource(artifacts, { ...input, source, entries });
}

/** Derived projection data only. The original Checkpoint/source reader must
 * prove the derivation separately; this never publishes a missing source,
 * rewrites its role or attests a capture/retirement. */
export async function readDependencyPlanForProjectedSource(artifacts: ArtifactCatalog, input: {
  source: SourceManifest; entries: WorkspaceEntryManifest; policy: DependencyPolicy; guestToolchainManifestRef: string;
  registryEndpoints: readonly EndpointRegistrationV1[]; maxSingleFileBytes: number;
}) {
  input = immutableSnapshot(input); artifacts.assertReadActive();
  if (!Number.isSafeInteger(input.maxSingleFileBytes) || input.maxSingleFileBytes < 1 || input.maxSingleFileBytes > 268_435_456)
    fail('source file ceiling is outside the original profile');
  const source = decodeSourceManifest(input.source); checkSourceManifest(source);
  const entries = decodeWorkspaceEntries(input.entries); checkEntries(entries);
  if (canonicalSha256(entries) !== source.entriesRef || entries.treeDigest !== source.treeDigest)
    fail('source entry tree differs from its complete candidate');
  const manifests = new Set(['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock']);
  for (const entry of entries.entries) {
    const base = entry.path.slice(entry.path.lastIndexOf('/') + 1);
    if (entry.path === 'node_modules' || entry.path.startsWith('node_modules/') || base === '.npmrc' ||
        manifests.has(base) && entry.path !== 'package.json' && entry.path !== 'package-lock.json')
      fail('source layout contains unsupported nested manifests, install configuration or captured dependency files');
  }
  const root = entries.entries.find(entry => entry.path === 'package.json'), lock = entries.entries.find(entry => entry.path === 'package-lock.json');
  if (!root || root.kind !== 'file' || !lock || lock.kind !== 'file' || root.size > Math.min(input.maxSingleFileBytes, jsonBytes) ||
      lock.size > Math.min(input.maxSingleFileBytes, jsonBytes)) fail('source requires exactly two bounded regular root package files');
  const files = await artifacts.mapReads([root, lock], async entry => {
    const bytes = await artifacts.readBoundedBytes(entry.blobRef, Math.min(input.maxSingleFileBytes, jsonBytes));
    if (bytes.length !== entry.size || sha256Bytes(bytes) !== entry.blobRef) fail('source package file differs from its original complete bytes');
    return bytes;
  });
  artifacts.assertReadActive();
  const gyp = entries.entries.find(entry => entry.path === 'binding.gyp');
  let bindingGyp: DependencyGypSourceV1 = { kind: 'absent' };
  if (gyp) {
    if (gyp.kind !== 'file' || gyp.size > input.maxSingleFileBytes) fail('source binding.gyp is not one bounded regular file');
    let count = 0;
    for await (const bytes of artifacts.readChunks(gyp.blobRef, gyp.size)) { artifacts.assertReadActive(); count += bytes.length; }
    if (count !== gyp.size) fail('source binding.gyp differs from its complete bytes');
    bindingGyp = { kind: 'present', contentRef: gyp.blobRef, contentDigest: gyp.blobRef };
  }
  const policy = decodeDependencyPolicy(input.policy), data = readNpmLockData({ packageJsonBytes: files[0]!, packageLockBytes: files[1]!,
    registryEndpoints: input.registryEndpoints, maxPackages: policy.maxPackages, maxSingleFileBytes: input.maxSingleFileBytes, bindingGyp });
  const plan = deriveDependencyPlan(data, policy, input.guestToolchainManifestRef);
  return { source, entries, data, plan };
}

/** Reopens every actual cache blob. Schema, SRI and exact package-set equality
 * are independent of the native producer and never create a live authority. */
export async function readDependencyPackageCache(artifacts: ArtifactCatalog, input: {
  manifestRef: string; runId: string; resultSourceRef: string; dependencyPlan: DependencyAcquisitionPlan; packages: readonly LockedPackageV1[];
}) {
  input = immutableSnapshot(input); artifacts.assertReadActive(); assertArtifactRef(input.manifestRef);
  const bytes = await artifacts.readBoundedBytes(input.manifestRef, jsonBytes);
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const manifest = decodePackageCacheManifest(parseJsonStrict(text));
  if (!Buffer.from(text).equals(bytes) || !canonicalJsonBytes(manifest).equals(bytes) || sha256Bytes(bytes) !== input.manifestRef)
    fail('cache manifest does not contain its exact complete canonical bytes');
  const plan = decodeDependencyAcquisitionPlan(input.dependencyPlan);
  const descriptorRoot = dependencyDescriptorSequence(input.packages);
  if (manifest.runId !== input.runId || manifest.resultSourceRef !== input.resultSourceRef ||
      manifest.dependencyPlanRef !== canonicalSha256(plan) || manifest.lockfileRef !== plan.lockfileRef ||
      manifest.lockfileDigest !== plan.lockfileDigest || manifest.packageCount > plan.maxPackages ||
      manifest.totalTransferredBytes > plan.maxDownloadBytes || manifest.entries.length !== input.packages.length ||
      manifest.packageCount !== plan.packageCount || descriptorRoot.descriptorSequenceDigest !== plan.descriptorSequenceDigest ||
      descriptorRoot.packageDescriptorBytes !== plan.packageDescriptorBytes || descriptorRoot.packageCount !== plan.packageCount ||
      manifest.entries.some((entry, index) => packageCacheKey(entry) !== lockedPackageKey(input.packages[index]!)))
    fail('cache manifest substitutes its original plan, source or complete package set');
  await artifacts.mapReads(manifest.entries, async entry => {
    const hash = createHash(entry.integrityAlgorithm); let total = 0;
    for await (const chunk of artifacts.readChunks(entry.blobRef, entry.blobBytes)) {
      artifacts.assertReadActive(); hash.update(chunk); total += chunk.length;
    }
    if (total !== entry.blobBytes || hash.digest('base64') !== entry.integrityDigest) fail('cache package integrity does not match its complete blob');
  });
  artifacts.assertReadActive(); return manifest;
}
