import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { mkdtemp, mkdir, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import type { DependencyPolicy, PackageCacheManifestV1 } from '../kernel/dependency.js';
import type { SourceManifest, WorkspaceEntry, WorkspaceEntryManifest } from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readCandidateDependencyPlan, readDependencyPackageCache } from './dependency-plan.js';

const ref = (digit: string) => digit.repeat(64), now = '2026-10-27T00:00:00.000Z';
const tar = Buffer.from('actual immutable fixture package bytes; package extraction is independently tested');
const sri = createHash('sha512').update(tar).digest('base64');
function endpoint(): EndpointRegistrationV1 {
  const value: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: 'registry',
    registrationKind: 'user', ownerPrincipalId: 'owner', purposes: ['dependency_registry'],
    target: { scheme: 'https', hostAscii: 'registry.example.com', port: 443, basePath: '/', redirectPolicy: 'reject_all' },
    tls: { serverNameAscii: 'registry.example.com', minimumVersion: 'TLSv1.3', trustStoreRuntimeBundleRef: ref('1'),
      trustStoreRuntimeBundleManifestDigest: ref('2'), trustStoreEntryId: 'default_https_trust_store', trustStoreRef: ref('3'),
      trustStoreDigest: ref('3'), spkiSha256Pins: [ref('4')] }, endpointIdentityDigest: '', tlsPolicyDigest: '', createdAt: now, registrationDigest: '' };
  value.tlsPolicyDigest = canonicalSha256(value.tls); value.endpointIdentityDigest = canonicalSha256({ target: value.target, tlsPolicyDigest: value.tlsPolicyDigest });
  value.registrationDigest = digestOmitting(value, 'registrationDigest'); return value;
}
async function fixture() {
  const home = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-dependency-cas-'))), root = path.join(home, 'cas');
  await mkdir(root, { mode: 0o700 }); const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  const policy: DependencyPolicy = { schemaVersion: 1, mode: 'locked_node', allowedAdapters: ['npm-ci-v1'],
    registryEndpoints: [{ endpointRegistrationRef: canonicalSha256(endpoint()), endpointIdentityDigest: endpoint().endpointIdentityDigest, tlsPolicyDigest: endpoint().tlsPolicyDigest }],
    credentialGrantRefs: [], installScriptsPolicy: 'deny', maxPackages: 50_000, maxDownloadBytes: 5 * 1_073_741_824 };
  async function file(filename: string, bytes: Buffer): Promise<WorkspaceEntry> {
    const published = await artifacts.publishBytes(bytes, 'application/octet-stream', 'fixture-source-bytes');
    return { path: filename, kind: 'file', mode: 0o644, size: bytes.length, blobRef: published.ref };
  }
  const declarations = { dep: '^1.0.0' }, packageJson = Buffer.from(JSON.stringify({ name: 'application', version: '1.0.0', dependencies: declarations }));
  const packageLock = Buffer.from(JSON.stringify({ name: 'application', version: '1.0.0', lockfileVersion: 3, requires: true, packages: {
    '': { name: 'application', version: '1.0.0', dependencies: declarations }, 'node_modules/dep': { version: '1.0.0',
      resolved: 'https://registry.example.com/dep/-/dep-1.0.0.tgz', integrity: `sha512-${sri}` } } }));
  const original = [await file('package-lock.json', packageLock), await file('package.json', packageJson)];
  async function source(extra: WorkspaceEntry[] = []) {
    const entries = [...original, ...extra].sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
    const image: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries, entryCount: entries.length,
      byteCount: entries.reduce((sum, entry) => sum + (entry.kind === 'file' ? entry.size : entry.kind === 'symlink' ? Buffer.byteLength(entry.target) : 0), 0),
      treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries }) };
    const entriesRef = (await artifacts.publishCanonical(image, image.format)).ref;
    const value: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'result', workspaceIdentityDigest: ref('1'),
      entriesRef, sourceProjectionRef: ref('2'), sourceProjectionDigest: ref('3'), frozenIgnoreRulesRef: ref('4'), frozenIgnoreRulesDigest: ref('5'),
      treeDigest: image.treeDigest, manifestDigest: '' };
    value.manifestDigest = digestOmitting(value, 'manifestDigest'); return (await artifacts.publishCanonical(value, value.format)).ref;
  }
  return { home, artifacts, policy, file, source, original, read: (sourceRef: string, selected = artifacts) => readCandidateDependencyPlan(selected, {
    sourceRef, policy, guestToolchainManifestRef: ref('6'), registryEndpoints: [endpoint()], maxSingleFileBytes: 268_435_456 }) };
}

test('candidate dependencies reopen exact complete CAS source and each cached package without StateOwner or Run authority', async t => {
  const f = await fixture(), open = fs.open.bind(fs); let active = 0;
  try {
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const file = await open(...args), close = file.close.bind(file); active++;
      t.mock.method(file, 'close', async () => { await close(); active--; }); return file;
    });
    const sourceRef = await f.source(), selected = await f.read(sourceRef), blob = await f.artifacts.publishBytes(tar, 'application/octet-stream', 'fixture-package');
    const value: PackageCacheManifestV1 = { schemaVersion: 1, format: 'cliq-package-cache-manifest-v1', runId: 'inert-data-only',
      resultSourceRef: sourceRef, dependencyPlanRef: canonicalSha256(selected.plan), lockfileRef: selected.plan.lockfileRef,
      lockfileDigest: selected.plan.lockfileDigest, entries: [{ ...selected.data.packages[0]!, blobRef: blob.ref, blobDigest: blob.ref,
        blobBytes: tar.length, fetchAttempts: [{ attempt: 1, outcome: 'completed', receivedBytes: tar.length, observationDigest: ref('7') }] }],
      packageCount: 1, totalTransferredBytes: tar.length, manifestDigest: '', createdAt: now };
    value.manifestDigest = digestOmitting(value, 'manifestDigest');
    const published = await f.artifacts.publishCanonical(value, value.format);
    assert.equal((await readDependencyPackageCache(f.artifacts, { manifestRef: published.ref, runId: value.runId,
      resultSourceRef: sourceRef, dependencyPlan: selected.plan, packages: selected.data.packages })).manifestDigest, value.manifestDigest);
    const changed = { ...value, entries: [{ ...value.entries[0]!, blobRef: ref('e'), blobDigest: ref('e') }] };
    changed.manifestDigest = digestOmitting(changed, 'manifestDigest');
    const bad = await f.artifacts.publishCanonical(changed, changed.format);
    await assert.rejects(readDependencyPackageCache(f.artifacts, { manifestRef: bad.ref, runId: value.runId,
      resultSourceRef: sourceRef, dependencyPlan: selected.plan, packages: selected.data.packages }));
    assert.equal(active, 0, 'every issued real CAS file/root descriptor joined after success and failure');
  } finally { t.mock.restoreAll(); await rm(f.home, { recursive: true, force: true }); }
});

test('ambiguous dependency layouts and project config refuse before reading package payloads', async () => {
  const f = await fixture();
  try {
    for (const extra of [
      [await f.file('.npmrc', Buffer.from('registry=https://unapproved.example/\nnode-options=--require=/outside/inject.js\n'))],
      [await f.file('yarn.lock', Buffer.from('other lock'))],
      [{ path: 'nested', kind: 'directory' as const, mode: 0o755 }, await f.file('nested/package.json', Buffer.from('{}'))],
      [{ path: 'node_modules', kind: 'directory' as const, mode: 0o755 }]
    ]) await assert.rejects(f.read(await f.source(extra)), /dependency|source layout/i);
    const cancellation = new AbortController(); cancellation.abort(new Error('original owned cancellation'));
    await assert.rejects(f.read(await f.source(), f.artifacts.withReadSignal(cancellation.signal)), /original owned cancellation/);
  } finally { await rm(f.home, { recursive: true, force: true }); }
});
