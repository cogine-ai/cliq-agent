// Actual CAS data planning only; these fixtures supply no StateOwner, live
// workspace, approval, Run, Journal claim or physical publication proof.
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import { publicationDirectoryIdentityDigest, type DeliveryCaptureTopologyV1 } from '../kernel/publication.js';
import type { SourceManifest, SourceProjectionSpec, WorkspaceEntry, WorkspaceEntryManifest } from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { planDeliveryPublication } from './publication-plan.js';
import { planDeliverySource } from './delivery-source.js';
import { prepareDeliveryMergePlan } from './publication-merge-plan.js';
import { fixtureSandboxProfile } from './testing/worker-launch.js';

async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-plan-'));
  const cas = path.join(directory, 'cas'); await mkdir(cas, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(cas));
  const profile = fixtureSandboxProfile(), sandboxProfileRef = (await artifacts.publishCanonical(profile, profile.format)).ref;
  const workspaceIdentity = { schemaVersion: 1, format: 'cliq-workspace-identity-v1', kind: 'live', ownerPrincipalId: 'data-only-principal',
    platform: 'linux', canonicalRootPath: '/data-only-workspace', rootIdentity: { deviceId: '1', fileId: '10', ownerUid: 501 }, identityDigest: '' };
  workspaceIdentity.identityDigest = digestOmitting(workspaceIdentity, 'identityDigest');
  const workspaceIdentityDigest = workspaceIdentity.identityDigest, workspaceIdentityRef = (await artifacts.publishCanonical(workspaceIdentity, workspaceIdentity.format)).ref;
  const rules = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1', matcherVersion: 'cliq-git-wildmatch-v1', sources: [], rules: [], rulesDigest: '' };
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest'); const rulesRef = (await artifacts.publishCanonical(rules, rules.format)).ref;
  const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1', frozenIgnoreRulesRef: rulesRef,
    frozenIgnoreRulesDigest: rules.rulesDigest, explicitIncludes: [], explicitExcludes: [], maxChangedPaths: 1000, maxChangedBytes: 1048576, projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const projectionRef = (await artifacts.publishCanonical(projection, 'cliq-source-projection-v1')).ref;
  const file = async (path: string, bytes: string): Promise<WorkspaceEntry> => ({ path, kind: 'file', mode: 0o644, size: Buffer.byteLength(bytes),
    blobRef: (await artifacts.publishBytes(Buffer.from(bytes), 'application/octet-stream', 'cliq-workspace-file-v1')).ref });
  const source = async (role: SourceManifest['role'], values: WorkspaceEntry[]) => {
    const entries = [...values].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
    const manifest: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries, entryCount: entries.length,
      byteCount: entries.reduce((sum, entry) => sum + (entry.kind === 'file' ? entry.size : entry.kind === 'symlink' ? Buffer.byteLength(entry.target) : 0), 0),
      treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries }) };
    const value: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role, workspaceIdentityDigest,
      entriesRef: (await artifacts.publishCanonical(manifest, manifest.format)).ref, sourceProjectionRef: projectionRef,
      sourceProjectionDigest: projection.projectionDigest, frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest,
      treeDigest: manifest.treeDigest, manifestDigest: '' };
    value.manifestDigest = digestOmitting(value, 'manifestDigest');
    return { ref: (await artifacts.publishCanonical(value, value.format)).ref, value, entries };
  };
  const directoryIdentity = (fileId: string, mode: number) => {
    const value = { deviceId: '1', fileId, ownerUid: 501, mode };
    return { ...value, identityDigest: publicationDirectoryIdentityDigest(workspaceIdentityDigest, value) };
  };
  return { artifacts, cas, source, file, workspaceIdentityDigest, workspaceIdentityRef, directoryIdentity, sandboxProfileRef };
}

test('one immutable plan orders type conversions and directory dependencies without publication', async t => {
  const f = await fixture(t), x = await f.file('x', 'old x'), oldChild = await f.file('y/old', 'old y');
  const captured = await f.source('base', [x, { path: 'y', kind: 'directory', mode: 0o755 }, oldChild]);
  const result = await f.source('result', [{ path: 'x', kind: 'directory', mode: 0o755 }, await f.file('x/new', 'new x'),
    await f.file('y', 'new y'), { path: 'z', kind: 'directory', mode: 0o755 }]);
  const topology = { schemaVersion: 1, format: 'cliq-delivery-capture-topology-v1',
    inspectionId: identityHash('data-only-inspection'), capturedWorkspaceRef: captured.ref,
    workspaceIdentityRef: f.workspaceIdentityRef, workspaceIdentityDigest: f.workspaceIdentityDigest,
    rootIdentity: f.directoryIdentity('10', 0o700), directories: [{ path: 'y', ...f.directoryIdentity('11', 0o700) }],
    fileModes: [{ path: 'x', mode: 0o600 }, { path: 'y/old', mode: 0o640 }], capturedAt: '2026-10-18T00:00:00.000Z', topologyDigest: '' } satisfies DeliveryCaptureTopologyV1;
  topology.topologyDigest = digestOmitting(topology, 'topologyDigest');
  const topologyRef = (await f.artifacts.publishCanonical(topology, topology.format)).ref;
  const operations = [
    { kind: 'modify', path: 'x', before: captured.entries[0], after: result.entries[0] },
    { kind: 'add', path: 'x/new', after: result.entries[1] },
    { kind: 'modify', path: 'y', before: captured.entries[1], after: result.entries[2] },
    { kind: 'delete', path: 'y/old', before: captured.entries[2] },
    { kind: 'add', path: 'z', after: result.entries[3] }
  ];
  const diff = { schemaVersion: 1, format: 'cliq-workspace-diff-v1', baseSourceRef: captured.ref, resultSourceRef: result.ref, operations, diffDigest: '' };
  diff.diffDigest = digestOmitting(diff, 'diffDigest'); const diffRef = (await f.artifacts.publishCanonical(diff, diff.format)).ref;
  const input = { deliveryRunId: 'data-only-delivery', sourceRunResultRef: sha256Bytes(Buffer.from('data-only-source-result')),
    sourceBaseRef: captured.ref, sourceDesiredRef: result.ref, capturedWorkspaceRef: captured.ref, captureTopologyRef: topologyRef, desiredSourceRef: result.ref, diffRef };
  const before = (await readdir(f.cas)).sort(), planned = await planDeliveryPublication(f.artifacts, input);
  assert.deepEqual(planned.plan.forwardOperations.map(operation => [operation.path, operation.kind]),
    [['x', 'replace'], ['x/new', 'create'], ['y/old', 'delete'], ['y', 'replace'], ['z', 'mkdir']]);
  assert.deepEqual(planned.plan.forwardOperations[1].parent, { kind: 'planned_directory', createdByOperationId: planned.plan.forwardOperations[0].operationId });
  assert.equal(planned.plan.forwardOperations[0].expected.kind === 'file' && planned.plan.forwardOperations[0].expected.mode, 0o600);
  assert.deepEqual(planned.plan.abortOperations.map(operation => [operation.path, operation.createdByOperationId]),
    [['x', planned.plan.forwardOperations[0].operationId], ['z', planned.plan.forwardOperations[4].operationId]]);
  // Each original claim has its own private arena. Workspace-name collision
  // allocation is neither necessary nor a source of publication authority.
  for (const operation of planned.plan.forwardOperations) {
    if ('stagingName' in operation) assert.equal(operation.stagingName, 'desired');
    if ('quarantineName' in operation) assert.equal(operation.quarantineName, 'preimage');
  }
  assert.equal(planned.planRef, canonicalSha256(planned.plan)); assert.deepEqual((await readdir(f.cas)).sort(), before);
});

test('one merge preparation publishes its immutable M closure and retains A as the private workspace base', async t => {
  const f = await fixture(t), base = await f.source('base', [await f.file('a', 'first\nlast\n')]);
  const desired = await f.source('result', [await f.file('a', 'agent\nlast\n')]), captured = await f.source('base', [await f.file('a', 'first\nuser\n')]);
  const source = await planDeliverySource(f.artifacts, { sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref,
    sandboxProfileRef: f.sandboxProfileRef });
  assert.equal(source.kind, 'ready'); if (source.kind !== 'ready') assert.fail('independent line edits must merge');
  await assert.rejects(f.artifacts.readBytes(source.sourceRef));
  const topology = { schemaVersion: 1, format: 'cliq-delivery-capture-topology-v1', inspectionId: identityHash('merge-data-inspection'),
    capturedWorkspaceRef: captured.ref, workspaceIdentityRef: f.workspaceIdentityRef, workspaceIdentityDigest: f.workspaceIdentityDigest,
    rootIdentity: f.directoryIdentity('10', 0o700), directories: [], fileModes: [{ path: 'a', mode: 0o600 }],
    capturedAt: '2026-10-18T00:00:00.000Z', topologyDigest: '' } satisfies DeliveryCaptureTopologyV1;
  topology.topologyDigest = digestOmitting(topology, 'topologyDigest'); const captureTopologyRef = (await f.artifacts.publishCanonical(topology, topology.format)).ref;
  const selected = { deliveryRunId: 'data-merge-run', sourceRunResultRef: 'f'.repeat(64), captureTopologyRef };
  const prepared = await prepareDeliveryMergePlan(f.artifacts, source, selected);
  assert.equal(prepared.workspaceState.baseWorkspaceManifestRef, captured.ref);
  assert.equal(prepared.workspaceState.entriesRef, source.source.entriesRef);
  assert.equal(prepared.plan.desiredSourceRef, source.sourceRef); assert.equal(prepared.plan.diffRef, source.diffRef);
  assert.equal(prepared.workspaceStateRef, canonicalSha256(prepared.workspaceState));
  assert.deepEqual(await f.artifacts.readCanonical(prepared.workspaceStateRef), prepared.workspaceState);
  const result = source.entries.entries[0]; assert.equal(result.kind, 'file');
  if (result.kind === 'file') assert.equal((await f.artifacts.readBytes(result.blobRef)).toString(), 'agent\nuser\n');
  assert.equal((await prepareDeliveryMergePlan(f.artifacts, source, selected)).planRef, prepared.planRef);
  assert.equal((await f.artifacts.readCanonical<SourceManifest>(captured.ref)).role, 'base');
});
