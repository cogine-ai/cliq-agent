import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import type { DependencyScriptConditionsV1 } from '../kernel/dependency.js';
import { digestOmitting } from '../kernel/identity.js';
import type { FrozenIgnoreRulesV1, SourceManifest, SourceProjectionSpec, WorkspaceEntry, WorkspaceEntryManifest } from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readDependencyScriptSourceConditions, readDerivedDependencyScriptSourceConditions, sameDependencyScriptInputs, sameDependencyReadyInputs } from './dependency-script-source.js';

const ref = (name: string) => canonicalSha256({ fixtureOnly: name });
const execution: DependencyScriptConditionsV1['execution'] = { runtimeBundleRef: ref('runtime'), runtimeBundleManifestDigest: ref('runtime meaning'),
  guestToolchainManifestRef: ref('guest'), guestToolchainManifestDigest: ref('guest meaning'), nodeExecutionPath: '/usr/bin/node',
  nodeExecutableDigest: ref('node'), adapterCodeRef: ref('adapter'), npmDataRef: ref('npm data'), registryTargetsDigest: ref('registry'), environmentDigest: ref('environment') };
test('complete script input data keeps true base/result provenance and includes ignored restorable program bytes', async () => {
  const home = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-dependency-script-source-')));
  await mkdir(path.join(home, 'cas'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(home, 'cas')));
  try {
    const rules: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1', matcherVersion: 'cliq-git-wildmatch-v1',
      sources: [], rules: [], rulesDigest: '' }; rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
    const rulesRef = (await artifacts.publishCanonical(rules, rules.format)).ref;
    const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1', frozenIgnoreRulesRef: rulesRef,
      frozenIgnoreRulesDigest: rules.rulesDigest, explicitIncludes: [], explicitExcludes: [{ path: 'ignored', scope: 'subtree' }, { path: '.npmrc', scope: 'entry' }, { path: 'node_modules', scope: 'subtree' }],
      maxChangedPaths: 1000, maxChangedBytes: 1_048_576, projectionDigest: '' }; projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
    const projectionRef = (await artifacts.publishCanonical(projection, 'cliq-source-projection-v1')).ref;
    const file = async (name: string, text: string): Promise<WorkspaceEntry> => {
      const blob = await artifacts.publishBytes(Buffer.from(text), 'application/octet-stream', 'fixture-only-script-bytes');
      return { path: name, kind: 'file', mode: 0o644, size: Buffer.byteLength(text), blobRef: blob.ref };
    };
    const pkg = await file('package.json', '{"name":"app","version":"1.0.0"}'), lock = await file('package-lock.json', '{"lockfileVersion":3}');
    const original = [pkg, lock].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
    async function entries(values: WorkspaceEntry[]) {
      const sorted = [...values].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
      const manifest: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: sorted, entryCount: sorted.length,
        byteCount: sorted.reduce((n, e) => n + (e.kind === 'file' ? e.size : e.kind === 'symlink' ? Buffer.byteLength(e.target) : 0), 0),
        treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: sorted }) };
      return { manifest, ref: (await artifacts.publishCanonical(manifest, manifest.format)).ref };
    }
    const projected = await entries(original);
    async function source(role: 'base' | 'result') {
      const value: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role, workspaceIdentityDigest: ref('workspace'),
        entriesRef: projected.ref, treeDigest: projected.manifest.treeDigest, sourceProjectionRef: projectionRef, sourceProjectionDigest: projection.projectionDigest,
        frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, manifestDigest: '' };
      value.manifestDigest = digestOmitting(value, 'manifestDigest'); return (await artifacts.publishCanonical(value, value.format)).ref;
    }
    const a = await source('base'), b = await source('result'); assert.notEqual(a, b);
    const programs = async (text: string, extra: WorkspaceEntry[] = []) => entries([...original, { path: 'ignored', kind: 'directory', mode: 0o755 },
      await file('ignored/install.js', text), ...extra]);
    const before = await programs('module.exports = 1;'), after = await programs('module.exports = 2;');
    const input = { sourceManifestRef: a, workspaceIdentityDigest: ref('workspace'), workspaceEntriesRef: before.ref, resources: DEFAULT_SANDBOX_RESOURCES,
      packageManifestDigest: (pkg as Extract<WorkspaceEntry, { kind: 'file' }>).blobRef,
      lockfileDigest: (lock as Extract<WorkspaceEntry, { kind: 'file' }>).blobRef, bindingGyp: { kind: 'absent' as const }, execution };
    const initial = await readDependencyScriptSourceConditions(artifacts, input);
    const current = await readDependencyScriptSourceConditions(artifacts, { ...input, sourceManifestRef: b });
    assert.notEqual(initial.source.sourceManifestRef, current.source.sourceManifestRef);
    assert.equal(initial.source.sourceRole, 'base'); assert.equal(current.source.sourceRole, 'result');
    assert(sameDependencyScriptInputs(initial, current));
    const originalManifest = await artifacts.readCanonical<SourceManifest>(b);
    const derived = { ...originalManifest, manifestDigest: '' }; derived.manifestDigest = digestOmitting(derived, 'manifestDigest');
    const beforeDerived = (await readdir(path.join(home, 'cas'))).sort();
    assert.deepEqual(await readDerivedDependencyScriptSourceConditions(artifacts, { ...input, source: derived, projected: projected.manifest }), current);
    assert.deepEqual((await readdir(path.join(home, 'cas'))).sort(), beforeDerived, 'a derived source read must not publish or repair CAS');
    await assert.rejects(readDerivedDependencyScriptSourceConditions(artifacts, { ...input,
      source: { ...derived, entriesRef: ref('different entries') }, projected: projected.manifest }));
    const drift = await readDependencyScriptSourceConditions(artifacts, { ...input, workspaceEntriesRef: after.ref });
    assert.equal(drift.source.projectedTreeDigest, initial.source.projectedTreeDigest);
    assert(!sameDependencyScriptInputs(initial, drift), 'ignored root program drift must invalidate original consent');
    assert(sameDependencyReadyInputs(initial, drift, false), 'ignore-scripts ready reuse depends on actual package inputs while retaining both source graphs');
    assert(!sameDependencyReadyInputs(initial, drift, true));
    const installed = await programs('module.exports = 1;', [{ path: 'node_modules', kind: 'directory', mode: 0o755 },
      await file('node_modules/dependency-data', 'output'), await file('node_modules/.npmrc', 'package data, never project configuration')]);
    const withOutput = await readDependencyScriptSourceConditions(artifacts, { ...input, workspaceEntriesRef: installed.ref });
    assert.notEqual(initial.source.workspaceEntriesRef, withOutput.source.workspaceEntriesRef);
    assert.equal(initial.source.scriptInputTreeDigest, withOutput.source.scriptInputTreeDigest);
    assert(sameDependencyScriptInputs(initial, withOutput));
    for (const changed of [{ ...current, lockfileDigest: ref('different lock') }, { ...current, packageManifestDigest: ref('different package') },
      { ...current, execution: { ...execution, nodeExecutableDigest: ref('different Node') } }]) assert(!sameDependencyReadyInputs(initial, changed, false));
    assert(!sameDependencyScriptInputs(initial, { ...current, execution: { ...execution, adapterCodeRef: ref('changed signed adapter') } }));
    const config = await programs('module.exports = 1;', [await file('.npmrc', 'registry=https://unapproved.invalid/')]);
    await assert.rejects(readDependencyScriptSourceConditions(artifacts, { ...input, workspaceEntriesRef: config.ref }));
    await assert.rejects(readDependencyScriptSourceConditions(artifacts, { ...input, workspaceIdentityDigest: ref('foreign workspace') }));
    await assert.rejects(readDependencyScriptSourceConditions(artifacts, { ...input, privateGitStateRef: ref('invented private Git') }));
    const aborted = new AbortController(); aborted.abort();
    await assert.rejects(readDependencyScriptSourceConditions(artifacts.withReadSignal(aborted.signal), input));
  } finally { await rm(home, { recursive: true, force: true }); }
});
