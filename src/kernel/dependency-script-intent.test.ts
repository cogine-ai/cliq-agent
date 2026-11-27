import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from './canonical.js';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting, identityHash } from './identity.js';
import type { DependencyScriptConditionsV1 } from './dependency.js';
import { decodeDependencyScriptIntent, type DependencyScriptIntentV1 } from './dependency-script-intent.js';
// Inert decoder fixtures; none is a captured source, StateOwner or permission.
const ref = (name: string) => canonicalSha256({ inertFixture: name });
function conditions(): DependencyScriptConditionsV1 {
  return { profile: 'npm-ci-v1', lockfilePath: 'package-lock.json', lockfileDigest: ref('lock'), packageManifestDigest: ref('package'), bindingGyp: { kind: 'absent' },
    source: { sourceManifestRef: ref('manifest bytes'), sourceManifestDigest: ref('manifest meaning'), sourceRole: 'base',
      projectedEntriesRef: ref('projection entries'), projectedTreeDigest: ref('projection tree'), sourceProjectionRef: ref('projection'),
      sourceProjectionDigest: ref('projection meaning'), workspaceEntriesRef: ref('complete entries'), workspaceTreeDigest: ref('complete tree'), scriptInputTreeDigest: ref('derived actual program inputs'), privateGit: { kind: 'absent' } },
    execution: { runtimeBundleRef: ref('runtime'), runtimeBundleManifestDigest: ref('runtime meaning'), guestToolchainManifestRef: ref('guest'),
      guestToolchainManifestDigest: ref('guest meaning'), nodeExecutionPath: '/usr/bin/node', nodeExecutableDigest: ref('node'),
      adapterCodeRef: ref('adapter'), npmDataRef: ref('official npm data'), registryTargetsDigest: ref('targets'), environmentDigest: ref('environment') } };
}
function intent(): DependencyScriptIntentV1 {
  const source = conditions(); source.source.workspaceEntriesRef = source.source.projectedEntriesRef;
  source.source.workspaceTreeDigest = source.source.projectedTreeDigest;
  const value: DependencyScriptIntentV1 = { schemaVersion: 1, format: 'cliq-dependency-script-intent-v1',
    inspectionId: identityHash('script intent fixture'), principalId: 'fixture-owner', targetRef: ref('target'),
    originalRequestId: '00000000-0000-7000-8000-000000000004', originalRequestDigest: ref('original wire'), admissionIntentDigest: ref('original intent'),
    workspaceIdentityRef: ref('workspace'), workspaceIdentityDigest: ref('workspace identity'), sourceManifestRef: source.source.sourceManifestRef,
    sourceManifestDigest: source.source.sourceManifestDigest, conditions: source, scriptlessPolicyRef: ref('deny policy'), scriptlessPlanRef: ref('intent plan'),
    registrySourceRefs: [ref('source one'), ref('source two')].sort(), intentDigest: '' };
  value.intentDigest = digestOmitting(value, 'intentDigest'); return value;
}
const resign = (value: DependencyScriptIntentV1) => ({ ...value, intentDigest: digestOmitting(value, 'intentDigest') });
test('one bounded dependency intent keeps every original locator and ordered registered-source ref', () => {
  const value = intent(); assert.deepEqual(canonicalJsonBytes(decodeDependencyScriptIntent(value)), canonicalJsonBytes(value));
  assert.notEqual(value.originalRequestDigest, value.admissionIntentDigest);
  const maximum = resign({ ...value, registrySourceRefs: Array.from({ length: 128 }, (_, i) => ref(String(i))).sort() });
  assert.equal(decodeDependencyScriptIntent(maximum).registrySourceRefs.length, 128);
  assert(canonicalJsonBytes(maximum).length < 1_048_576);
});
test('intent rejects missing, duplicate, reordered, extra and cross-source data even when self-rehashed', () => {
  const value = intent();
  for (const changed of [
    { ...value, registrySourceRefs: [] }, { ...value, registrySourceRefs: [...value.registrySourceRefs].reverse() },
    { ...value, registrySourceRefs: [value.registrySourceRefs[0]!, value.registrySourceRefs[0]!] },
    { ...value, registrySourceRefs: Array.from({ length: 129 }, (_, i) => ref(String(i))).sort() },
    { ...value, sourceManifestRef: ref('another source') },
    { ...value, sourceManifestDigest: ref('another source meaning') },
    { ...value, conditions: { ...value.conditions, source: { ...value.conditions.source, sourceRole: 'result' as const } } },
    { ...value, conditions: { ...value.conditions, source: { ...value.conditions.source, workspaceEntriesRef: ref('uncaptured bytes') } } },
    { ...value, unrelatedAuthority: true }
  ]) assert.throws(() => decodeDependencyScriptIntent(resign(changed)));
});
test('intent decoder refuses accessors and proxies without observing their traps', () => {
  const value = intent(); let observed = 0;
  const getter = { ...value }; Object.defineProperty(getter, 'conditions', { enumerable: true, get() { observed++; return value.conditions; } });
  assert.throws(() => decodeDependencyScriptIntent(getter)); assert.equal(observed, 0);
  assert.throws(() => decodeDependencyScriptIntent(new Proxy(value, { ownKeys() { observed++; throw new Error('must not run'); } })));
  assert.equal(observed, 0);
  const refs = [...value.registrySourceRefs]; Object.defineProperty(refs, '0', { enumerable: true, get() { observed++; return value.registrySourceRefs[0]; } });
  assert.throws(() => decodeDependencyScriptIntent({ ...value, registrySourceRefs: refs })); assert.equal(observed, 0);
});
