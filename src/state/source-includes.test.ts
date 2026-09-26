import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';

import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type {
  FrozenIgnoreRulesV1, GitIndexSnapshotV1, SourceIncludeAuthorizationV1,
  SourceIncludeClassificationEvidenceV1, SourceProjectionSpec, WorkspaceEntry,
  WorkspaceEntryManifest
} from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import {
  decodeSourceIncludeAuthorization, decodeSourceIncludeClassificationEvidence
} from './decoders.js';
import { validateBuiltinSourceIncludes } from './source-includes.js';

const REF = 'a'.repeat(64);
const RUN = 'run-1';
const SESSION = 'session-1';
const PRINCIPAL = 'principal-1';
const TIME = '2026-09-27T00:00:00.000Z';

function entryManifest(entries: WorkspaceEntry[]): WorkspaceEntryManifest {
  return {
    schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries,
    entryCount: entries.length,
    byteCount: entries.reduce((total, entry) => total +
      (entry.kind === 'file' ? entry.size : entry.kind === 'symlink' ? Buffer.byteLength(entry.target) : 0), 0),
    treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries })
  };
}

async function fixture(t: TestContext) {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-include-'));
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  const casRoot = path.join(root, 'cas');
  await mkdir(casRoot, { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(casRoot));
  const rules: FrozenIgnoreRulesV1 = {
    schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1', matcherVersion: 'cliq-git-wildmatch-v1',
    repositoryIdentityDigest: REF,
    sources: [{ index: 0, kind: 'gitignore', canonicalRootRelativePath: '.gitignore',
      baseDirectory: '', contentRef: REF, contentDigest: REF }],
    rules: [{ order: 0, sourceIndex: 0, sourceLine: 1, baseDirectory: '', negated: false,
      directoryOnly: false, anchored: false, pattern: '*.log' }], rulesDigest: ''
  };
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
  const rulesRef = (await artifacts.publishCanonical(rules, rules.format)).ref;
  const entry: WorkspaceEntry = { path: 'ignored.log', kind: 'file', mode: 0o644,
    size: 1, blobRef: REF };
  const entries = entryManifest([entry]);
  const selector = { path: entry.path, scope: 'entry' as const };
  const base = {
    schemaVersion: 1 as const, principalId: PRINCIPAL, runId: RUN, sessionId: SESSION,
    workspaceIdentityRef: REF, workspaceIdentityDigest: REF,
    selector, selectorDigest: canonicalSha256(selector), admissionIntentDigest: REF
  };
  const evidence = (classification: SourceIncludeClassificationEvidenceV1['entries'][number]['classification']) => {
    const value: SourceIncludeClassificationEvidenceV1 = {
      ...base, format: 'cliq-source-include-classification-v1',
      frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest,
      entries: [{ path: entry.path, workspaceEntryDigest: canonicalSha256(entry),
        deviceId: '1', fileId: '2', linkCount: 2, classification }],
      observedAt: TIME, evidenceDigest: ''
    };
    value.evidenceDigest = digestOmitting(value, 'evidenceDigest');
    return value;
  };
  const publishGraph = async (observation: SourceIncludeClassificationEvidenceV1,
    kind: 'builtin_nonignored' | 'consumed_user_read_grant' = 'builtin_nonignored') => {
    const evidenceRef = (await artifacts.publishCanonical(observation, observation.format)).ref;
    const authorization: SourceIncludeAuthorizationV1 = kind === 'builtin_nonignored'
      ? {
          ...base, format: 'cliq-source-include-authorization-v1', kind,
          frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest,
          classification: 'tracked_or_nonignored_in_root',
          classificationEvidenceRef: evidenceRef, classificationEvidenceDigest: observation.evidenceDigest,
          createdAt: TIME, authorizationDigest: ''
        }
      : {
          ...base, format: 'cliq-source-include-authorization-v1', kind,
          authorizationGrantId: 'grant-1', authorizationGrantTargetDigest: REF,
          consumptionReceiptRef: REF, consumptionReceiptDigest: REF,
          createdAt: TIME, authorizationDigest: ''
        };
    authorization.authorizationDigest = digestOmitting(authorization, 'authorizationDigest');
    const authorizationRef = (await artifacts.publishCanonical(authorization, authorization.format)).ref;
    const projection: SourceProjectionSpec = {
      schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1',
      frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest,
      explicitIncludes: [{ ...selector, authorizationRef }], explicitExcludes: [],
      maxChangedPaths: 10_000, maxChangedBytes: 512 * 1024 * 1024,
      projectionDigest: ''
    };
    projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
    return { authorization, projection };
  };
  const input = (projection: SourceProjectionSpec, git?: { indexRef: string; snapshot: GitIndexSnapshotV1 }) => ({
    principalId: PRINCIPAL, runId: RUN, sessionId: SESSION,
    workspaceIdentityRef: REF, workspaceIdentityDigest: REF, admissionIntentDigest: REF,
    projection, entries, frozenIgnoreRulesRef: rulesRef, frozenIgnoreRules: rules,
    ...(git ? { git } : {})
  });
  return { artifacts, entry, evidence, publishGraph, input };
}

test('builtin include rejects rehashed claims that ignored bytes are ordinary source', async (t) => {
  const f = await fixture(t);
  const ignored = f.evidence('nonignored_in_root');
  const graph = await f.publishGraph(ignored);
  assert.deepEqual(decodeSourceIncludeClassificationEvidence(ignored), ignored);
  assert.deepEqual(decodeSourceIncludeAuthorization(graph.authorization), graph.authorization);
  await assert.rejects(validateBuiltinSourceIncludes(f.artifacts, f.input(graph.projection)),
    /classifies an ignored path as nonignored/);

  const changed = f.evidence('nonignored_in_root');
  changed.entries[0]!.workspaceEntryDigest = 'b'.repeat(64);
  changed.evidenceDigest = digestOmitting(changed, 'evidenceDigest');
  const changedGraph = await f.publishGraph(changed);
  await assert.rejects(validateBuiltinSourceIncludes(f.artifacts, f.input(changedGraph.projection)),
    /differs from the captured WorkspaceEntry/);
});

test('tracked include needs the exact canonical Git index and Run binding', async (t) => {
  const f = await fixture(t);
  const tracked = f.evidence('tracked_in_git_index');
  tracked.gitIndexRef = 'b'.repeat(64);
  tracked.gitIndexTreeObjectId = 'c'.repeat(40);
  tracked.evidenceDigest = digestOmitting(tracked, 'evidenceDigest');
  const graph = await f.publishGraph(tracked);
  const index = { entries: [{ canonicalRootRelativePath: f.entry.path }] } as GitIndexSnapshotV1;
  const git = { indexRef: tracked.gitIndexRef, snapshot: {
    ...index, indexTreeObjectId: tracked.gitIndexTreeObjectId
  } };
  assert.equal((await validateBuiltinSourceIncludes(f.artifacts,
    f.input(graph.projection, git))).metadata.length, 2);
  await assert.rejects(validateBuiltinSourceIncludes(f.artifacts,
    f.input(graph.projection, { indexRef: 'd'.repeat(64), snapshot: git.snapshot })),
  /does not match the admitted Git index/);
  await assert.rejects(validateBuiltinSourceIncludes(f.artifacts,
    { ...f.input(graph.projection, git), runId: 'another-run' }),
  /not bound to the admitted Run/);
});

test('source include evidence decoder rejects selector escape, duplicate and unpaired Git claims', async (t) => {
  const f = await fixture(t);
  const tracked = f.evidence('tracked_in_git_index');
  assert.throws(() => decodeSourceIncludeClassificationEvidence(tracked), /needs a Git index/);
  const duplicate = f.evidence('nonignored_in_root');
  duplicate.entries.push({ ...duplicate.entries[0]! });
  duplicate.evidenceDigest = digestOmitting(duplicate, 'evidenceDigest');
  assert.throws(() => decodeSourceIncludeClassificationEvidence(duplicate), /unique and byte-sorted/);
  const outside = f.evidence('nonignored_in_root');
  outside.entries[0]!.path = 'another.log';
  outside.evidenceDigest = digestOmitting(outside, 'evidenceDigest');
  assert.throws(() => decodeSourceIncludeClassificationEvidence(outside), /outside its selector/);
  const unpaired = f.evidence('nonignored_in_root');
  unpaired.gitIndexRef = 'b'.repeat(64);
  unpaired.evidenceDigest = digestOmitting(unpaired, 'evidenceDigest');
  assert.throws(() => decodeSourceIncludeClassificationEvidence(unpaired), /must be paired/);
});

test('read-grant include cannot enter admission without atomic grant consumption', async (t) => {
  const f = await fixture(t);
  const graph = await f.publishGraph(f.evidence('nonignored_in_root'), 'consumed_user_read_grant');
  assert.equal(decodeSourceIncludeAuthorization(graph.authorization).kind, 'consumed_user_read_grant');
  await assert.rejects(validateBuiltinSourceIncludes(f.artifacts, f.input(graph.projection)),
    /not yet supported by Run admission/);
});
