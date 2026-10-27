// Real CAS data projection only: no StateOwner, Run, permission, native
// retirement or installed delivery is created or qualified by these fixtures.
import assert from 'node:assert/strict';
import { chmodSync, writeFileSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { FrozenIgnoreRulesV1, SourceManifest, SourceProjectionSpec, WorkspaceEntry, WorkspaceEntryManifest } from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { planDeliverySource } from './delivery-source.js';
import { KernelStorageError } from './errors.js';
import { fixtureSandboxProfile } from './testing/worker-launch.js';
import type { DeliverySourceInput } from './delivery-source.js';
import type { Diff3ComputationV1 } from '../kernel/diff3.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';

async function fixture(t: TestContext, projectionChanges: Partial<SourceProjectionSpec> = {}, resourceChanges: Partial<SandboxResourceSpec> = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-delivery-source-'));
  const root = path.join(directory, 'cas'); await mkdir(root, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  const profile = fixtureSandboxProfile();
  Object.assign(profile.resources, resourceChanges); profile.profileDigest = digestOmitting(profile, 'profileDigest');
  const sandboxProfileRef = (await artifacts.publishCanonical(profile, profile.format)).ref;
  const rules: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1',
    matcherVersion: 'cliq-git-wildmatch-v1', sources: [], rules: [], rulesDigest: '' };
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
  const rulesRef = (await artifacts.publishCanonical(rules, rules.format)).ref;
  const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1',
    frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, explicitIncludes: [], explicitExcludes: [],
    maxChangedPaths: 1000, maxChangedBytes: 64 * 1024 ** 2, ...projectionChanges, projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const projectionRef = (await artifacts.publishCanonical(projection, 'cliq-source-projection-v1')).ref;
  const file = async (name: string, content: string | Buffer, mode = 0o644): Promise<WorkspaceEntry> => {
    const bytes = Buffer.from(content), blob = await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-workspace-file-v1');
    return { path: name, kind: 'file', mode, size: bytes.length, blobRef: blob.ref };
  };
  const source = async (role: SourceManifest['role'], values: WorkspaceEntry[], changes: Partial<SourceManifest> = {}) => {
    const sorted = [...values].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
    const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: sorted,
      entryCount: sorted.length, byteCount: sorted.reduce((sum, entry) => sum + (entry.kind === 'file' ? entry.size :
        entry.kind === 'symlink' ? Buffer.byteLength(entry.target) : 0), 0), treeDigest: '' };
    entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: sorted });
    const entriesRef = (await artifacts.publishCanonical(entries, entries.format)).ref;
    const value: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role,
      workspaceIdentityDigest: sha256Bytes(Buffer.from('data-only-workspace-identity')), entriesRef,
      sourceProjectionRef: projectionRef, sourceProjectionDigest: projection.projectionDigest,
      frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, treeDigest: entries.treeDigest,
      ...changes, manifestDigest: '' };
    value.manifestDigest = digestOmitting(value, 'manifestDigest');
    return { ref: (await artifacts.publishCanonical(value, value.format)).ref, value, entries };
  };
  const plan = (input: DeliverySourceInput, computation?: Diff3ComputationV1) =>
    planDeliverySource(artifacts, { ...input, sandboxProfileRef }, computation);
  return { root, artifacts, rules, rulesRef, projection, projectionRef, file, source, plan, sandboxProfileRef };
}

test('delivery plans the exact B/S/A/M projection and A-to-M diff without publishing partial artifacts', async t => {
  const f = await fixture(t);
  const base = await f.source('base', [await f.file('a', 'old\n'), await f.file('b', 'old\n')]);
  const desired = await f.source('result', [await f.file('a', 'agent\n'), await f.file('b', 'old\n')]);
  const captured = await f.source('base', [await f.file('a', 'old\n'), await f.file('b', 'user\n')]);
  const before = (await readdir(f.root)).sort();
  const plan = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref,
    capturedWorkspaceRef: captured.ref });
  assert.equal(plan.kind, 'ready');
  if (plan.kind !== 'ready') assert.fail('disjoint path changes must merge');
  assert.equal(plan.source.role, 'result');
  assert.equal(plan.source.workspaceIdentityDigest, captured.value.workspaceIdentityDigest);
  assert.deepEqual(plan.entries.entries, [await f.file('a', 'agent\n'), await f.file('b', 'user\n')]);
  assert.equal(plan.diff.baseSourceRef, captured.ref);
  assert.equal(plan.diff.resultSourceRef, plan.sourceRef);
  assert.deepEqual(plan.diff.operations, [{ path: 'a', kind: 'modify', before: captured.entries.entries[0], after: desired.entries.entries[0] }]);
  assert.equal(plan.noOp, false); assert.equal(plan.identicalToSourceDesired, false);
  assert.deepEqual((await readdir(f.root)).sort(), before);
  assert.equal(plan.sourceRef, canonicalSha256(plan.source));
  assert.equal(plan.diffRef, canonicalSha256(plan.diff));
  assert.equal(plan.summaryRef, canonicalSha256(plan.summary));
});

test('strict source-result reuse and normalized captured no-op are separate complete-manifest equations', async t => {
  const f = await fixture(t), original = await f.file('a', 'before\n'), agent = await f.file('a', 'after\n'), user = await f.file('a', 'user\n');
  const base = await f.source('base', [original]), desired = await f.source('result', [agent]);
  const alreadyApplied = await f.source('base', [agent]), unchangedDesired = await f.source('result', [original]);
  const userCaptured = await f.source('base', [user]);
  for (const [s, a, identicalToSourceDesired, noOp] of [
    [desired, base, true, false], [desired, alreadyApplied, true, true], [unchangedDesired, userCaptured, false, true],
  ] as const) {
    const plan = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: s.ref, capturedWorkspaceRef: a.ref });
    assert.equal(plan.kind, 'ready');
    if (plan.kind !== 'ready') assert.fail('one-sided source changes must be deterministic');
    assert.equal(plan.identicalToSourceDesired, identicalToSourceDesired); assert.equal(plan.noOp, noOp);
    assert.equal(plan.sourceRef === s.ref, identicalToSourceDesired);
    assert.notEqual(plan.sourceRef, a.ref, 'role=base must never be silently rewritten in place');
    const normalized = { ...a.value, role: 'result', manifestDigest: '' };
    normalized.manifestDigest = digestOmitting(normalized, 'manifestDigest');
    assert.equal(canonicalSha256(normalized) === plan.sourceRef, noOp);
    assert.equal(plan.diff.baseSourceRef, a.ref);
    assert.equal(plan.diff.operations.length === 0, noOp);
    assert.equal((await f.artifacts.readCanonical<SourceManifest>(a.ref)).role, 'base');
  }
});

test('same-mode text merge preserves BOM, Unicode, CRLF and exact new blob bytes in an artifact-first retry plan', async t => {
  const f = await fixture(t), base = await f.source('base', [await f.file('a', '\ufefffirst\r\n二\nlast')]);
  const desired = await f.source('result', [await f.file('a', '\ufeffFIRST\r\n二\nlast')]);
  const captured = await f.source('base', [await f.file('a', '\ufefffirst\r\n二\nLAST🙂')]);
  const input = { sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref };
  const before = (await readdir(f.root)).sort(), plan = await f.plan(input);
  assert.equal(plan.kind, 'ready');
  if (plan.kind !== 'ready') assert.fail('disjoint text edits must merge');
  const result = plan.entries.entries[0]; assert.equal(result.kind, 'file');
  if (result.kind !== 'file') assert.fail('merged content must remain a regular file');
  const bytes = Buffer.from('\ufeffFIRST\r\n二\nLAST🙂');
  assert.equal(result.blobRef, sha256Bytes(bytes)); assert.equal(result.size, bytes.length);
  const blob = plan.publications.find(value => value.ref === result.blobRef)!;
  assert.deepEqual(Buffer.from(blob.bytes), bytes);
  blob.bytes.fill(0);
  assert.deepEqual(Buffer.from(blob.bytes), bytes, 'a caller cannot mutate the retained planned bytes');
  assert.deepEqual((await readdir(f.root)).sort(), before);
  for (let attempt = 0; attempt < 2; attempt++) for (const artifact of plan.publications) {
    const published = await f.artifacts.publishBytes(artifact.bytes, artifact.mediaType, artifact.schemaKind);
    assert.equal(published.ref, artifact.ref);
  }
  const repeated = await f.plan(input);
  assert.equal(repeated.kind, 'ready');
  if (repeated.kind !== 'ready') assert.fail('publishing the plan must not change the merge');
  assert.equal(repeated.sourceRef, plan.sourceRef); assert.equal(repeated.diffRef, plan.diffRef); assert.equal(repeated.summaryRef, plan.summaryRef);
  assert.deepEqual(await f.artifacts.readBytes(result.blobRef), bytes);
  assert.equal(plan.summary.byteCount, Buffer.byteLength(plan.summary.utf8));
  assert.ok(plan.summary.byteCount < 1024);
});

test('only eligible regular files enter text merge; binary one-sided changes remain valid', async t => {
  const f = await fixture(t);
  const link = (target: string): WorkspaceEntry => ({ path: 'a', kind: 'symlink', mode: 0o777,
    target, targetDigest: sha256Bytes(Buffer.from(target)) });
  const cases: Array<{ base: WorkspaceEntry; current: WorkspaceEntry; desired: WorkspaceEntry; reason: string }> = [
    { base: await f.file('a', Buffer.from([0, 1])), current: await f.file('a', Buffer.from([0, 2])), desired: await f.file('a', Buffer.from([0, 3])), reason: 'non_text' },
    { base: await f.file('a', Buffer.from([0xff])), current: await f.file('a', 'current'), desired: await f.file('a', 'desired'), reason: 'non_text' },
    { base: await f.file('a', 'old'), current: await f.file('a', 'current', 0o755), desired: await f.file('a', 'desired'), reason: 'type_or_mode' },
    { base: link('one'), current: link('two'), desired: link('three'), reason: 'non_text' },
  ];
  for (const entry of cases) {
    const base = await f.source('base', [entry.base]), desired = await f.source('result', [entry.desired]), captured = await f.source('base', [entry.current]);
    const before = (await readdir(f.root)).sort();
    const plan = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref });
    assert.equal(plan.kind, 'conflict');
    if (plan.kind !== 'conflict') assert.fail('ineligible bilateral content must conflict');
    assert.equal(plan.conflicts[0].reason, entry.reason);
    for (const field of ['source', 'sourceRef', 'diff', 'diffRef', 'summary', 'summaryRef', 'publications']) assert.equal(Object.hasOwn(plan, field), false);
    assert.deepEqual((await readdir(f.root)).sort(), before);
    const oneSided = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: base.ref });
    assert.equal(oneSided.kind, 'ready');
    if (oneSided.kind === 'ready') assert.equal(oneSided.sourceRef, desired.ref);
  }
});

test('individually valid source graphs can conflict only after combination without inventing a root path', async t => {
  const f = await fixture(t), directory: WorkspaceEntry = { path: 'p', kind: 'directory', mode: 0o755 };
  const link = (name: string, target: string): WorkspaceEntry => ({ path: name, kind: 'symlink', mode: 0o777,
    target, targetDigest: sha256Bytes(Buffer.from(target)) });
  const cases: Array<{ base: WorkspaceEntry[]; current: WorkspaceEntry[]; desired: WorkspaceEntry[] }> = [
    { base: [directory], current: [], desired: [directory, await f.file('p/child', 'new')] },
    { base: [], current: [await f.file('Foo', 'current')], desired: [await f.file('foo', 'desired')] },
    { base: [], current: [link('a', 'b')], desired: [link('b', 'a')] },
  ];
  for (const value of cases) {
    const base = await f.source('base', value.base), desired = await f.source('result', value.desired), captured = await f.source('base', value.current);
    const before = (await readdir(f.root)).sort();
    const plan = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref });
    assert.equal(plan.kind, 'conflict');
    if (plan.kind !== 'conflict') assert.fail('the combined graph must not be repaired silently');
    assert.deepEqual(plan.conflicts, [{ reason: 'merged_graph' }]);
    assert.equal(Object.hasOwn(plan, 'sourceRef'), false); assert.equal(Object.hasOwn(plan, 'publications'), false);
    assert.deepEqual((await readdir(f.root)).sort(), before);
  }
  const base = await f.source('base', []), bad = await f.source('result', [await f.file('p/child', 'bad input')]);
  await assert.rejects(f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: bad.ref, capturedWorkspaceRef: base.ref }),
    error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
});

test('complete role, workspace, entry, projection and ignore identities are checked before merging', async t => {
  const f = await fixture(t), entry = await f.file('a', 'data');
  const base = await f.source('base', [entry]), desired = await f.source('result', [entry]);
  for (const changes of [
    { role: 'base' }, { workspaceIdentityDigest: '1'.repeat(64) }, { sourceProjectionDigest: '2'.repeat(64) },
    { frozenIgnoreRulesDigest: '3'.repeat(64) }, { treeDigest: '4'.repeat(64) }, { unknown: true },
  ]) {
    const bad = await f.source('result', [entry], changes as Partial<SourceManifest>);
    await assert.rejects(f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: bad.ref, capturedWorkspaceRef: base.ref }),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
  }
  assert.equal(entry.kind, 'file');
  if (entry.kind !== 'file') assert.fail('fixture must contain a file');
  const badSize = await f.source('result', [{ ...entry, size: entry.size + 1 }]);
  await assert.rejects(f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: badSize.ref, capturedWorkspaceRef: base.ref }),
    error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
  const unsafe = await f.source('result', [{ path: 'A', kind: 'directory', mode: 0o755 }, { path: 'a', kind: 'directory', mode: 0o755 }]);
  await assert.rejects(f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: unsafe.ref, capturedWorkspaceRef: base.ref }),
    error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
  const selected = { sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: base.ref };
  const pending = f.plan(selected); selected.sourceDesiredRef = badSize.ref;
  const plan = await pending;
  assert.equal(plan.kind, 'ready'); assert.equal(plan.input.sourceDesiredRef, desired.ref);
});

test('forged Git identity, missing include authorization and unproven ignore data are rejected', async t => {
  const f = await fixture(t), entry = await f.file('a', 'data'), base = await f.source('base', [entry]);
  const git = await f.source('result', [entry], { git: { repositoryIdentityDigest: '1'.repeat(64),
    head: { kind: 'unborn', branch: 'main' }, indexRef: '2'.repeat(64), indexTreeObjectId: '3'.repeat(40) } });
  await assert.rejects(f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: git.ref, capturedWorkspaceRef: base.ref }),
    error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
  for (const unsupported of ['includes', 'ignore'] as const) {
    const rules = { ...f.rules, ...(unsupported === 'ignore' ? { rules: [{ order: 0, sourceIndex: 0, sourceLine: 1,
      baseDirectory: '', negated: false, directoryOnly: false, anchored: false, pattern: 'ignored' }] } : {}), rulesDigest: '' };
    rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
    const rulesRef = (await f.artifacts.publishCanonical(rules, rules.format)).ref;
    const projection = { ...f.projection, frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest,
      ...(unsupported === 'includes' ? { explicitIncludes: [{ path: 'a', scope: 'entry' as const, authorizationRef: '1'.repeat(64) }] } : {}), projectionDigest: '' };
    projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
    const projectionRef = (await f.artifacts.publishCanonical(projection, 'cliq-source-projection-v1')).ref;
    const changes = { sourceProjectionRef: projectionRef, sourceProjectionDigest: projection.projectionDigest,
      frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest };
    const b = await f.source('base', [entry], changes), s = await f.source('result', [entry], changes);
    const planned = f.plan({ sourceBaseRef: b.ref, sourceDesiredRef: s.ref, capturedWorkspaceRef: b.ref });
    if (unsupported === 'includes') await assert.rejects(planned, { code: 'ENOENT' });
    else await assert.rejects(planned, error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
  }
});

test('unchanged blobs are completely rehashed even when another path would produce a text conflict', async t => {
  const f = await fixture(t), retained = await f.file('z', 'retained'), base = await f.source('base', [await f.file('a', 'base'), retained]);
  const desired = await f.source('result', [await f.file('a', 'desired'), retained]);
  const captured = await f.source('base', [await f.file('a', 'current'), retained]);
  assert.equal(retained.kind, 'file'); if (retained.kind !== 'file') assert.fail('fixture must contain a file');
  const actual = path.join(f.root, retained.blobRef);
  await chmod(actual, 0o600); await writeFile(actual, Buffer.from('RETAINED')); await chmod(actual, 0o400);
  await assert.rejects(f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref }), /byte count|corrupt/u);
});

test('ordinary files may reuse structured bytes without schema labels substituting for either validation', async t => {
  const f = await fixture(t), shared = await f.file('data.json', canonicalJsonBytes(f.projection));
  assert.equal(shared.kind, 'file'); if (shared.kind !== 'file') assert.fail('fixture must contain a file');
  assert.equal(shared.blobRef, f.projectionRef);
  const base = await f.source('base', [shared]), desired = await f.source('result', [shared]);
  const plan = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: base.ref });
  assert.equal(plan.kind, 'ready');
  const descriptions = plan.metadata.filter(value => value.ref === f.projectionRef);
  assert.equal(descriptions.length, 1); assert.equal(descriptions[0].schemaKind, 'cliq-source-projection-v1');
});

test('frozen result limits return deterministic measured refusals without publishing partial source', async t => {
  for (const [limits, reason] of [[{ maxChangedPaths: 0 }, 'changed_paths'], [{ maxChangedBytes: 0 }, 'changed_bytes']] as const) {
    const f = await fixture(t, limits), base = await f.source('base', [await f.file('a', 'before')]);
    const desired = await f.source('result', [await f.file('a', 'after')]), before = (await readdir(f.root)).sort();
    const plan = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: base.ref });
    assert.deepEqual(plan.kind === 'limited' && plan.limit, { kind: reason, observed: reason === 'changed_paths' ? 1 : 5, limit: 0 });
    for (const field of ['source', 'sourceRef', 'entries', 'diff', 'diffRef', 'summary', 'summaryRef', 'publications'])
      assert.equal(Object.hasOwn(plan, field), false);
    assert.deepEqual((await readdir(f.root)).sort(), before);
  }
});

test('owner cancellation and arbitrary work errors remain errors, never deterministic source limits', async t => {
  const f = await fixture(t), long = 'x'.repeat(50_000), base = await f.source('base', [await f.file('a', `${long}\ntail`)]);
  const desired = await f.source('result', [await f.file('a', `${long}\nTAIL`)]);
  const captured = await f.source('base', [await f.file('a', `y${long}\ntail`)]);
  const input = { sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref };
  const before = (await readdir(f.root)).sort(), cancellation = new Error('owner cancelled merge'), resource = new Error('owner exhausted merge work');
  const early = new AbortController(), pending = f.plan(input, { signal: early.signal }); early.abort(cancellation);
  await assert.rejects(pending, error => error === cancellation);
  await assert.rejects(f.plan(input, { onWork: ({ totalWork }) => { if (totalWork >= 4096) throw resource; } }), error => error === resource);
  const controller = new AbortController();
  await assert.rejects(f.plan(input, { signal: controller.signal,
    onWork: ({ totalWork }) => { if (totalWork >= 4096) setImmediate(() => controller.abort(cancellation)); } }), error => error === cancellation);
  assert.deepEqual((await readdir(f.root)).sort(), before);
});

test('a parent catalog cancellation after real diff3 work rejects the same computation without partial publication', async t => {
  const f = await fixture(t), long = 'x'.repeat(50_000), base = await f.source('base', [await f.file('a', `${long}\ntail`)]);
  const desired = await f.source('result', [await f.file('a', `${long}\nTAIL`)]);
  const captured = await f.source('base', [await f.file('a', `y${long}\ntail`)]);
  const before = (await readdir(f.root)).sort(), parent = new AbortController(), reason = new Error('parent catalog revoked during diff3');
  const view = f.artifacts.withReadSignal(parent.signal);
  let worked = false;
  await assert.rejects(planDeliverySource(view, { sourceBaseRef: base.ref, sourceDesiredRef: desired.ref,
    capturedWorkspaceRef: captured.ref, sandboxProfileRef: f.sandboxProfileRef }, {
    onWork({ totalWork }) { if (totalWork >= 4096 && !worked) { worked = true; parent.abort(reason); } }
  }), error => error === reason);
  assert.equal(worked, true, 'the original complete CAS reads must reach real diff3 CPU work before cancellation');
  assert.deepEqual((await readdir(f.root)).sort(), before);
});

test('merged regular bytes and largest file reproduce the frozen profile limits without counting symlink payloads', async t => {
  const f = await fixture(t, { maxChangedBytes: 4 * 1024 ** 3 },
    { maxGenerationBytes: 256 * 1024 ** 2, maxSingleFileBytes: 1024 ** 2 });
  const shared = await f.file('shared', Buffer.alloc(1024 ** 2, 42));
  const files = (count: number) => Array.from({ length: count }, (_, index) => ({ ...shared, path: `file-${String(index).padStart(3, '0')}` }));
  const base = await f.source('base', []), captured = await f.source('base', files(128)), desired = await f.source('result', files(257).slice(128));
  const before = (await readdir(f.root)).sort();
  const over = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref });
  assert.deepEqual(over.kind === 'limited' && over.limit, { kind: 'generation_bytes', observed: 257 * 1024 ** 2, limit: 256 * 1024 ** 2 });
  const exactSource = await f.source('result', files(256));
  const exact = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: exactSource.ref, capturedWorkspaceRef: base.ref });
  assert.equal(exact.kind, 'ready');
  const link = { path: 'link', kind: 'symlink' as const, mode: 0o777, target: 'file-000', targetDigest: sha256Bytes(Buffer.from('file-000')) };
  const withLink = await f.source('result', [...files(256), link]);
  assert.equal((await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: withLink.ref, capturedWorkspaceRef: base.ref })).kind, 'ready');
  // Each genuine byte input fits 1 MiB; disjoint line insertions combine to
  // 1 MiB + 1 only in M. No oversized input is passed off as an admitted Run.
  const firstLine = 'a'.repeat(524_287), lastLine = 'b'.repeat(524_287);
  const textBase = await f.source('base', [await f.file('large', `${firstLine}\n${lastLine}`)]);
  const big = await f.source('result', [await f.file('large', `${firstLine}a\n${lastLine}`)]);
  const textCaptured = await f.source('base', [await f.file('large', `${firstLine}\n${lastLine}b`)]);
  const singleInput = { sourceBaseRef: textBase.ref, sourceDesiredRef: big.ref, capturedWorkspaceRef: textCaptured.ref };
  const single = await f.plan(singleInput);
  assert.deepEqual(single.kind === 'limited' && single.limit, { kind: 'single_file_bytes', observed: 1024 ** 2 + 1, limit: 1024 ** 2 });
  const afterPlanning = (await readdir(f.root)).sort();
  assert.ok(afterPlanning.length > before.length, 'only explicit fixture publications add new CAS objects');
  const againBefore = afterPlanning;
  const again = await f.plan(singleInput);
  assert.deepEqual(again, single); assert.deepEqual((await readdir(f.root)).sort(), againBefore);
});

test('fixed limit precedence, equality and original profile integrity are reproduced from complete CAS bytes', async t => {
  const f = await fixture(t, { maxChangedPaths: 1, maxChangedBytes: 1 }, { maxSingleFileBytes: 1024 ** 2 });
  const base = await f.source('base', []), bigFile = await f.file('large', Buffer.alloc(1024 ** 2 + 1, 45));
  const desired = await f.source('result', [bigFile, await f.file('second', 'b')]);
  const input = { sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: base.ref };
  const paths = await f.plan(input);
  assert.deepEqual(paths.kind === 'limited' && paths.limit, { kind: 'changed_paths', observed: 2, limit: 1 });
  const oneFile = await f.source('result', [bigFile]);
  const bytes = await f.plan({ ...input, sourceDesiredRef: oneFile.ref });
  assert.deepEqual(bytes.kind === 'limited' && bytes.limit, { kind: 'changed_bytes', observed: 1024 ** 2 + 1, limit: 1 });
  const exactSource = await f.source('result', [await f.file('one', 'a')]);
  assert.equal((await f.plan({ ...input, sourceDesiredRef: exactSource.ref })).kind, 'ready');
  const profile = await f.artifacts.readCanonical<Record<string, unknown>>(f.sandboxProfileRef);
  const invalidProfile = await f.artifacts.publishCanonical({ ...profile, ignored: true }, 'cliq-sandbox-profile-v1');
  await assert.rejects(planDeliverySource(f.artifacts, { ...input, sandboxProfileRef: invalidProfile.ref }), { code: 'ARTIFACT_MISMATCH' });
  assert.equal(bigFile.kind, 'file');
  if (bigFile.kind !== 'file') assert.fail('fixture must be regular');
  const blobPath = path.join(f.root, bigFile.blobRef);
  await chmod(blobPath, 0o600); await writeFile(blobPath, Buffer.alloc(bigFile.size, 46)); await chmod(blobPath, 0o400);
  await assert.rejects(f.plan(input), /corrupt/u);
});

test('a limited text merge retains only completely read source metadata, never unpublished M artifacts', async t => {
  const f = await fixture(t, { maxChangedPaths: 0 }), base = await f.source('base', [await f.file('a', 'head\ntail\n')]);
  const desired = await f.source('result', [await f.file('a', 'HEAD\ntail\n')]), captured = await f.source('base', [await f.file('a', 'head\nTAIL\n')]);
  const before = (await readdir(f.root)).sort();
  const limited = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref });
  assert.equal(limited.kind, 'limited');
  for (const metadata of limited.metadata) assert.equal((await f.artifacts.readBytes(metadata.ref)).byteLength, metadata.byteLength);
  assert.deepEqual((await readdir(f.root)).sort(), before);
});

test('a merge with 100001 explicit entries proves the fixed walker entry ceiling is exceeded even when its diff fits', async t => {
  const f = await fixture(t), common: WorkspaceEntry[] = Array.from({ length: 99_999 }, (_, index) =>
    ({ path: `d${String(index).padStart(6, '0')}`, kind: 'directory', mode: 0o755 }));
  const base = await f.source('base', common);
  const desired = await f.source('result', [...common, { path: 'source-added', kind: 'directory', mode: 0o755 }]);
  const captured = await f.source('base', [...common, { path: 'user-added', kind: 'directory', mode: 0o755 }]);
  const before = (await readdir(f.root)).sort();
  const limited = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref });
  assert.deepEqual(limited.kind === 'limited' && limited.limit, { kind: 'merged_entries', observed: 100_001, limit: 100_000 });
  assert.deepEqual((await readdir(f.root)).sort(), before);
  // Removing the bilateral addition is an exact 100000-entry output. This is
  // not a proof that a real walk has no other hidden/excluded inventory.
  const exact = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: base.ref });
  assert.equal(exact.kind, 'ready');
});

test('add, delete, mode and type fast paths preserve full entries while bilateral differences conflict', async t => {
  const f = await fixture(t), old = await f.file('a', 'old'), changed = await f.file('a', 'new'), other = await f.file('a', 'other');
  const executable = await f.file('a', 'old', 0o755);
  const link: WorkspaceEntry = { path: 'a', kind: 'symlink', mode: 0o777, target: 'safe', targetDigest: sha256Bytes(Buffer.from('safe')) };
  const directory: WorkspaceEntry = { path: 'a', kind: 'directory', mode: 0o755 };
  const cases: Array<{ base?: WorkspaceEntry; current?: WorkspaceEntry; desired?: WorkspaceEntry; expected?: WorkspaceEntry; conflict?: string }> = [
    { current: changed, desired: changed, expected: changed },
    { current: changed, desired: other, conflict: 'add_add' },
    { base: old },
    { base: old, desired: changed, conflict: 'delete_modify' },
    { base: old, current: changed, conflict: 'delete_modify' },
    { base: old, current: old },
    { base: old, desired: old },
    { base: old, current: old, desired: executable, expected: executable },
    { base: old, current: executable, desired: old, expected: executable },
    { base: old, current: old, desired: link, expected: link },
    { base: old, current: old, desired: directory, expected: directory },
    { base: old, current: directory, desired: old, expected: directory },
    { base: old, current: link, desired: changed, conflict: 'type_or_mode' },
    { base: old, current: executable, desired: changed, conflict: 'type_or_mode' },
    { base: old, current: link, desired: link, expected: link },
  ];
  for (const value of cases) {
    const base = await f.source('base', value.base ? [value.base] : []);
    const desired = await f.source('result', value.desired ? [value.desired] : []);
    const captured = await f.source('base', value.current ? [value.current] : []);
    const plan = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref });
    assert.equal(plan.kind, value.conflict ? 'conflict' : 'ready', JSON.stringify(value));
    if (plan.kind === 'ready') assert.deepEqual(plan.entries.entries, value.expected ? [value.expected] : []);
    else assert.equal(plan.conflicts[0].reason, value.conflict);
  }
});

test('legal one-sided directory additions, removals and complete type replacement remain data, not publication-subset conflicts', async t => {
  const f = await fixture(t), dir: WorkspaceEntry = { path: 'p', kind: 'directory', mode: 0o755 };
  const child = await f.file('p/child', 'data'), replacement = await f.file('p', 'replacement');
  for (const [baseEntries, desiredEntries] of [
    [[], [dir]], [[dir], []], [[dir, child], [replacement]], [[replacement], [dir, child]],
  ] as Array<[WorkspaceEntry[], WorkspaceEntry[]]>) {
    const base = await f.source('base', baseEntries), desired = await f.source('result', desiredEntries);
    const plan = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: base.ref });
    assert.equal(plan.kind, 'ready');
    if (plan.kind !== 'ready') assert.fail('data projection cannot hide a missing publication primitive');
    assert.equal(plan.sourceRef, desired.ref); assert.equal(plan.identicalToSourceDesired, true);
    assert.deepEqual(plan.entries.entries, desired.entries.entries);
    assert.deepEqual(plan.diff.operations.map(value => value.path), [...new Set([...baseEntries, ...desiredEntries].map(value => value.path))]
      .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))));
  }
});

test('text content is rehashed per path rather than retained from a whole-graph decoded cache', async t => {
  const f = await fixture(t), laterDesired = await f.file('b', 'first\nkeep\nEND');
  const base = await f.source('base', [await f.file('a', 'one\nkeep\nlast'), await f.file('b', 'first\nkeep\nend')]);
  const desired = await f.source('result', [await f.file('a', 'one\nkeep\nLAST'), laterDesired]);
  const captured = await f.source('base', [await f.file('a', 'ONE\nkeep\nlast'), await f.file('b', 'FIRST\nkeep\nend')]);
  assert.equal(laterDesired.kind, 'file'); if (laterDesired.kind !== 'file') assert.fail('fixture must contain a file');
  const before = (await readdir(f.root)).sort();
  let changed = false;
  await assert.rejects(f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref }, {
    // Only this disposable fixture's storage is changed; no process pause,
    // synthetic proof or production source is involved in the read regression.
    onWork: () => {
      if (changed) return; changed = true;
      const actual = path.join(f.root, laterDesired.blobRef);
      chmodSync(actual, 0o600); writeFileSync(actual, Buffer.alloc(laterDesired.size, 0x51)); chmodSync(actual, 0o400);
    },
  }), /corrupt/u);
  assert.equal(changed, true);
  assert.deepEqual((await readdir(f.root)).sort(), before);
});

test('merged bytes already retained at another input path reuse that blob with no duplicate publication', async t => {
  const f = await fixture(t), existing = await f.file('z', 'ONE\nkeep\nLAST');
  const base = await f.source('base', [await f.file('a', 'one\nkeep\nlast'), existing]);
  const desired = await f.source('result', [await f.file('a', 'one\nkeep\nLAST'), existing]);
  const captured = await f.source('base', [await f.file('a', 'ONE\nkeep\nlast'), existing]);
  const plan = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref });
  assert.equal(plan.kind, 'ready');
  if (plan.kind !== 'ready') assert.fail('disjoint edits may select an already retained blob');
  const merged = plan.entries.entries[0]; assert.equal(merged.kind, 'file'); assert.equal(existing.kind, 'file');
  if (merged.kind !== 'file' || existing.kind !== 'file') assert.fail('both entries must remain regular files');
  assert.equal(merged.blobRef, existing.blobRef);
  assert.equal(plan.metadata.filter(value => value.ref === existing.blobRef).length, 1);
  assert.equal(plan.publications.some(value => value.ref === existing.blobRef), false);
});

test('text work observations accumulate across paths so an owner budget cannot reset at each file', async t => {
  const f = await fixture(t);
  const base = await f.source('base', [await f.file('a', 'one\nkeep\nlast'), await f.file('b', 'first\nkeep\nend')]);
  const desired = await f.source('result', [await f.file('a', 'one\nkeep\nLAST'), await f.file('b', 'first\nkeep\nEND')]);
  const captured = await f.source('base', [await f.file('a', 'ONE\nkeep\nlast'), await f.file('b', 'FIRST\nkeep\nend')]);
  let previous = -1, starts = 0;
  const plan = await f.plan({ sourceBaseRef: base.ref, sourceDesiredRef: desired.ref, capturedWorkspaceRef: captured.ref }, {
    onWork: ({ phase, totalWork }) => {
      assert.ok(totalWork >= previous, `text-work budget reset from ${previous} to ${totalWork}`);
      if (phase === 'tokenize') starts++;
      previous = totalWork;
    },
  });
  assert.equal(plan.kind, 'ready'); assert.equal(starts, 2);
  assert.ok(previous > 0);
});
