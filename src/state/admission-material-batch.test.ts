import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import ts from 'typescript';
import { KERNEL_CAS_DIRECTORY } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { SourceInspectionRetirementEvidenceV1, SourceInspectionTargetV1 } from '../kernel/execution.js';
import { createSourceInspectionFixture } from './testing/source-inspection-fixtures.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError } from './errors.js';
import { openStateStore } from './store.js';

test('real source capture durably joins its target triple and retirement pair without moving capture or replay', async t => {
  const fixture = await createSourceInspectionFixture(t, 'fixed-admission-groups');
  await writeFile(path.join(fixture.workspace, 'one.txt'), 'one complete source file\n');
  await writeFile(path.join(fixture.workspace, 'two.txt'), 'two complete source file\n');
  const casRoot = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY), open = fs.open.bind(fs);
  const active = new Set<object>(); let fileSyncs = 0, rootSyncs = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
    const handle = await open(...args); active.add(handle);
    const close = handle.close.bind(handle), sync = handle.sync.bind(handle);
    t.mock.method(handle, 'close', async () => { await close(); active.delete(handle); });
    t.mock.method(handle, 'sync', async () => { await sync(); if (args[0] === casRoot) rootSyncs++; else fileSyncs++; });
    return handle;
  });
  try {
    const retired = await fixture.store.captureSubmittedSource({ request: fixture.request, identity: fixture.identity });
    assert.equal(retired.phase, 'retired');
    assert.equal(retired.outcome.kind, 'captured');
    assert.equal(active.size, 0, 'the original CAS descriptors close before capture can return');
    assert.equal(fileSyncs, 11, 'all eleven original files still receive their own real data fsync');
    assert.equal(rootSyncs, 32, 'target3 and retirement2 share only their own four namespace boundaries');
    const target = await fixture.store.artifacts.readCanonical<SourceInspectionTargetV1>(retired.targetRef);
    assert.equal(target.originalRequestRef, canonicalSha256(fixture.request));
    assert.deepEqual(await fixture.store.artifacts.readCanonical(target.originalRequestRef), fixture.request);
    const evidence = await fixture.store.artifacts.readCanonical<SourceInspectionRetirementEvidenceV1>(retired.retirementEvidenceRef);
    assert.equal(evidence.targetRef, retired.targetRef);
    assert.equal(evidence.captureOwnerClosure.kind, 'local_resources_joined');
    assert.equal(evidence.stagingObservation, 'exact_reserved_root_absent');
    assert.deepEqual(await readdir(path.join(fixture.stateRoot, 'runtime/source-inspections')), []);
    const before = await readdir(casRoot), synced = rootSyncs;
    assert.deepEqual(await fixture.store.captureSubmittedSource({ request: fixture.request, identity: fixture.identity }), retired);
    assert.equal(rootSyncs, synced, 'retained replay remains read-only and does not rerun a durability group');
    assert.deepEqual(await readdir(casRoot), before);
    assert.equal(active.size, 0);
  } finally { t.mock.restoreAll(); }
});

async function modelMaterialPublisher() {
  // Execute the actual inert publication body with a real CAS. This does not
  // create an installed runtime, grant, Run, StateOwner or execution proof.
  const source = await readFile(new URL('./installed-run.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('installed-run.ts', source, ts.ScriptTarget.Latest, true);
  const functions = parsed.statements.filter(ts.isFunctionDeclaration);
  const helper = functions.find(node => node.name?.text === 'publishInstalledModelMaterial');
  let body: string;
  if (helper) body = helper.getText(parsed) + '; return publishInstalledModelMaterial;';
  else {
    const start = source.indexOf('    const endpointArtifact = await artifacts.publishCanonical(endpoint, endpoint.format), credentialGrantRefs: string[] = [];');
    const end = source.indexOf('    const toolCandidates =', start);
    assert(start >= 0 && end > start, 'the original model material publisher must remain identifiable');
    body = `async function publishInstalledModelMaterial(input) {
      const {artifacts,endpoint,credentialBindings,remote,identity,admittedAt,deadlineAt,catalog,installed}=input;
      ${source.slice(start, end)}
      return {endpointArtifact,credentialGrantRefs,capabilityArtifact};
    }; return publishInstalledModelMaterial;`;
  }
  const output = ts.transpileModule(body, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  return new Function('canonicalSha256', 'digestOmitting', 'mismatch', output)(canonicalSha256, digestOmitting,
    (message: string): never => { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }) as
    (input: Record<string, unknown>) => Promise<{ endpointArtifact: { ref: string }; credentialGrantRefs: string[]; capabilityArtifact: { ref: string } }>;
}

function inertMaterial(artifacts: ArtifactCatalog, count = 1) {
  const admittedAt = '2026-10-25T00:00:00.000Z', deadlineAt = '2026-10-25T00:01:00.000Z';
  const endpoint = { format: 'cliq-endpoint-registration-v1', ownerPrincipalId: 'inert-principal',
    endpointIdentityDigest: 'e'.repeat(64), tlsPolicyDigest: 'f'.repeat(64) };
  const credentialBindings = Array.from({ length: count }, (_, index) => ({ credentialGrantId: `inert-grant-${index}`,
    ownerPrincipalId: 'inert-principal', purpose: 'model_endpoint', endpointRegistrationRef: canonicalSha256(endpoint),
    endpointIdentityDigest: endpoint.endpointIdentityDigest, tlsPolicyDigest: endpoint.tlsPolicyDigest,
    createdAt: admittedAt, expiresAt: deadlineAt }));
  const catalog = { provider: 'inert-provider', model: 'inert-model', endpointIdentityDigest: endpoint.endpointIdentityDigest,
    adapter: { adapterId: 'inert-adapter' }, catalogEntryDigest: 'c'.repeat(64), claims: { streaming: false }, validThrough: deadlineAt };
  const capability = { schemaVersion: 1, format: 'cliq-model-capability-evidence-v1', provider: catalog.provider, model: catalog.model,
    endpointIdentityDigest: catalog.endpointIdentityDigest, adapter: catalog.adapter,
    source: { kind: 'signed_catalog', runtimeBundleRef: 'b'.repeat(64), catalogEntryRef: 'd'.repeat(64), catalogEntryDigest: catalog.catalogEntryDigest },
    ...catalog.claims, observedAt: admittedAt, validThrough: deadlineAt, evidenceDigest: '' };
  capability.evidenceDigest = digestOmitting(capability, 'evidenceDigest');
  return { artifacts, endpoint, credentialBindings, capability,
    remote: { modelCredentialGrantIds: credentialBindings.map(binding => binding.credentialGrantId) },
    identity: { principalId: 'inert-principal' }, admittedAt, deadlineAt, catalog, installed: { bundleDigest: 'b'.repeat(64) } };
}

test('one credential model material preserves its bytes and joins one real four-stage triple', async t => {
  const publish = await modelMaterialPublisher();
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-admission-material-')); await fs.chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root)), input = inertMaterial(artifacts);
  const open = fs.open.bind(fs), active = new Set<object>(); let roots = 0, files = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
    const handle = await open(...args); active.add(handle);
    const sync = handle.sync.bind(handle), close = handle.close.bind(handle);
    t.mock.method(handle, 'sync', async () => { await sync(); if (args[0] === root) roots++; else files++; });
    t.mock.method(handle, 'close', async () => { await close(); active.delete(handle); }); return handle;
  });
  try {
    const result = await publish(input);
    assert.equal(roots, 4, 'the three model material objects share four namespace boundaries, not twelve');
    assert.equal(files, 3); assert.equal(active.size, 0);
    assert.equal(result.endpointArtifact.ref, canonicalSha256(input.endpoint));
    assert.deepEqual(result.credentialGrantRefs, [canonicalSha256(input.credentialBindings[0])]);
    assert.equal(result.capabilityArtifact.ref, canonicalSha256(input.capability));
    for (const value of [input.endpoint, ...input.credentialBindings, input.capability])
      assert.deepEqual(await artifacts.readBytes(canonicalSha256(value)), canonicalJsonBytes(value));
    assert.equal(active.size, 0);
  } finally { t.mock.restoreAll(); }
});

test('non-single credential inert publication keeps the original ordinary path without dummy members', async t => {
  const publish = await modelMaterialPublisher(), root = await mkdtemp(path.join(os.tmpdir(), 'cliq-material-ordinary-'));
  await fs.chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root)), input = inertMaterial(artifacts, 2);
  const open = fs.open.bind(fs); let roots = 0, files = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
    const handle = await open(...args), sync = handle.sync.bind(handle);
    t.mock.method(handle, 'sync', async () => { await sync(); if (args[0] === root) roots++; else files++; });
    return handle;
  });
  const result = await publish(input);
  assert.equal(roots, 16); assert.equal(files, 4);
  assert.deepEqual(result.credentialGrantRefs, input.credentialBindings.map(canonicalSha256).sort());
  assert.equal((await readdir(root)).length, 4);
  // This publisher cannot change the installed recipe's existing one-bearer
  // refusal. No multi-credential Run or installed capability is constructed.
});

test('the original single-credential binding rejections remain before the fixed publication', async t => {
  const publish = await modelMaterialPublisher(), root = await mkdtemp(path.join(os.tmpdir(), 'cliq-material-refusal-'));
  await fs.chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  for (const changes of [{ credentialGrantId: 'foreign' }, { ownerPrincipalId: 'foreign' }, { purpose: 'foreign' },
    { endpointRegistrationRef: 'a'.repeat(64) }, { endpointIdentityDigest: 'a'.repeat(64) }, { tlsPolicyDigest: 'a'.repeat(64) },
    { createdAt: '2026-10-25T00:00:00.001Z' }, { expiresAt: '2026-10-25T00:00:59.999Z' }]) {
    const input = inertMaterial(artifacts);
    Object.assign(input.credentialBindings[0]!, changes);
    await assert.rejects(publish(input), error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    assert.deepEqual(await readdir(root), []);
  }
});

test('actual source shutdown during the target triple joins every issued file before original owner release', async t => {
  const fixture = await createSourceInspectionFixture(t, 'target-group-cancel');
  const open = fs.open.bind(fs), active = new Set<object>(); let closing: Promise<void> | undefined, reached = false;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
    const handle = await open(...args); active.add(handle);
    const write = handle.writeFile.bind(handle), close = handle.close.bind(handle);
    t.mock.method(handle, 'close', async () => { await close(); active.delete(handle); });
    if (String(args[0]).includes('/.tmp-stream-')) t.mock.method(handle, 'writeFile', async (...values: Parameters<typeof write>) => {
      await write(...values);
      if (!reached && values[0] instanceof Uint8Array && Buffer.from(values[0]).includes(Buffer.from('cliq-source-inspection-target-v1'))) {
        reached = true; closing = fixture.store.close();
      }
    });
    return handle;
  });
  const pending = fixture.store.captureSubmittedSource({ request: fixture.request, identity: fixture.identity });
  try {
    await assert.rejects(pending, error => error instanceof Error && error.name === 'AbortError');
    assert.equal(reached, true); assert(closing); await closing;
    assert.equal(active.size, 0);
    assert((await readdir(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY))).every(name => /^[a-f0-9]{64}$/u.test(name)));
    await assert.rejects(fs.lstat(path.join(fixture.stateRoot, 'runtime/source-inspections')),
      error => error instanceof Error && 'code' in error && error.code === 'ENOENT');
  } finally { await Promise.allSettled([pending, ...(closing ? [closing] : [])]); t.mock.restoreAll(); }
  const successor = await openStateStore(fixture.stateRoot, fixture.authority);
  try { assert.equal(successor.ownerEpoch, fixture.store.ownerEpoch + 1); } finally { await successor.close(); }
});

test('installed model material remains inside the original full admission and cannot replace material or final authority checks', async () => {
  const source = await readFile(new URL('./installed-run.ts', import.meta.url), 'utf8');
  const start = source.indexOf('export async function assembleInstalledRun('), end = source.indexOf('admissions.set(result,', start);
  assert(start >= 0 && end > start);
  const assembly = source.slice(start, end), phases = ['publishInstalledModelMaterial({', 'await materialFor(installed, reads, assembly, signal)',
    'verifyToolRuntimeAuthority(', 'await artifacts.publishCanonical(sandbox, sandbox.format)', 'await prepareInstalledVerifierAssembly(',
    'await artifacts.publishCanonical(policy, policy.format)', 'await installed.revalidate(signal)',
    'await validateControlChannelClosure(reads, owner, identity)', 'assertActiveStateOwner(driver, owner)'];
  let previous = assembly.indexOf(phases[0]!); assert(previous >= 0);
  for (const phase of phases.slice(1)) { const index = assembly.indexOf(phase, previous + 1); assert(index > previous, phase); previous = index; }
  const parsed = ts.createSourceFile('installed-run.ts', source, ts.ScriptTarget.Latest, true);
  const material = parsed.statements.find((node): node is ts.FunctionDeclaration => ts.isFunctionDeclaration(node) && node.name?.text === 'materialFor');
  assert(material?.body);
  assert(material.body.getText(parsed).includes('await readRetainedVerifierToolchain(artifacts,'));
  assert(material.body.getText(parsed).includes('signal?.throwIfAborted();'));
});
