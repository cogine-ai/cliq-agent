// Actual result-preparation composition with inert dependency nodes and real
// CAS publication/retirement. No StateOwner, accepted Run or native proof is
// constructed; actual installed execution remains an independent Linux gate.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { Script } from 'node:vm';
import ts from 'typescript';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError, ResourceRetirementError, stateOperation } from './errors.js';

const gate = () => {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
};

async function resultFactory(dependencies: Record<string, unknown>) {
  const source = ts.createSourceFile('run-result.ts', await readFile(new URL('./run-result.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const declaration = source.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'loadRunResult');
  assert(declaration);
  const js = ts.transpileModule(declaration.getText(source).replace(/^export\s+/u, ''),
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const names = Object.keys(dependencies);
  return new Script(`(function(${names.join(',')}) { ${js}; return loadRunResult; })`).runInThisContext()(...Object.values(dependencies));
}

async function fixture(t: TestContext, publicationFailure?: Error) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-result-read-lifetime-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const objects = path.join(root, 'objects'); await mkdir(objects, { mode: 0o700 });
  const cas = new ContentAddressedStore(objects), artifacts = new ArtifactCatalog(cas), stop = new AbortController();
  const spec = { operation: 'agent' }, candidate = { itemId: 'inert-candidate', resultSourceRef: 'inert-source' };
  const frontier = { schemaVersion: 1, kind: 'verify', phase: 'verifiers', candidateItemId: candidate.itemId,
    resultSourceRef: candidate.resultSourceRef, verifierPlanRef: 'inert-plan', nextVerifierIndex: 0, afterPass: 'finalize' };
  const frontierRef = (await artifacts.publishCanonical(frontier, 'inert-frontier-data')).ref;
  const nodeRef = (await artifacts.publishCanonical({ kind: 'inert-basis-node' }, 'inert-data')).ref;
  const run = { id: 'inert-run', specRef: canonicalSha256(spec), createdAt: '2026-01-01T00:00:00.000Z',
    deadlineAt: '2026-01-01T01:00:00.000Z', revision: 2, status: 'queued', nextStep: 'verify', frontierRef };
  const cut = { run, runSpec: spec, latestCheckpoint: { id: 'inert-checkpoint' }, items: [], journal: [] };
  const basis = { candidate, plan: { entries: [] }, planRef: 'inert-plan', progress: {},
    principalId: 'inert-principal', completionCheckpoint: { id: 'inert-checkpoint' } };
  const started = gate(), release = gate();
  const closure = { format: 'inert-closure-data', kind: 'no-authority' }, bytes = canonicalJsonBytes(closure);
  let publicationJoined = false, sqlTransactions = 0, publications = 0;
  artifacts.publishCanonical = async () => {
    publications++;
    try {
      return await artifacts.publishChunks((async function* () {
        started.resolve(); await release.promise;
        if (publicationFailure) throw publicationFailure;
        yield bytes;
      })(), 'application/json', 'inert-closure-data', bytes.length);
    } finally { publicationJoined = true; }
  };
  const driver = { prepare: () => ({ all: () => [] }), transaction: () => { sqlTransactions++; throw new Error('inert data cannot commit'); } };
  const owner = Object.freeze({ kind: 'inert-data-owner-label' });
  const create = await resultFactory({
    exactKeys, canonicalSha256, requireEqual, stateOperation, KernelStorageError, readCanonicalArtifact,
    assertActiveStateOwner: (actualDriver: unknown, actualOwner: unknown) => {
      assert.equal(actualDriver, driver); assert.equal(actualOwner, owner);
    },
    observeInstalledPublicationWork: (_id: string, _kind: string, operation: () => Promise<unknown>) => operation(),
    readRecoveryClosure: async (_driver: unknown, reads: ArtifactCatalog) => {
      await readCanonicalArtifact(reads, nodeRef); return cut;
    },
    readResultBasis: async () => basis,
    readResultRecoveryClosure: async (_driver: unknown, reads: ArtifactCatalog) => {
      await readCanonicalArtifact(reads, nodeRef); return { cut, basis };
    },
    readWorkerLaunchesForRun: () => [], readWorkspaceGenerationsForRun: () => [], readChildAllocationsForRun: () => [],
    sampleCanonicalNow: () => '2026-01-01T00:00:01.000Z',
    expectedVerificationClosure: () => closure,
    decodeVerificationClosure: (value: unknown) => { assert.equal(value, closure); return value; },
    expectedInheritedVerificationProvenance: () => undefined,
    verificationCheckpointId: () => 'inert-verification-checkpoint'
  });
  const result = create(driver, artifacts, owner, { run, spec, principalId: 'inert-principal' }, undefined, stop.signal);
  return { result, cas, started, release, stop, bytes,
    stats: () => ({ publicationJoined, sqlTransactions, publications }) };
}

for (const retirementFailure of [false, true]) test(`cancelled effect-free result preparation joins its original real CAS publication${retirementFailure ? ' and preserves retirement failure' : ''}`, async t => {
  const retirement = retirementFailure ? new ResourceRetirementError('inert actual publication failure', new Error('inert underlying failure')) : undefined;
  const f = await fixture(t, retirement), reason = new Error('inert result reader cancelled');
  let settled = false;
  const pending = f.result.completeVerification({ expectedRunRevision: 2 });
  void pending.then(() => { settled = true; }, () => { settled = true; });
  await Promise.race([f.started.promise, pending.then(() => { throw new Error('publication did not start'); })]);
  f.stop.abort(reason);
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(settled, false, 'reader cancellation cannot retire an issued publication');
  assert.equal(f.stats().publicationJoined, false);
  f.release.resolve();
  await assert.rejects(pending, error => error === (retirement ?? reason));
  assert.deepEqual(f.stats(), { publicationJoined: true, sqlTransactions: 0, publications: 1 });
  if (!retirement) assert.deepEqual(await f.cas.read(canonicalSha256(JSON.parse(f.bytes.toString('utf8')))), f.bytes);
});

test('an already cancelled normal result preparation reads no graph and performs no publication or SQL', async t => {
  const f = await fixture(t), reason = new Error('inert cancelled before preparation'); f.release.resolve(); f.stop.abort(reason);
  await assert.rejects(f.result.completeVerification({ expectedRunRevision: 2 }), error => error === reason);
  assert.deepEqual(f.stats(), { publicationJoined: false, sqlTransactions: 0, publications: 0 });
});
