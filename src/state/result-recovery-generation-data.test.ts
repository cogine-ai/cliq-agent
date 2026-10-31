// Execute the original data traversal over inert JSON and genuine CAS files.
// Leaf schemas below are deliberately inert; no Run/owner/native proof exists.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { Script } from 'node:vm';
import ts from 'typescript';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';

type Data = Record<string, any>;
async function fixture(t: TestContext, same = true) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-result-generation-data-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const casRoot = path.join(root, 'objects'); await mkdir(casRoot, { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(casRoot));
  const save = async (value: unknown) => (await artifacts.publishCanonical(value, 'inert-result-data')).ref;
  const rootRef = await save({ kind: 'inert-root-data' });
  const workspace = { state: { stateDigest: 'inert-before' }, entries: { treeDigest: 'inert-tree' } };
  const sourceRef = await save(workspace), snapshotRef = same ? sourceRef : await save({ ...workspace, different: true });
  const identity = { generationId: 'inert-generation', runId: 'inert-run', identityDigest: 'inert-identity',
    sourceCheckpointId: 'inert-checkpoint', sourceWorkspaceStateRef: sourceRef, sourceWorkspaceStateDigest: 'inert-before',
    sourceTreeDigest: 'inert-tree', locator: { stateRootIdentityRef: rootRef } };
  const generationRef = await save(identity);
  const evidence = { evidenceDigest: 'inert-snapshot', generationRef, generationIdentityDigest: 'inert-identity',
    runId: 'inert-run', workspaceStateRef: snapshotRef, workspaceStateDigest: 'inert-before',
    treeDigest: 'inert-tree',
    purpose: same ? 'materialized_from_checkpoint' : 'sealed_to_checkpoint', checkpointId: 'inert-checkpoint' };
  const evidenceRef = await save(evidence);
  const generation: Data = { ...identity, generationRef, generationIdentityDigest: 'inert-identity',
    snapshotEvidenceRef: evidenceRef, snapshotEvidenceDigest: 'inert-snapshot', lastVerifiedTreeDigest: 'inert-tree',
    phase: same ? 'active' : 'sealed' };
  let workspaceReads = 0;
  const dependencies = {
    requireRecoveryArtifacts: async (reads: ArtifactCatalog, refs: [string, string | undefined][]) => {
      for (const [, ref] of refs) if (ref !== undefined) await reads.verifyBytes(ref);
    },
    decodeWorkspaceGenerationIdentity: (value: unknown) => value,
    decodeWorkspaceGenerationSnapshotEvidence: (value: unknown) => value,
    validateWorkspaceStateArtifacts: async (reads: ArtifactCatalog, ref: string) => {
      workspaceReads++; return reads.readCanonical(ref);
    },
    recoveryFailure: (message: string): never => { throw new Error(message); }
  };
  const source = ts.createSourceFile('recovery-closure.ts', await readFile(new URL('./recovery-closure.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const declaration = source.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'validateGenerationArtifacts');
  assert(declaration);
  const names = Object.keys(dependencies);
  const js = ts.transpileModule(declaration.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const factory = new Script(`(function(${names.join(',')}) { ${js}; return validateGenerationArtifacts; })`).runInThisContext();
  const validate = factory(...Object.values(dependencies)) as (reads: ArtifactCatalog, generations: Data[], frozen: unknown) => Promise<void>;
  return { artifacts, generation, validate, save, evidence, reads: () => workspaceReads };
}

test('one generation reuses the just-validated workspace only when both original references are exactly equal', async t => {
  const f = await fixture(t);
  await f.validate(f.artifacts, [f.generation], {});
  assert.equal(f.reads(), 1);
  await f.validate(f.artifacts, [f.generation], {});
  assert.equal(f.reads(), 2, 'a new traversal must read the original CAS node again');
});

test('different generation source and sealed snapshot references retain both independent complete reads', async t => {
  const f = await fixture(t, false);
  await f.validate(f.artifacts, [f.generation], {});
  assert.equal(f.reads(), 2);
});

test('sharing the same workspace does not skip original snapshot linkage checks or cancelled-read checks', async t => {
  const f = await fixture(t);
  f.generation.snapshotEvidenceRef = await f.save({ ...f.evidence, checkpointId: 'foreign-inert-checkpoint' });
  await assert.rejects(f.validate(f.artifacts, [f.generation], {}), /snapshot evidence does not match/);
  assert.equal(f.reads(), 1);
  const stop = new AbortController(), reason = new Error('inert read cancelled'); stop.abort(reason);
  await assert.rejects(f.validate(f.artifacts.withReadSignal(stop.signal), [f.generation], {}), error => error === reason);
  assert.equal(f.reads(), 1);
});
