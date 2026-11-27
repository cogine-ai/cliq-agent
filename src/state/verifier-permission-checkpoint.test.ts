// A read-only historical data projection over actual SQLite/CAS. These
// deliberately inert candidate bytes are never installed as a valid Run,
// consent, Checkpoint or native proof and cannot authorize any invocation.
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { FinalCandidateItem } from '../kernel/result.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact } from './agent-context.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { decodeContextManifest } from './decoders.js';
import { decodeFinalCandidateItem } from './result-artifacts.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';

test('verifier consent history requires its actual prior candidate and complete same-assembly context prefix', async () => {
  const source = ts.createSourceFile('verifier-permission-history.ts', await readFile(new URL('./verifier-permission-history.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const declaration = source.statements.filter(ts.isFunctionDeclaration).find(node => node.name?.text === 'readPermissionCheckpointContext'); assert(declaration);
  const code = ts.transpileModule(declaration.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const read = new Function('readCanonicalArtifact', 'decodeContextManifest', 'validateContextItems', 'decodeFinalCandidateItem',
    `${code};return readPermissionCheckpointContext;`)(readCanonicalArtifact, decodeContextManifest, validateContextItems, decodeFinalCandidateItem) as
    (...input: unknown[]) => Promise<void>;
  const f = await createAgentFixture('verifier-consent-prefix', undefined, { mode: 'plan' });
  const driver = openSqliteDriver(path.join(f.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const cut = await f.store.readRecoveryClosure(f.runId), artifacts = f.store.artifacts, at = cut.run.createdAt;
    const candidate: FinalCandidateItem = { schemaVersion: 1, kind: 'final_candidate', operation: 'agent', itemId: 'inert-candidate-data', runId: f.runId,
      producingItemId: 'inert-unexecuted-model', producingOpId: 'inert-op', baseSourceRef: cut.runSpec.baseWorkspaceManifestRef,
      resultSourceRef: canonicalSha256('inert-result'), diffRef: canonicalSha256('inert-diff'), summaryRef: canonicalSha256('inert-summary'),
      sourceDigest: canonicalSha256('inert-source'), diffDigest: canonicalSha256('inert-diff-digest'), createdAt: at };
    const context = { run: cut.run, spec: cut.runSpec, target: { candidateItemId: candidate.itemId,
      resultSourceRef: candidate.resultSourceRef, sourceDigest: candidate.sourceDigest } };
    await assert.rejects(read(driver, artifacts, context, cut.latestCheckpoint), /preceded its actual durable candidate/);
    const manifest = decodeContextManifest(await artifacts.readCanonical(cut.latestCheckpoint.contextManifestRef));
    const frontier = await artifacts.readCanonical<import('../kernel/types.js').RunFrontier>(cut.run.frontierRef!);
    const graph = await prepareContinuationCommit(artifacts, { context: manifest, existingItems: [], items: [candidate], frontier,
      checkpointId: 'inert-unregistered-checkpoint', workspaceStateRef: cut.latestCheckpoint.workspaceStateRef });
    // Do not call graph.commit: only install untrusted rows for this reader.
    driver.prepare('INSERT INTO items(item_id,session_id,run_id,item_seq,kind,payload_ref,created_at) VALUES(?,NULL,?,1,?,?,?)')
      .run(candidate.itemId, f.runId, candidate.kind, canonicalSha256(candidate), at);
    const checkpoint = { ...cut.latestCheckpoint, runItemSeq: 1, contextManifestRef: graph.contextManifestRef };
    await read(driver, artifacts, context, checkpoint);
    for (const target of [{ ...context.target, candidateItemId: 'other' }, { ...context.target, resultSourceRef: canonicalSha256('other') },
      { ...context.target, sourceDigest: canonicalSha256('other') }]) await assert.rejects(read(driver, artifacts, { ...context, target }, checkpoint));
    for (const changed of [{ runItemSeq: 2 }, { contextManifestRef: cut.latestCheckpoint.contextManifestRef },
      { createdAt: new Date(Date.parse(at) - 1).toISOString() }]) await assert.rejects(read(driver, artifacts, context, { ...checkpoint, ...changed }));
    await assert.rejects(read(driver, artifacts, { ...context, spec: { ...cut.runSpec, assemblyRef: canonicalSha256('other') } }, checkpoint));
    const abort = new AbortController(), reason = Error('original data reader retired'); abort.abort(reason);
    await assert.rejects(read(driver, artifacts.withReadSignal(abort.signal), context, checkpoint), error => error === reason);
  } finally {
    driver.close(); await disposeFixture(f);
  }
});
