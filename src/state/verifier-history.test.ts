// The existing retained-data seam uses real SQLite/CAS. Inert bad histories
// below are never installed and do not establish a claim or native proof.
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import type { ContinuationItem, InvocationJournalEntry } from '../kernel/types.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { validateVerifierHistory } from './verifier-history.js';

test('retained verifier history rejects orphan Journal and audit facts even without a winning stop', async () => {
  const fixture = await createAgentFixture('verifier-history-coverage', undefined, { mode: 'plan' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    const input = { driver, artifacts: fixture.store.artifacts, run: cut.run, spec: cut.runSpec, items: cut.items,
      journal: cut.journal, checkpoints: [cut.latestCheckpoint], workspaceGenerations: cut.workspaceGenerations,
      decodedItems: new Map<string, ContinuationItem>(), verifierProgressByCandidate: new Map() };
    assert.deepEqual(await validateVerifierHistory(input), { repairAttempts: 0 });
    const prepared: InvocationJournalEntry = { seq: cut.journal.length + 1, runId: fixture.runId, opId: 'orphan', opKind: 'verifier',
      attempt: 0, leaseEpoch: 1, phase: 'prepared', target: 'a'.repeat(64), requestRef: 'b'.repeat(64), replayClass: 'retry',
      grantRef: 'c'.repeat(64), budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, timestamp: cut.run.updatedAt };
    await assert.rejects(validateVerifierHistory({ ...input, journal: [...cut.journal, prepared] }), /verifier.*owned|verifier.*candidate/);
    for (const item of [
      { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'verifier_launch', itemId: 'orphan-policy', runId: fixture.runId,
        opId: 'orphan', principalId: fixture.principalId, decisionRef: 'a'.repeat(64), policyChannelEvidenceRef: 'a'.repeat(64),
        policyChannelEvidenceDigest: 'b'.repeat(64), createdAt: cut.run.updatedAt, decisionSource: 'direct_policy', decision: 'allow', grantRef: 'c'.repeat(64) },
      { schemaVersion: 1, kind: 'verifier_result', itemId: 'orphan-result', runId: fixture.runId, candidateItemId: 'missing',
        verifierPlanRef: 'a'.repeat(64), verifierIndex: 0, verifierId: 'checks', opId: 'orphan', attempt: 0,
        outcome: 'passed', receiptRef: 'b'.repeat(64), createdAt: cut.run.updatedAt },
      { schemaVersion: 1, kind: 'verifier_stop', itemId: 'orphan-stop', runId: fixture.runId, candidateItemId: 'missing',
        verifierPlanRef: 'a'.repeat(64), verifierIndex: 0, verifierId: 'checks', opId: 'orphan', attempt: 0,
        stopIntent: 'cancelled_by_user', stopIntentRef: 'b'.repeat(64), containmentEvidenceRef: 'c'.repeat(64), createdAt: cut.run.updatedAt }
    ] as ContinuationItem[]) {
      const artifact = await fixture.store.artifacts.publishCanonical(item, 'offline-retained-audit-data');
      const row = { schemaVersion: 1 as const, itemId: item.itemId, itemSeq: 1, payloadRef: artifact.ref,
        payloadDigest: artifact.ref, createdAt: item.createdAt };
      await assert.rejects(validateVerifierHistory({ ...input, items: [row], decodedItems: new Map([[item.itemId, item]]) }),
        /verifier.*owned|verifier.*candidate|verifier.*preparation/);
    }
    for (const run of [{ ...cut.run, repairCount: 1 }, { ...cut.run, budgetConsumed: { ...cut.run.budgetConsumed, repairAttempts: 1 } }])
      await assert.rejects(validateVerifierHistory({ ...input, run }), /repair.*count|repair.*counter/);
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('StateStore recovery never skips an orphan verifier item merely because no model was prepared', async () => {
  const fixture = await createAgentFixture('verifier-history-empty-journal', undefined, { mode: 'plan' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const run = fixture.store.getRun(fixture.runId);
    const artifact = await fixture.store.artifacts.publishCanonical({ schemaVersion: 1, kind: 'verifier_result',
      runId: fixture.runId, itemId: 'unowned-verifier-result', createdAt: run.updatedAt }, 'offline-corrupt-history');
    driver.prepare('INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) VALUES (?, NULL, ?, ?, ?, ?, ?)')
      .run('unowned-verifier-result', fixture.runId, 1n, 'verifier_result', artifact.ref, run.updatedAt);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('a repair-labelled model frontier cannot create a counted repair or compaction origin', async () => {
  const fixture = await createAgentFixture('verifier-history-repair-frontier', undefined, { mode: 'plan' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const cut = await fixture.store.readRecoveryClosure(fixture.runId), artifacts = fixture.store.artifacts;
    const original = await artifacts.readCanonical<Record<string, unknown>>(cut.run.frontierRef!);
    for (const frontier of [{ ...original, cause: 'repair' }, { ...original, cause: 'repair', phase: 'context_compaction', compactionPlanRef: 'a'.repeat(64) }]) {
      const forged = await artifacts.publishCanonical(frontier, 'offline-frontier-data');
      await assert.rejects(validateVerifierHistory({ driver, artifacts, run: { ...cut.run, frontierRef: forged.ref }, spec: cut.runSpec,
        items: cut.items, journal: cut.journal, checkpoints: [cut.latestCheckpoint], workspaceGenerations: cut.workspaceGenerations,
        decodedItems: new Map(), verifierProgressByCandidate: new Map() }), /repair.*original.*authorization/);
    }
  } finally { driver.close(); await disposeFixture(fixture); }
});
