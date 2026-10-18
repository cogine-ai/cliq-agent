// Pure diagnostic planning only. Inert receipt data cannot authorize a Run,
// establish a native measurement, or qualify installed verifier execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { VerificationReceipt } from '../kernel/verifier.js';
import { decodeRepairDiagnosticItem, decodeVerifierRepairDiagnostic, decodeVerifierRepairModelContent } from './verifier-artifacts.js';
import type { VerifierProgress } from './verifier-recovery.js';
import { planVerifierRepair } from './verifier-repair.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';

const ref = (label: string) => canonicalSha256(label);
function inertProgress(): VerifierProgress {
  const receipt: VerificationReceipt = { schemaVersion: 1, format: 'cliq-verification-receipt-v1', runId: 'run', verifierId: 'checks',
    verifierVersion: '1', attempt: 0, outcome: 'assertion_failed', resultSourceRef: ref('source'), sourceDigestBefore: ref('tree'),
    sourceDigestAfter: ref('tree'), commandRef: ref('command'), commandDigest: ref('command-digest'), environmentRef: ref('environment'),
    environmentDigest: ref('environment-digest'), startedAt: '2026-10-18T00:00:00.000Z', endedAt: '2026-10-18T00:00:01.000Z', durationMs: 1000,
    terminationReason: 'exit', exitCode: 7, stdoutRef: ref('unsafe-output'), stderrRef: ref('unsafe-error'),
    stdoutTruncated: false, stderrTruncated: false, leaseEpoch: 1, containmentEvidenceRef: ref('inert-not-death-proof'), receiptDigest: '' };
  receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest');
  // This projection is deliberately incomplete physical history. The planner
  // has no connection, StateOwner, native brand, or transaction capability.
  return { candidate: { itemId: 'audit-candidate-only-21a' }, planRef: ref('plan'), entries: [{ planEntry: { index: 0, required: true },
    specEntry: { id: 'checks' }, receipt, resultItem: { itemId: 'result-item', outcome: 'assertion_failed', receiptRef: canonicalSha256(receipt) },
    terminalJournal: { opId: 'verifier-op', attempt: 0, phase: 'completed', receiptRef: canonicalSha256(receipt) } }] } as VerifierProgress;
}

test('repair planning publishes only the exact fixed model projection and preserves output refs only in audit data', () => {
  const progress = inertProgress(), input = { runId: 'run', repairOrdinal: 1, createdAt: '2026-10-18T00:00:02.000Z' };
  const result = planVerifierRepair(progress, input);
  assert.deepEqual(planVerifierRepair(progress, input), result);
  assert.equal(result.item.repairOrdinal, 1); assert.deepEqual(result.item.failedVerifierResultItemIds, ['result-item']);
  decodeRepairDiagnosticItem(result.item);
  const diagnostic = decodeVerifierRepairDiagnostic(JSON.parse(Buffer.from(result.plans[1]!.bytes).toString('utf8')));
  const content = decodeVerifierRepairModelContent(JSON.parse(Buffer.from(result.plans[0]!.bytes).toString('utf8')));
  assert.equal(content.message, 'Verifier "checks" failed an assertion (exit 7). Revise the candidate and try again.');
  assert.equal(diagnostic.stdoutRef, progress.entries[0]!.receipt!.stdoutRef);
  assert.equal(diagnostic.stderrRef, progress.entries[0]!.receipt!.stderrRef);
  for (const value of [diagnostic.stdoutRef, diagnostic.stderrRef, diagnostic.receiptRef, diagnostic.candidateItemId, diagnostic.verifierPlanRef])
    assert.equal(JSON.stringify(content).includes(value), false);
  assert.equal(result.frontier.kind, 'agent'); assert.equal(result.frontier.cause, 'repair');
});

test('advisory, infrastructure, missing result and mismatched receipt data never authorize a repair plan', () => {
  const input = { runId: 'run', repairOrdinal: 1, createdAt: '2026-10-18T00:00:02.000Z' };
  for (const change of [
    (v: VerifierProgress) => { v.entries[0]!.planEntry.required = false; },
    (v: VerifierProgress) => { v.entries[0]!.receipt!.outcome = 'infra_failed'; },
    (v: VerifierProgress) => { delete v.entries[0]!.resultItem; },
    (v: VerifierProgress) => { v.entries[0]!.resultItem!.receiptRef = ref('different'); }
  ]) { const value = inertProgress(); change(value); assert.throws(() => planVerifierRepair(value, input)); }
  assert.throws(() => planVerifierRepair(inertProgress(), { ...input, repairOrdinal: 0 }));
  assert.throws(() => planVerifierRepair(inertProgress(), { ...input, repairOrdinal: 6 }));
});

test('the real repair owner refuses an ordinary model frontier without changing counters, items or Journal', async () => {
  const fixture = await createAgentFixture('repair-no-verifier-authority');
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.authorizeVerifierRepair({ expectedRunRevision: before.run.revision }), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await assert.rejects(fixture.agent.authorizeVerifierRepair({ expectedRunRevision: before.run.revision, repairOrdinal: 1 } as never));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
