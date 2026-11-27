// Inert retained graphs only. These tests create no process, native proof,
// StateOwner, clock, publication authority or installation.
import assert from 'node:assert/strict';
import test from 'node:test';
import { assertInstalledDeliveryOutcome } from './installed-delivery-result.js';
import { graph, at } from './installed-publication-data-fixture.js';
import { assertInstalledPublicationStopResult } from './installed-publication-stop-result.js';
import { encodeControlCheckpointCursor } from '../../../src/kernel/control-wire.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting } from '../../../src/kernel/identity.js';

function fixture(settledBeforeRelease: boolean | 'path_only' | 'unowned_settlement' = false) {
  const data = graph(true, {}, 'before\n', true, settledBeforeRelease), beforeCut = structuredClone(data.cut), run = beforeCut.snapshot.run;
  const read = (ref: string) => JSON.parse(data.objects.get(ref)!.toString());
  beforeCut.journal = beforeCut.journal.slice(0, 2);
  beforeCut.items = beforeCut.items.filter((row: any) => { const item = read(row.payloadRef);
    return item.kind !== 'publication_path_result' && item.state !== 'received_handoff'; });
  beforeCut.checkpoints = beforeCut.checkpoints.filter((row: any) => row.runItemSeq <= beforeCut.items.length);
  const cp = beforeCut.checkpoints.at(-1)!;
  run.status = 'running'; delete run.terminalReason; delete run.resultRef; run.nextStep = 'delivery';
  run.activeWorkerLaunchId = 'original-M-worker'; run.frontierRef = read(beforeCut.journal[0].requestRef).frontierRef;
  run.latestCheckpointId = cp.id; run.revision = 4; run.budgetReserved = { ...run.budgetConsumed };
  run.budgetConsumed = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }; run.updatedAt = cp.createdAt;
  beforeCut.snapshot.latestRunItemSeq = beforeCut.highWaterItemSeq = beforeCut.nextItemSeq = beforeCut.items.length;
  beforeCut.highWaterJournalSeq = beforeCut.nextJournalSeq = 2;
  beforeCut.highWaterCheckpointCursor = beforeCut.nextCheckpointCursor = encodeControlCheckpointCursor(run.id, { createdAt: cp.createdAt, checkpointId: cp.id });
  return { ...data, beforeCut, input: { ...data.input, beforeCut, sessionCut: data.sessionCut, sourceCut: data.sourceCut,
    sourceResultRef: data.sourceResultRef, expectedFiles: [{ path: 'example.txt', text: 'after\n' }] } };
}

function claimOnlyFixture() {
  const data = fixture(), before = data.beforeCut;
  before.items = before.items.slice(0, 4);
  before.checkpoints = before.checkpoints.filter((row: any) => row.runItemSeq <= 4);
  const cp = before.checkpoints.at(-1)!;
  before.snapshot.run.latestCheckpointId = cp.id; before.snapshot.run.revision = 3;
  before.snapshot.run.updatedAt = before.journal[0].timestamp;
  before.snapshot.latestRunItemSeq = before.highWaterItemSeq = before.nextItemSeq = 4;
  before.highWaterCheckpointCursor = before.nextCheckpointCursor = encodeControlCheckpointCursor(before.snapshot.run.id,
    { createdAt: cp.createdAt, checkpointId: cp.id });
  return data;
}

test('the stop fixture traverses the unchanged complete normal Delivery outcome reader', async () => {
  const data = graph(true, {}, 'before\n', true);
  const result = await assertInstalledDeliveryOutcome({ ...data.input, sessionCut: data.sessionCut, sourceCut: data.sourceCut,
    sourceResultRef: data.sourceResultRef, expectedFiles: [{ path: 'example.txt', text: 'after\n' }], kind: 'publish' });
  assert.equal(result.completeRetainedArtifactWalk, true);
});

test('one original normal receipt/handoff and its full graceful successor closure retain the captured claim', async () => {
  const data = fixture(), result = await assertInstalledPublicationStopResult(data.input);
  assert.deepEqual(result && { originalOwnerEpoch: result.originalOwnerEpoch, successorOwnerEpoch: result.successorOwnerEpoch,
    runId: result.runId, dispatchId: result.dispatchId, receiptRef: result.receiptRef }, {
    originalOwnerEpoch: 2, successorOwnerEpoch: 3, runId: data.cut.snapshot.run.id,
    dispatchId: 'original-dispatch', receiptRef: data.cut.journal[2].receiptRef,
  });
  assert.equal(result.terminalInspectorOwnerEpoch, 3);
  assert.equal(result.retirementDiagnosticKey, canonicalSha256(['cliq-publication-claim-retirement-diagnostic-v1',
    result.runId, result.planRef, result.opId, 0, 'original-dispatch']));
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.publicationWorkerRetirement));
});

test('an original-owner terminal result remains the same complete outcome after its graceful restart', async () => {
  const data = fixture(true), result = await assertInstalledPublicationStopResult(data.input);
  assert.equal(result.terminalInspectorOwnerEpoch, 2);
  assert.equal(result.resultRef, data.cut.snapshot.run.resultRef);
});

test('an originally settled path can retain its one result while the successor finishes only the full read-only projection', async () => {
  const data = fixture('path_only');
  const result = await assertInstalledPublicationStopResult(data.input);
  assert.equal(result.terminalInspectorOwnerEpoch, 3);
  assert.equal(data.cut.journal[2].timestamp, at(8));
});

test('a settlement in the unowned release-to-acquisition interval cannot count as a successful graceful stop closure', async () => {
  const data = fixture('unowned_settlement');
  await assertInstalledDeliveryOutcome({ ...data.input, kind: 'publish' });
  await assert.rejects(assertInstalledPublicationStopResult(data.input), /stop closure refused/u);
});

test('the captured running snapshot must name its actual fully retained initial Checkpoint', async () => {
  const data = fixture(); data.beforeCut.snapshot.run.latestCheckpointId = 'foreign-before-cut-checkpoint';
  await assert.rejects(assertInstalledPublicationStopResult(data.input), /stop closure refused/u);
});

test('a claim-only cut retains the last Run write timestamp rather than inventing a claim-time Run update', async () => {
  const data = claimOnlyFixture();
  assert(data.beforeCut.snapshot.run.updatedAt < data.beforeCut.journal[1].timestamp);
  await assertInstalledPublicationStopResult(data.input);
});

test('the captured Run must retain its real earlier revision, original lease, reservation and causal Run-write interval', async () => {
  const cases: Array<[string, () => ReturnType<typeof fixture>]> = [
    ['equal revision', () => { const d = fixture(); d.beforeCut.snapshot.run.revision = d.cut.snapshot.run.revision; return d; }],
    ['later revision', () => { const d = fixture(); d.beforeCut.snapshot.run.revision = d.cut.snapshot.run.revision + 1; return d; }],
    ['foreign lease', () => { const d = fixture(); d.beforeCut.snapshot.run.leaseEpoch++; return d; }],
    ['already consumed', () => { const d = fixture(); d.beforeCut.snapshot.run.budgetConsumed.toolCalls = 1; return d; }],
    ['unreserved call', () => { const d = fixture(); d.beforeCut.snapshot.run.budgetReserved.toolCalls = 0; return d; }],
    ['extra reservation', () => { const d = fixture(); d.beforeCut.snapshot.run.budgetReserved.modelTokens = 1; return d; }],
    ['after final update', () => { const d = fixture(true); d.beforeCut.snapshot.run.updatedAt = at(11); return d; }],
    ['before preparation write', () => { const d = claimOnlyFixture(); d.beforeCut.journal[0].timestamp = d.cut.journal[0].timestamp = at(1); return d; }],
  ];
  const accepted: string[] = [];
  for (const [name, make] of cases) {
    const data = make();
    try { await assertInstalledPublicationStopResult(data.input); accepted.push(name); }
    catch (error) { assert.match((error as Error).message, /stop closure refused/u); }
  }
  assert.deepEqual(accepted, []);
});

test('terminalReason cannot replace the actual original graceful transition or successor acquisition bytes', async () => {
  for (const field of ['transitionEvidenceRef', 'acquisitionEvidenceRef'] as const) {
    const data = fixture(), owner = data.owners[field === 'transitionEvidenceRef' ? 1 : 2]!;
    data.objects.delete(owner[field as keyof typeof owner] as string);
    await assert.rejects(assertInstalledPublicationStopResult(data.input), /stop closure refused/u);
  }
  for (const field of ['priorTerminalRowDigest', 'priorTransitionEvidenceRef', 'priorTransitionEvidenceDigest'] as const) {
    const data = fixture(), successor = data.owners[2]!, value = JSON.parse(data.objects.get(successor.acquisitionEvidenceRef)!.toString());
    value[field] = 'f'.repeat(64); value.evidenceDigest = digestOmitting(value, 'evidenceDigest');
    const ref = canonicalSha256(value); data.objects.set(ref, canonicalJsonBytes(value));
    successor.acquisitionEvidenceRef = ref; successor.acquisitionEvidenceDigest = value.evidenceDigest;
    successor.rowDigest = digestOmitting(successor, 'rowDigest');
    await assert.rejects(assertInstalledPublicationStopResult(data.input), /stop closure refused/u);
  }
});

test('the original resource Checkpoint must predate its real owner release even when the normal outcome remains valid', async () => {
  const data = fixture(), cp = data.cut.checkpoints.find((row: any) => row.runItemSeq === 6)!;
  cp.createdAt = at(8);
  // This remains a normal successful publication, but cannot establish that
  // the original owner retained its handoff before the tested graceful stop.
  await assertInstalledDeliveryOutcome({ ...data.input, kind: 'publish' });
  await assert.rejects(assertInstalledPublicationStopResult(data.input), /stop closure refused/u);
});

test('the pre-signal cut cannot contain a handoff, a result, a replaced claim or an UNKNOWN history', async () => {
  for (const mutate of [
    (data: ReturnType<typeof fixture>) => { data.beforeCut.journal[1].dispatchId = 'replacement-dispatch'; },
    (data: ReturnType<typeof fixture>) => { data.cut.journal[2].phase = 'unknown'; },
    (data: ReturnType<typeof fixture>) => { data.beforeCut = data.cut; data.input.beforeCut = data.cut; },
    (data: ReturnType<typeof fixture>) => { data.beforeCut.snapshot.run.activeWorkerLaunchId = 'foreign-worker'; },
    (data: ReturnType<typeof fixture>) => { data.beforeCut.items[0].payloadDigest = 'f'.repeat(64); },
  ]) {
    const data = fixture(); mutate(data);
    await assert.rejects(assertInstalledPublicationStopResult(data.input), /stop closure refused/u);
  }
});

test('complete retained source bytes are still mandatory rather than matching result names or hashes alone', async () => {
  const data = fixture();
  const result = JSON.parse(data.objects.get(data.cut.snapshot.run.resultRef)!.toString());
  const source = JSON.parse(data.objects.get(result.resultSourceRef)!.toString());
  const entries = JSON.parse(data.objects.get(source.entriesRef)!.toString());
  data.objects.set(entries.entries[0].blobRef, Buffer.from('corrupted bytes'));
  await assert.rejects(assertInstalledPublicationStopResult(data.input), /stop closure refused/u);
});

test('fixed cuts are captured before external callbacks and returned diagnostics do not retain mutable caller objects', async () => {
  const data = fixture(), read = data.input.readRetainedArtifact;
  const result = await assertInstalledPublicationStopResult({ ...data.input, readRetainedArtifact: async ref => {
    data.beforeCut.snapshot.run.activeWorkerLaunchId = 'mutated-after-capture';
    data.cut.snapshot.run.resultRef = 'f'.repeat(64);
    data.sourceCut.snapshot!.run.resultRef = 'f'.repeat(64);
    data.input.expectedFiles[0]!.text = 'mutated-after-capture'; return read(ref);
  } });
  assert.notEqual(result.resultRef, data.cut.snapshot.run.resultRef);
  assert.equal(result.publicationWorkerRetirement.launchId, 'original-M-worker');
});

test('accessor inputs and oversized cuts fail closed without calling readers or getters', async () => {
  let calls = 0;
  const data = fixture(), input = { ...data.input, readRetainedArtifact: async () => { calls++; throw new Error('must not read'); },
    readOwnerHistory: async () => { calls++; throw new Error('must not read'); } };
  const getter = Object.defineProperty({ ...input }, 'beforeCut', { enumerable: true, get() { calls++; return data.beforeCut; } });
  await assert.rejects(assertInstalledPublicationStopResult(getter), /stop closure refused/u);
  await assert.rejects(assertInstalledPublicationStopResult({ ...input, beforeCut: { oversized: 'x'.repeat(1_048_576) } }), /stop closure refused/u);
  assert.equal(calls, 0);
});
