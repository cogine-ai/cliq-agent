// Inert graph regressions only; no runtime, StateOwner or native authority.
import assert from 'node:assert/strict';
import test from 'node:test';
import { assertInstalledDeliveryPublication } from './installed-delivery-publication-result.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting } from '../../../src/kernel/identity.js';
import { decodePublicationProof } from '../../../src/kernel/publication.js';
import { graph, at, type Mutations } from './installed-publication-data-fixture.js';
test('publication data requires the original complete successful public cut before artifact or owner reads', async () => {
  let reads = 0;
  for (const cut of [{}, { method: 'run.get', snapshot: { operation: 'delivery', run: { status: 'failed' } } }]) {
    await assert.rejects(assertInstalledDeliveryPublication({ cut,
      readRetainedArtifact: async () => { reads++; throw new Error('untrusted private detail'); },
      readOwnerHistory: async () => { reads++; return []; } }),
    error => error instanceof Error && error.message === 'installed Delivery publication graph refused');
  }
  assert.equal(reads, 0);
});

test('the complete no-op retained projection and one-path publication data are traversable without claiming native qualification', async () => {
  for (const withPath of [false, true]) {
    const data = graph(withPath), result = await assertInstalledDeliveryPublication(data.input);
    assert.deepEqual(result, { planRef: data.planRef, projectionRef: data.projectionRef,
      publishClaims: withPath ? 1 : 0, progressCount: withPath ? 1 : 0, receiptCount: withPath ? 1 : 0,
      slotObservationCount: withPath ? 2 : 0, arenaRetirementCount: withPath ? 1 : 0,
      publicationWorkerRetirement: data.publicationWorkerRetirement });
  }
});

test('a separately valid retired-arena descriptor cannot replace the original claim birth', async () => {
  const data = graph(true, { proof(kind, value) { if (kind === 'arena_retirement') value.arenaIdentity = { ...value.arenaIdentity, fileId: '900' }; } });
  // The old shallow assertion only decoded this kind. Its shape and digest
  // really remain valid; the refusal below comes from the original-birth edge.
  const arena = [...data.objects.values()].map(bytes => { try { return JSON.parse(bytes.toString()); } catch { return null; } })
    .find(value => value?.kind === 'arena_retirement');
  assert.equal(decodePublicationProof(arena).kind, 'arena_retirement');
  await assert.rejects(assertInstalledDeliveryPublication(data.input), /publication graph refused/u);
});

test('publication rejects rehashed substitutions of claim, child grant, progress, cleanup barrier, receipt and terminal graph', async () => {
  const mutations: Mutations[] = [
    { birth: value => { value.dispatchId = 'different-permanent-dispatch'; } },
    { birth: value => { value.stateRootIdentityDigest = canonicalSha256('another root digest'); } },
    { birth: value => { value.observedAt = at(3); } },
    { claim: value => { value.stateOwnerEpoch = 2; } },
    { claim: value => { value.target = canonicalSha256('another path target'); } },
    { claim: value => { value.leaseEpoch = 2; } },
    { claim: value => { value.evidenceDigest = canonicalSha256('another birth'); } },
    { progress: value => { value.preservedPreimageRef = canonicalSha256('unrelated bytes'); } },
    { progress: value => { value.beforeObservationRef = value.destinationEvidenceRef; } },
    { handoff: value => { value.dispatchId = 'different-permanent-dispatch'; } },
    { handoff: value => { value.claimJournalSeq = 1; } },
    { handoff: value => { value.receiptDigest = canonicalSha256('different receipt'); } },
    { handoff: value => { value.retirement.slotObservationRefs = [...value.retirement.slotObservationRefs].reverse(); } },
    { handoff: value => { value.generationResources.generationRef = canonicalSha256('foreign generation'); } },
    { handoff: value => { value.createdAt = at(6); } },
    { snapshot: value => { value.checkpointId = 'foreign checkpoint'; } },
    { snapshot: value => { value.workspaceStateDigest = canonicalSha256('foreign state'); } },
    { snapshot: value => { value.observedAt = at(8); } },
    { snapshot: value => { value.purpose = 'materialized_from_checkpoint'; delete value.quiescenceEvidenceRef; } },
    { proof: (kind, value) => { if (kind === 'terminal_receipt') value.opId = 'different-operation'; } },
    { proof: (kind, value) => { if (kind === 'terminal_receipt') value.parentIdentityBeforeDigest = canonicalSha256('foreign parent'); } },
    { proof: (kind, value) => { if (kind === 'terminal_receipt') value.before = { ...value.before, entryLinkCount: 2 }; } },
    { proof: (kind, value) => { if (kind === 'path_observation' && value.observation.location.kind === 'publication_arena')
      value.observation = { ...value.observation, parentFileId: 'foreign-arena' }; } },
    { proof: (kind, value) => { if (kind === 'path_observation' && value.observedAt === at(5)) value.observedAt = at(3); } },
    { proof: (kind, value) => { if (kind === 'arena_retirement') value.retirementObservation = { kind: 'darwin_unlinked',
      heldPathUnchanged: true, parentPathUnchanged: true, observedLinkCount: 2 }; } },
    { proof: (kind, value) => { if (kind === 'transient_absence') value.observationRefs = [...value.observationRefs].reverse(); } },
    { proof: (kind, value) => { if (kind === 'projection_closure') value.forwardResultItemRefs = []; } },
    { proof: (kind, value) => { if (kind === 'git_index_unchanged') value.observedAt = at(11); } },
    { result: value => { value.retirement.slotObservationRefs = [...value.retirement.slotObservationRefs].reverse(); } },
    { cut: value => { value.journal = value.journal.filter((row: any) => row.phase !== 'dispatch_claimed'); value.highWaterJournalSeq--; value.nextJournalSeq--; } },
    { cut: value => { const cp = value.checkpoints.find((row: any) => row.runItemSeq === 5); cp.journalSeq = 1; } },
    { cut: value => { const cp = value.checkpoints.find((row: any) => row.runItemSeq === 5); cp.createdAt = at(6); } },
  ];
  for (const mutate of mutations) {
    const data = graph(true, mutate);
    await assert.rejects(assertInstalledDeliveryPublication(data.input), /publication graph refused/u);
  }
});

test('no-op still requires its real owner-bound fresh complete root projection and same-transaction verification Checkpoint', async () => {
  for (const mutate of [
    { proof: (kind: string, value: any) => { if (kind === 'projection_closure') value.inspectorIdentityDigest = canonicalSha256('foreign inspector'); } },
    { cut: (value: any) => { value.checkpoints[0].basedOnRunRevision--; } },
    { cut: (value: any) => { value.checkpoints[1].createdAt = '2026-10-18T00:00:06.000Z'; } },
    { cut: (value: any) => { value.snapshot.run.status = 'failed'; } },
  ]) await assert.rejects(assertInstalledDeliveryPublication(graph(false, mutate).input), /publication graph refused/u);
  const original = graph(false);
  await assert.rejects(assertInstalledDeliveryPublication({ ...original.input, readOwnerHistory: async () => [] }), /publication graph refused/u);
  const owner = structuredClone(original.owners[0])!; owner.acquiredAt = at(11); owner.rowDigest = digestOmitting(owner, 'rowDigest');
  await assert.rejects(assertInstalledDeliveryPublication({ ...original.input, readOwnerHistory: async () => [owner] }), /publication graph refused/u);
  await assert.rejects(assertInstalledDeliveryPublication(graph(false, {}, 'not the desired source\n').input), /publication graph refused/u);
});

test('retained reads require complete canonical bytes, bounded objects and stable caller data', async () => {
  const data = graph(true), before = canonicalJsonBytes(data.cut);
  await assertInstalledDeliveryPublication(data.input); assert.ok(canonicalJsonBytes(data.cut).equals(before));
  const badReaders = [async () => Buffer.from('{}'), async () => Buffer.alloc(1_048_577), async () => Buffer.from([0xff])];
  for (const readRetainedArtifact of badReaders)
    await assert.rejects(assertInstalledDeliveryPublication({ ...data.input, readRetainedArtifact }), /publication graph refused/u);
  let getterRuns = 0;
  const getterCut = { ...data.cut, get journal() { getterRuns++; return data.cut.journal; } };
  await assert.rejects(assertInstalledDeliveryPublication({ ...data.input, cut: getterCut }), /publication graph refused/u);
  assert.equal(getterRuns, 0);
});

test('one retained walk snapshots the actual cut before asynchronous I/O', async () => {
  const data = graph(true), expected = await assertInstalledDeliveryPublication(data.input);
  let first = true;
  const result = await assertInstalledDeliveryPublication({ ...data.input, readRetainedArtifact: async ref => {
    if (first) { first = false; data.cut.snapshot.run.resultRef = canonicalSha256('changed caller result'); }
    return data.input.readRetainedArtifact(ref);
  } });
  assert.deepEqual(result, expected);
});
