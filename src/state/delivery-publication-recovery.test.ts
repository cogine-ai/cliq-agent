// Real SQLite/CAS refusal checks only. No delivery, native observation,
// approval or physical publication proof is manufactured by this fixture.
import assert from 'node:assert/strict';
import test from 'node:test';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import type { DeliveryTerminalProjectionEvidence, PublicationProofV1 } from '../kernel/publication.js';
import type { Checkpoint, RecoveryClosureV1, RunSpec } from '../kernel/types.js';
import { readDeliveryTerminalProjection, readUnclaimedPublicationStopHistory,
  validatePublicationAbortCheckpoint, validatePublicationTerminalPathState } from './delivery-publication-recovery.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readCanonicalArtifact } from './agent-context.js';
import { deliveryPublicationCheckpointId, deliveryPublicationTerminalCheckpointId, readPublicationPrefix } from './delivery-publication-progress.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';

test('publication reserves one stable checkpoint before its fresh terminal projection exists', () => {
  // Identity derivation only: this is not a Checkpoint, seal or projection proof.
  const runId = 'delivery', planRef = identityHash('complete immutable plan');
  assert.equal(deliveryPublicationCheckpointId(runId, planRef),
    identityHash('cliq-delivery-publication-checkpoint-v1', runId, planRef));
  assert.notEqual(deliveryPublicationCheckpointId(runId, identityHash('another plan')),
    deliveryPublicationCheckpointId(runId, planRef));
  assert.notEqual(deliveryPublicationCheckpointId('another run', planRef),
    deliveryPublicationCheckpointId(runId, planRef));
});

test('received handoff keeps the actual M resource checkpoint distinct from the later terminal projection', () => {
  // Deterministic names only, not proof that either real transaction occurred.
  const runId = 'delivery', planRef = identityHash('complete immutable plan');
  assert.equal(deliveryPublicationTerminalCheckpointId(runId, planRef),
    identityHash('cliq-delivery-publication-terminal-checkpoint-v1', runId, planRef));
  assert.notEqual(deliveryPublicationTerminalCheckpointId(runId, planRef), deliveryPublicationCheckpointId(runId, planRef));
});

test('abort terminal Checkpoint follows the last actual path cut even when the Plan has no directory abort operations', () => {
  // Pure canonical cut association only, not a real Checkpoint, publication,
  // approval or native proof. A file-only Plan has no synthetic abort item.
  const previous: Checkpoint = { schemaVersion: 1, id: 'last-real-forward-result', runId: 'data-only-run', reason: 'auto',
    basedOnRunRevision: 12, runItemSeq: 8, journalSeq: 9, contextManifestRef: 'a'.repeat(64),
    workspaceStateRef: 'b'.repeat(64), createdAt: '2026-10-18T00:00:00.000Z' };
  const terminal: Checkpoint = { ...previous, id: 'stable-publication-checkpoint', basedOnRunRevision: 14,
    createdAt: '2026-10-18T00:00:01.000Z' };
  assert.doesNotThrow(() => validatePublicationAbortCheckpoint(terminal, previous, previous.journalSeq));
  // A genuine later not-created observation uses the same rule without
  // inventing a Journal phase: its exact Checkpoint already owns that cut.
  const absent = { ...previous, id: 'last-real-not-created-result', basedOnRunRevision: 15, runItemSeq: 9 };
  assert.doesNotThrow(() => validatePublicationAbortCheckpoint({ ...terminal, basedOnRunRevision: 16, runItemSeq: 9 }, absent, absent.journalSeq));
  // A fully validated unclaimed preparation can close after the last path
  // Checkpoint without inventing a path item or new path Checkpoint.
  assert.doesNotThrow(() => validatePublicationAbortCheckpoint({ ...terminal, journalSeq: 11 }, previous, 11));
  for (const change of [{ runId: 'another-run' }, { reason: 'manual' as const }, { runItemSeq: 7 }, { runItemSeq: 9 },
    { journalSeq: 8 }, { journalSeq: 10 }, { contextManifestRef: 'c'.repeat(64) }, { workspaceStateRef: 'c'.repeat(64) },
    { basedOnRunRevision: 12 }, { basedOnRunRevision: 11 }, { createdAt: '2026-10-17T23:59:59.999Z' }])
    assert.throws(() => validatePublicationAbortCheckpoint({ ...terminal, ...change }, previous, previous.journalSeq), /exact final path cut/u);
  for (const journalSeq of [8, -1, 9.5, Number.MAX_SAFE_INTEGER + 1])
    assert.throws(() => validatePublicationAbortCheckpoint({ ...terminal, journalSeq }, previous, journalSeq), /exact final path cut/u);
});

test('terminal descendant absence follows one same-observation ancestor from real CAS without inventing its missing direct parent', async t => {
  // Pure retained-data association: these real CAS objects do not claim that
  // this fixture held a workspace, native inspector, delivery Run or owner.
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'cliq-terminal-ancestor-data-')), cas = path.join(temporary, 'cas');
  await mkdir(cas, { mode: 0o700 }); t.after(() => rm(temporary, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(cas)), ref = 'a'.repeat(64);
  const base = { schemaVersion: 1 as const, format: 'cliq-publication-proof-v1' as const, deliveryRunId: 'data-only-run',
    deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref, inspectorIdentityRef: ref,
    inspectorIdentityDigest: ref, observedAt: '2026-10-18T00:00:00.000Z', proofDigest: '' };
  const ancestor: PublicationProofV1 = { ...base, kind: 'path_observation', observation: { location: { kind: 'workspace', path: 'd' },
    state: { kind: 'absent' }, parentDeviceId: '1', parentFileId: '2', parentLinkCount: 2 } };
  ancestor.proofDigest = digestOmitting(ancestor, 'proofDigest');
  const original = await artifacts.publishCanonical(ancestor, ancestor.format);
  const derived = { ...base, kind: 'ancestor_projection_absence', path: 'd/f', ancestorPath: 'd', ancestorObservationRef: original.ref };
  derived.proofDigest = digestOmitting(derived, 'proofDigest');
  const target = await artifacts.publishCanonical(derived, derived.format);
  assert.deepEqual(validatePublicationTerminalPathState(await readCanonicalArtifact(artifacts, target.ref),
    await readCanonicalArtifact(artifacts, original.ref)), { path: 'd/f', state: { kind: 'absent' } });
  assert.deepEqual(validatePublicationTerminalPathState(await readCanonicalArtifact(artifacts, original.ref)), { path: 'd', state: { kind: 'absent' } });
  // An original-claim recovery observation is not the fresh whole-root
  // terminal observation, even when its inspector and visible state match.
  const recovered = { ...ancestor, recoveryOriginRef: 'b'.repeat(64), recoveryOriginDigest: 'c'.repeat(64) };
  recovered.proofDigest = digestOmitting(recovered, 'proofDigest');
  const recoveredArtifact = await artifacts.publishCanonical(recovered, recovered.format);
  const recoveredLeaf = { ...derived, ancestorObservationRef: recoveredArtifact.ref };
  recoveredLeaf.proofDigest = digestOmitting(recoveredLeaf, 'proofDigest');
  assert.throws(() => validatePublicationTerminalPathState(recovered), /fresh terminal observation/u);
  assert.throws(() => validatePublicationTerminalPathState(recoveredLeaf, recovered), /fresh terminal observation/u);
  const wrongRef = { ...derived, ancestorObservationRef: 'b'.repeat(64) }; wrongRef.proofDigest = digestOmitting(wrongRef, 'proofDigest');
  assert.throws(() => validatePublicationTerminalPathState(wrongRef, ancestor), /ancestor/u);
  for (const state of [{ kind: 'file' as const, digest: ref, mode: 0o600 },
    { kind: 'symlink' as const, target: '../outside', digest: sha256Bytes(Buffer.from('../outside')) }]) {
    const physical = { ...ancestor, observation: { ...ancestor.observation, state,
      entryDeviceId: '1', entryFileId: '3', entryLinkCount: 1 } };
    physical.proofDigest = digestOmitting(physical, 'proofDigest');
    const anchor = await artifacts.publishCanonical(physical, physical.format);
    const leaf = { ...derived, ancestorObservationRef: anchor.ref }; leaf.proofDigest = digestOmitting(leaf, 'proofDigest');
    assert.deepEqual(validatePublicationTerminalPathState(leaf, await readCanonicalArtifact(artifacts, anchor.ref)),
      { path: 'd/f', state: { kind: 'absent' } });
  }
  const deep = { ...derived, path: 'd/nested/f' }; deep.proofDigest = digestOmitting(deep, 'proofDigest');
  assert.deepEqual(validatePublicationTerminalPathState(deep, ancestor), { path: 'd/nested/f', state: { kind: 'absent' } });
  const check = async (raw: Record<string, unknown>) => {
    const candidate = { ...raw, proofDigest: digestOmitting(raw, 'proofDigest') };
    const artifact = await artifacts.publishCanonical(candidate, 'cliq-publication-proof-v1');
    const linked = { ...derived, ancestorObservationRef: artifact.ref }; linked.proofDigest = digestOmitting(linked, 'proofDigest');
    const wrapper = await artifacts.publishCanonical(linked, linked.format);
    return validatePublicationTerminalPathState(await readCanonicalArtifact(artifacts, wrapper.ref), await readCanonicalArtifact(artifacts, artifact.ref));
  };
  for (const [field, value] of [ ['deliveryRunId', 'another-run'], ['deliveryPlanRef', 'b'.repeat(64)],
    ['workspaceIdentityRef', 'b'.repeat(64)], ['workspaceIdentityDigest', 'b'.repeat(64)], ['inspectorIdentityRef', 'b'.repeat(64)],
    ['inspectorIdentityDigest', 'b'.repeat(64)], ['observedAt', '2026-10-17T23:59:59.999Z'], ['observedAt', '2026-10-18T00:00:00.001Z'] ])
    await assert.rejects(check({ ...ancestor, [field]: value }), /original owner or observation/u);
  const observations = [
    { ...ancestor.observation, location: { kind: 'workspace', path: 'other' } },
    { ...ancestor.observation, location: { kind: 'publication_arena', arenaId: identityHash('data-only-arena'), component: '.old' } },
    { ...ancestor.observation, state: { kind: 'directory', mode: 0o700, identityDigest: ref, empty: true },
      entryDeviceId: '1', entryFileId: '3', entryLinkCount: 2 },
    { ...ancestor.observation, parentLinkCount: 0 }
  ];
  for (const observation of observations) await assert.rejects(check({ ...ancestor, observation }), TypeError);
  await assert.rejects(check(derived), /ancestor observation/u); // No recursive proof chain.
  assert.throws(() => validatePublicationTerminalPathState(derived), TypeError);
  assert.throws(() => validatePublicationTerminalPathState(ancestor, ancestor), TypeError);
  const hostile = { ...ancestor };
  Object.defineProperty(hostile, 'observation', { enumerable: true, get() { assert.fail('association must not execute a data accessor'); } });
  assert.throws(() => validatePublicationTerminalPathState(derived, hostile), TypeError);
  await assert.rejects(readCanonicalArtifact(artifacts, wrongRef.ancestorObservationRef));
  const abort = new AbortController(), reason = new Error('original terminal reader closed'); abort.abort(reason);
  await assert.rejects(readCanonicalArtifact(artifacts.withReadSignal(abort.signal), original.ref), error => error === reason);
  const bytes = Buffer.from(await artifacts.readBytes(original.ref)); bytes[bytes.length - 1] ^= 1;
  const file = path.join(cas, original.ref); await chmod(file, 0o600); await writeFile(file, bytes); await chmod(file, 0o400);
  await assert.rejects(readCanonicalArtifact(artifacts, original.ref), /corrupt/u);
});

test('registered CAS and a real Agent cut cannot become delivery publication history or terminal observation', async () => {
  const fixture = await createAgentFixture('publication-retained-no-authority', undefined, { mode: 'plan' });
  try {
    const held = fixture.store as unknown as { driver: SqliteDriver };
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    const session = fixture.store.getSession(cut.run.sessionId);
    const arbitrary = await fixture.store.artifacts.publishCanonical({ ordinary: 'retained data is not native proof' }, 'cliq-publication-proof-v1');
    await assert.rejects(readPublicationPrefix(held.driver, fixture.store.artifacts, cut), /requires a delivery Run/u);
    await assert.rejects(readDeliveryTerminalProjection(held.driver, fixture.store.artifacts, cut, arbitrary.ref), /requires a delivery Run/u);
    await assert.rejects(readUnclaimedPublicationStopHistory(held.driver, fixture.store.artifacts, cut), /only undispatched stopping delivery preparations/u);
    const relabeled = { ...cut, runSpec: { ...cut.runSpec, operation: 'delivery' } } as RecoveryClosureV1;
    await assert.rejects(readPublicationPrefix(held.driver, fixture.store.artifacts, relabeled), /exact original RunSpec/u);
    await assert.rejects(readDeliveryTerminalProjection(held.driver, fixture.store.artifacts, relabeled, arbitrary.ref), /exact original RunSpec/u);
    const stopping = { ...relabeled, run: { ...relabeled.run, stopIntentRef: arbitrary.ref } };
    await assert.rejects(readUnclaimedPublicationStopHistory(held.driver, fixture.store.artifacts, stopping), /exact original RunSpec/u);
    // A data-only relabel cannot turn a permanent claim into unclaimed cleanup.
    const claimed = { ...stopping, journal: [{ opKind: 'publish', phase: 'dispatch_claimed' }] } as RecoveryClosureV1;
    await assert.rejects(readUnclaimedPublicationStopHistory(held.driver, fixture.store.artifacts, claimed), /only undispatched stopping delivery preparations/u);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), cut);
    assert.deepEqual(fixture.store.getSession(cut.run.sessionId), session);
  } finally { await disposeFixture(fixture); }
});

test('rehashed delivery-shaped data and a relabeled real SQL Run still cannot replace original run.apply provenance', async () => {
  const fixture = await createAgentFixture('publication-retained-original-apply', undefined, { mode: 'plan' });
  const held = fixture.store as unknown as { driver: SqliteDriver };
  const before = await fixture.store.readRecoveryClosure(fixture.runId);
  try {
    const { unverifiedConsentRef: _consent, ...core } = before.runSpec;
    const spec: RunSpec = { ...core, operation: 'delivery', credentialGrantRefs: [], budgets: { ...core.budgets,
      modelTokens: 0, costMicros: 0, repairAttempts: 0, childDepth: 0, childConcurrency: 0 } };
    const artifact = await fixture.store.artifacts.publishCanonical(spec, 'cliq-run-spec-v1');
    held.driver.prepare('UPDATE runs SET spec_ref=? WHERE id=?').run(artifact.ref, fixture.runId);
    const cut: RecoveryClosureV1 = { ...before, run: fixture.store.getRun(fixture.runId), runSpec: spec };
    const evidence: DeliveryTerminalProjectionEvidence = { schemaVersion: 1, deliveryRunId: cut.run.id,
      deliveryPlanRef: core.baseWorkspaceManifestRef, selectedBranch: 'forward_finalize', observedSourceRef: core.baseWorkspaceManifestRef,
      observedPathStates: [], forwardResultItemRefs: [], unstartedForwardOperationIds: [], abortResultItemRefs: [],
      transientAbsenceEvidenceRef: core.baseWorkspaceManifestRef, projectionClosureEvidenceRef: core.baseWorkspaceManifestRef,
      gitIndexUnchangedEvidenceRef: core.baseWorkspaceManifestRef, observedAt: cut.run.updatedAt, evidenceDigest: '' };
    evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');
    const data = await fixture.store.artifacts.publishCanonical(evidence, 'cliq-delivery-terminal-projection-v1');
    await assert.rejects(readPublicationPrefix(held.driver, fixture.store.artifacts, cut), /no original admission identity/u);
    await assert.rejects(readDeliveryTerminalProjection(held.driver, fixture.store.artifacts, cut, data.ref), /no original admission identity/u);
  } finally {
    try {
      held.driver.prepare('UPDATE runs SET spec_ref=? WHERE id=?').run(before.run.specRef, fixture.runId);
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    } finally { await disposeFixture(fixture); }
  }
});
