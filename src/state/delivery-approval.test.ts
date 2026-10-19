// Existing real StateStore and pure counterfeit-refusal seams. No verified
// source, delivery approval, native worker or publication evidence is injected.
import assert from 'node:assert/strict';
import test from 'node:test';
import { loadDeliveryApproval, readDeliveryAuthorization } from './delivery-approval.js';
import type { RecoveryClosureV1 } from '../kernel/types.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { readSessionPrincipalId } from './rows.js';
import { publishInProcessChannel } from './store.js';
import { uuidv7 } from './testing/fixtures.js';

test('delivery approval refuses caller-selected plan or grant fields before touching storage', async () => {
  const approval = loadDeliveryApproval(undefined as unknown as SqliteDriver, undefined as never,
    undefined as unknown as StateOwnerContext, { run: { id: 'closed-request' }, spec: {} } as never);
  await assert.rejects(approval.prepareDeliveryApproval({ expectedRunRevision: 1, grantRef: 'a'.repeat(64) } as never), { code: 'INVALID_REQUEST' });
  await assert.rejects(approval.prepareDeliveryApproval({ expectedRunRevision: 0 }), { code: 'INVALID_REQUEST' });
});

test('publication history cannot survive without its original atomic delivery allow', async () => {
  // Inert rejected data, never installed as Run/Journal/native authority.
  const cut = { runSpec: { operation: 'delivery' }, run: {}, items: [], journal: [{ opKind: 'publish' }] } as unknown as RecoveryClosureV1;
  await assert.rejects(readDeliveryAuthorization(undefined as unknown as SqliteDriver, undefined as never, cut), /original.*allow/);
});

test('an undecided delivery ask cannot skip its original approval frontier', async () => {
  const cut = { runSpec: { operation: 'delivery' }, run: { status: 'waiting', waitingReason: 'approval',
    waitingOnRef: 'a'.repeat(64) }, items: [], journal: [] } as unknown as RecoveryClosureV1;
  await assert.rejects(readDeliveryAuthorization(undefined as unknown as SqliteDriver, undefined as never, cut), /original approval frontier/);
});

test('delivery approval cannot reinterpret a genuinely admitted Agent Run', async () => {
  const fixture = await createAgentFixture('delivery-approval-agent-refusal', undefined, { mode: 'plan' });
  try {
    const original = await fixture.store.readRecoveryClosure(fixture.runId);
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const approval = loadDeliveryApproval(held.driver, fixture.store.artifacts, held.owner, {
      run: original.run, spec: original.runSpec, principalId: readSessionPrincipalId(held.driver, original.run.sessionId),
      assertAuthority: async () => { throw new Error('an Agent Run must be refused before delivery authority is loaded'); }
    });
    await assert.rejects(approval.prepareDeliveryApproval({ expectedRunRevision: original.run.revision }), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), original);
  } finally { await disposeFixture(fixture); }
});

test('public delivery approval refuses an ineligible real Run without turning the business refusal into INTERNAL', async () => {
  const fixture = await createAgentFixture('delivery-public-approval-refusal', undefined, { mode: 'plan' });
  try {
    const original = await fixture.store.readRecoveryClosure(fixture.runId), session = fixture.store.getSession(original.run.sessionId);
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const approval = loadDeliveryApproval(held.driver, fixture.store.artifacts, held.owner, {
      run: original.run, spec: original.runSpec, principalId: fixture.principalId,
      assertAuthority() { assert.fail('an Agent Run cannot enter delivery authority'); }
    });
    await assert.rejects(approval.approveDelivery({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      expectedRunRevision: original.run.revision, waitingOnRef: 'a'.repeat(64), decision: 'allow' }), { code: 'INVALID_REQUEST' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), original);
    assert.deepEqual(fixture.store.getSession(original.run.sessionId), session);
  } finally { await disposeFixture(fixture); }
});

test('real CAS rejects unapproved publication and a foreign pending-wait frontier without installing either projection', async () => {
  const fixture = await createAgentFixture('delivery-approval-retained-negative', undefined, { mode: 'plan' });
  try {
    const original = await fixture.store.readRecoveryClosure(fixture.runId);
    const held = fixture.store as unknown as { driver: SqliteDriver };
    // Rejected reader input only. The real Agent rows and source remain
    // untouched; none of these values is a verified Delivery source or proof.
    for (const phase of ['publish', 'abort_cleanup'] as const) {
      const frontier = await fixture.store.artifacts.publishCanonical({ schemaVersion: 1, kind: 'delivery', phase }, 'cliq-run-frontier-v1');
      await assert.rejects(readDeliveryAuthorization(held.driver, fixture.store.artifacts, {
        ...original, items: [], journal: [], runSpec: { ...original.runSpec, operation: 'delivery' },
        run: { ...original.run, frontierRef: frontier.ref }
      }), /original complete delivery allow/);
    }
    await assert.rejects(readDeliveryAuthorization(held.driver, fixture.store.artifacts, {
      ...original, items: [], journal: [], runSpec: { ...original.runSpec, operation: 'delivery' },
      run: { ...original.run, status: 'waiting', waitingReason: 'approval', waitingOnRef: 'a'.repeat(64) }
    }), /original approval frontier/);
    // A historical candidate label is not proof that an ask existed. Returning
    // undefined here means no authorization; it does not accept this untrusted
    // projection as a Run, candidate, verified source or recovery closure.
    const candidate = await fixture.store.artifacts.publishCanonical({ kind: 'final_candidate' }, 'cliq-test-untrusted-data-v1');
    assert.equal(await readDeliveryAuthorization(held.driver, fixture.store.artifacts, {
      ...original, runSpec: { ...original.runSpec, operation: 'delivery' }, journal: [],
      items: [{ schemaVersion: 1, itemId: 'untrusted-candidate', itemSeq: 1, payloadRef: candidate.ref,
        payloadDigest: candidate.ref, createdAt: original.run.createdAt }],
      run: { ...original.run, status: 'failed', nextStep: null, frontierRef: undefined }
    }), undefined);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), original);
  } finally { await disposeFixture(fixture); }
});
