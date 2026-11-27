// Real Store/SQLite/CAS preparation only. No capturing attempt, native proof
// or successful grant consumption is fabricated by these component tests.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { WorkspaceIdentityV1 } from '../kernel/types.js';
import { createQueuedFixture, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { publishInProcessChannel } from './store.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { readAuthorizationGrant } from './repositories/authorization-grants.js';
import { decodeAuthorizationGrant } from './authorization-artifacts.js';
import { assertSourceIncludeConsentConsumed, consumeSourceIncludeConsent,
  prepareSourceIncludeConsent, sourceIncludeConsentData } from './source-include-consent.js';

async function fixture(options: {scope?:'entry'|'subtree';expectedDigest?:string} = {}) {
  const data = await createQueuedFixture('include-consent');
  try {
    const identity = await publishInProcessChannel(data.store);
    const session = data.store.getSession(data.store.getRun(data.runId).sessionId);
    const workspace = await data.store.artifacts.readCanonical<WorkspaceIdentityV1>(session.workspaceIdentityRef);
    assert.equal(workspace.kind, 'live');
    if (workspace.kind !== 'live') assert.fail('expected actual live workspace identity');
    const core = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(),
      decision: { kind: 'read_scope', purpose: 'source', target: { sessionId: session.id,
        expectedWorkspaceIdentityDigest: workspace.identityDigest, path: 'ignored/source', scope: options.scope??'subtree',
        ...(options.expectedDigest===undefined?{}:{expectedDigest:options.expectedDigest}) } } };
    const created = await data.store.createAuthorization({ ...core, requestDigest: canonicalSha256(core) }, identity);
    const grantId = created.response.result.grant.grantId;
    const held = data.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const expected = { principalId: identity.principalId, sessionId: session.id, workspaceIdentityRef: session.workspaceIdentityRef,
      workspaceIdentityDigest: workspace.identityDigest, inspectionId: 'data-not-a-capturing-attempt', admissionIntentDigest: 'a'.repeat(64) };
    const selectors = [{ path: 'ignored/source', scope: options.scope??'subtree', readGrantId: grantId }];
    const footprint = () => ({ grant: readAuthorizationGrant(held.driver, grantId),
      artifacts: held.driver.prepare('SELECT * FROM artifacts ORDER BY ref').all(),
      owners: held.driver.prepare('SELECT * FROM state_owners ORDER BY owner_epoch').all(),
      attempts: held.driver.prepare('SELECT * FROM source_inspection_attempts ORDER BY inspection_id').all(),
      timeFence: held.driver.prepare('SELECT * FROM canonical_time_fence ORDER BY id').all(),
      controls: held.driver.prepare('SELECT * FROM control_requests ORDER BY principal_id,method,request_id').all() });
    return { ...data, held, identity, expected, selectors, grantId, footprint };
  } catch (error) { await disposeFixture(data); throw error; }
}

test('source include receipt/snapshot publication leaves the real grant, capture registry and SQL authority unchanged', async () => {
  const data = await fixture();
  try {
    const before = data.footprint();
    const prepared = await prepareSourceIncludeConsent(data.held.driver, data.store.artifacts, data.held.owner,
      data.runtimeAuthority, data.expected, data.selectors);
    const value = sourceIncludeConsentData(data.held.owner, prepared);
    assert.equal(value.sourceReadGrantRefs.length, 1); assert.equal(value.metadata.length, 2);
    const snapshot = decodeAuthorizationGrant(await data.store.artifacts.readCanonical(value.sourceReadGrantRefs[0]!));
    assert.equal(snapshot.state, 'consumed', 'published data is not an SQL consumption');
    assert.deepEqual(data.footprint(), before);
    assert.throws(() => assertSourceIncludeConsentConsumed(data.held.driver, data.held.owner, prepared),
      { refusalCode: 'AUTHORIZATION_REQUIRED' });
    for (const clone of [{}, { ...prepared }]) {
      assert.throws(() => sourceIncludeConsentData(data.held.owner, clone as typeof prepared), TypeError);
      assert.throws(() => data.held.driver.transaction(connection =>
        consumeSourceIncludeConsent(connection, data.held.owner, clone as typeof prepared, data.expected, sampleCanonicalNow())), TypeError);
    }
    assert.deepEqual(data.footprint(), before);
  } finally { await disposeFixture(data); }
});

test('revocation between preparation and capture cannot be bypassed by a published snapshot or receipt', async () => {
  const data = await fixture();
  try {
    const prepared = await prepareSourceIncludeConsent(data.held.driver, data.store.artifacts, data.held.owner,
      data.runtimeAuthority, data.expected, data.selectors);
    const core = { protocolVersion: 1, method: 'authorization.revoke', requestId: uuidv7(), grantId: data.grantId };
    await data.store.revokeAuthorization({ ...core, requestDigest: canonicalSha256(core) }, data.identity);
    const before = data.footprint();
    assert.throws(() => data.held.driver.transaction(connection =>
      consumeSourceIncludeConsent(connection, data.held.owner, prepared, data.expected, sampleCanonicalNow())),
    { refusalCode: 'AUTHORIZATION_REQUIRED' });
    assert.throws(() => assertSourceIncludeConsentConsumed(data.held.driver, data.held.owner, prepared),
      { refusalCode: 'AUTHORIZATION_REQUIRED' });
    assert.deepEqual(data.footprint(), before);
  } finally { await disposeFixture(data); }
});

test('mismatched scopes and duplicated one-use grants fail before publication or capture', async () => {
  const data = await fixture();
  try {
    const before = data.footprint();
    const beforeCas = (await readdir(path.join(data.stateRoot, 'cas'))).sort();
    for (const selectors of [[{ ...data.selectors[0]!, path: 'other' }],
      [{ ...data.selectors[0]!, scope: 'entry' as const }], [data.selectors[0]!, data.selectors[0]!]]) {
      await assert.rejects(prepareSourceIncludeConsent(data.held.driver, data.store.artifacts, data.held.owner,
        data.runtimeAuthority, data.expected, selectors), { refusalCode: 'AUTHORIZATION_REQUIRED' });
      assert.deepEqual(data.footprint(), before);
      assert.deepEqual((await readdir(path.join(data.stateRoot, 'cas'))).sort(), beforeCas);
    }
  } finally { await disposeFixture(data); }
});

test('a real constrained subtree grant is refused before receipt publication or any SQL consumption',async()=>{
  const data=await fixture({expectedDigest:'0'.repeat(64)});
  try {
    const before=data.footprint(),beforeCas=(await readdir(path.join(data.stateRoot,'cas'))).sort();
    await assert.rejects(prepareSourceIncludeConsent(data.held.driver,data.store.artifacts,data.held.owner,
      data.runtimeAuthority,data.expected,data.selectors),{refusalCode:'AUTHORIZATION_REQUIRED'});
    assert.deepEqual(data.footprint(),before);assert.deepEqual((await readdir(path.join(data.stateRoot,'cas'))).sort(),beforeCas);
    assert.equal(readAuthorizationGrant(data.held.driver,data.grantId)?.state,'active');
  }finally{await disposeFixture(data);}
});

test('a real entry grant preparation retains its exact digest constraint without claiming consumption',async()=>{
  const data=await fixture({scope:'entry',expectedDigest:'0'.repeat(64)});
  try {
    const before=data.footprint(),prepared=await prepareSourceIncludeConsent(data.held.driver,data.store.artifacts,data.held.owner,
      data.runtimeAuthority,data.expected,data.selectors);
    const value=sourceIncludeConsentData(data.held.owner,prepared),grant=decodeAuthorizationGrant(await data.store.artifacts.readCanonical(value.sourceReadGrantRefs[0]!));
    assert.equal(grant.target.kind,'read_scope');
    if(grant.target.kind!=='read_scope')assert.fail('wrong original target');
    assert.equal(grant.target.expectedDigest,'0'.repeat(64));assert.deepEqual(data.footprint(),before);
    assert.throws(()=>assertSourceIncludeConsentConsumed(data.held.driver,data.held.owner,prepared),{refusalCode:'AUTHORIZATION_REQUIRED'});
  }finally{await disposeFixture(data);}
});
