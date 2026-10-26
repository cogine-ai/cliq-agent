import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeInstalledControlRequest, decodeInstalledControlResponse } from '../kernel/control-wire.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { admissionKey, createQueuedFixture, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { signedVerifierAuthority } from './testing/verifier-authority.js';
import type { SourceManifest } from '../kernel/types.js';

test('Run list materializes original owned snapshots and preserves its pages across admission and real Store restart', async () => {
  const fixture = await createQueuedFixture('run-list-cut');
  let store = fixture.store;
  try {
    let identity = await publishInProcessChannel(store);
    const closure = await store.readRecoveryClosure(fixture.runId), spec = closure.runSpec;
    const source = await store.artifacts.readCanonical<SourceManifest>(spec.baseWorkspaceManifestRef);
    const admit = (label: string) => store.admitRun({ ...identity, requestId: uuidv7(), admissionKey: admissionKey(label),
      sessionId: closure.run.sessionId, expectedContextRevision: 1, workspacePath: fixture.workspace, objective: label, allowUnverified: true,
      sourceProjectionRef: spec.sourceProjectionRef, frozenIgnoreRulesRef: source.frozenIgnoreRulesRef,
      baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef, verifierSpecRef: spec.verifierSpecRef,
      assemblyRef: spec.assemblyRef, policyRef: spec.policyRef, sandboxProfileRef: spec.sandboxProfileRef });
    await admit('run-list-second'); await admit('run-list-third');
    const request = { protocolVersion: 1, method: 'run.list', sessionId: closure.run.sessionId, operation: 'agent', statuses: ['queued'], limit: 1 } as const;
    const first = await store.listControl(request, identity); assert(first.result.method === 'run.list');
    assert.equal(first.result.runs.length, 1); assert(first.result.nextCursor);
    const nextRequest = { ...request, cursor: first.result.nextCursor };
    const next = await store.listControl(nextRequest, identity); assert(next.result.method === 'run.list');
    await admit('run-list-fourth');
    await store.close(); store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    identity = await publishInProcessChannel(store);
    assert.deepEqual(canonicalJsonBytes(await store.listControl(nextRequest, identity)), canonicalJsonBytes(next));
    assert(next.result.nextCursor);
    const last = await store.listControl({ ...request, cursor: next.result.nextCursor }, identity); assert(last.result.method === 'run.list');
    assert.equal(last.result.nextCursor, undefined); assert.equal(last.result.runs.length, 1);
    assert.equal(new Set([first.result.runs[0]!.run.id, next.result.runs[0]!.run.id, last.result.runs[0]!.run.id]).size, 3);
    const freshRequest = decodeInstalledControlRequest({ ...request, limit: 100 });
    const fresh = await store.listControl(freshRequest, identity); assert(fresh.result.method === 'run.list');
    assert.equal(fresh.result.runs.length, 4); assert.deepEqual(decodeInstalledControlResponse(fresh, freshRequest), fresh);
    const delivery = await store.listControl({ ...request, operation: 'delivery', limit: 100 }, identity);
    assert(delivery.result.method === 'run.list'); assert.deepEqual(delivery.result.runs, []);
    for (const change of [{ limit: 2 }, { sessionId: 'another-session' }, { operation: 'delivery' }, { statuses: ['running'] }, { cursor: first.result.nextCursor + '=' }])
      await assert.rejects(store.listControl({ ...nextRequest, ...change }, identity), { code: 'INVALID_REQUEST' });
    await assert.rejects(store.listControl({ protocolVersion: 1, method: 'authorization.list', cursor: first.result.nextCursor, limit: 1 }, identity), { code: 'INVALID_REQUEST' });
  } finally { await disposeFixture({ ...fixture, store }); }
});

test('authorization list freezes active summaries across genuine revoke, new grant and real Store restart', async t => {
  const signed = await signedVerifierAuthority();
  const fixture = await createQueuedFixture('authorization-list-cut', { runtimeAuthority: { bundle: signed.bundle, releaseKeys: signed.releaseKeys }, assembly: async store => {
    for (const object of signed.objects) await store.artifacts.publishBytes(object.bytes, 'application/octet-stream', 'offline-verifier-object');
    const { testFixture } = await import('../model/testing/fixtures.js');
    return (await store.artifacts.publishCanonical(testFixture().assembly, 'cliq-run-assembly-v1')).ref;
  } });
  let store = fixture.store;
  try {
    let identity = await publishInProcessChannel(store);
    const create = async () => {
      const core = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(), decision: { kind: 'execution_identity_read',
        purpose: 'verifier', target: { kind: 'guest_toolchain', guestToolchainManifestId: signed.manifestId, toolId: 'node' } } };
      return (await store.createAuthorization({ ...core, requestDigest: canonicalSha256(core) }, identity)).response.result.grant;
    };
    await create(); await create(); await create();
    const request = { protocolVersion: 1, method: 'authorization.list', targetKind: 'execution_identity_read', state: 'active', limit: 1 } as const;
    const first = await store.listControl(request, identity); assert(first.result.method === 'authorization.list' && first.result.nextCursor);
    const nextRequest = { ...request, cursor: first.result.nextCursor }, next = await store.listControl(nextRequest, identity);
    assert(next.result.method === 'authorization.list');
    const core = { protocolVersion: 1, method: 'authorization.revoke', requestId: uuidv7(), grantId: next.result.grants[0]!.grantId };
    await store.revokeAuthorization({ ...core, requestDigest: canonicalSha256(core) }, identity); await create();
    await store.close(); store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority); identity = await publishInProcessChannel(store);
    assert.deepEqual(canonicalJsonBytes(await store.listControl(nextRequest, identity)), canonicalJsonBytes(next));
    const revokedRequest = decodeInstalledControlRequest({ ...request, state: 'revoked', limit: 100 });
    const revoked = await store.listControl(revokedRequest, identity); assert(revoked.result.method === 'authorization.list');
    assert.equal(revoked.result.grants.length, 1); assert.equal(revoked.result.grants[0]!.grantId, core.grantId);
    assert.deepEqual(decodeInstalledControlResponse(revoked, revokedRequest), revoked);
    const active = await store.listControl({ ...request, limit: 100 }, identity); assert(active.result.method === 'authorization.list');
    assert.equal(active.result.grants.length, 3); assert(active.result.grants.every(grant => grant.state === 'active'));
    const { KERNEL_DATABASE_FILENAME } = await import('../config.js');
    const { openSqliteDriver } = await import('./sqlite-driver.js');
    const path = await import('node:path');
    const audit = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const grantId = active.result.grants[0]!.grantId;
      const row = audit.prepare('SELECT row_json FROM authorization_grants WHERE grant_id=?').get<{ row_json: string }>(grantId)!;
      for (const invalid of [null, false, '0', 0.5]) {
        const changed = { ...JSON.parse(row.row_json), useCount: invalid };
        audit.transaction(connection => connection.prepare('UPDATE authorization_grants SET row_json=? WHERE grant_id=?').run(canonicalJsonBytes(changed).toString('utf8'), grantId));
        try { await assert.rejects(store.listControl({ ...request, limit: 100 }, identity), { code: 'RECOVERY_REQUIRED' }); }
        finally { audit.transaction(connection => connection.prepare('UPDATE authorization_grants SET row_json=? WHERE grant_id=?').run(row.row_json, grantId)); }
      }
      const actual = Reflect.get(store, 'driver'), prototype = Object.getPrototypeOf(actual), transaction = prototype.transaction;
      let changed = false;
      t.mock.method(prototype, 'transaction', function (this: unknown, ...args: unknown[]) {
        const value = Reflect.apply(transaction, this, args);
        if (this === actual && typeof value === 'number' && !changed) {
          changed = true;
          queueMicrotask(() => audit.transaction(connection => connection.prepare('UPDATE authorization_grants SET row_json=? WHERE grant_id=?')
            .run(canonicalJsonBytes({ ...JSON.parse(row.row_json), useCount: false }).toString('utf8'), grantId)));
        }
        return value;
      });
      try {
        // json_extract(false) and json_extract(0) both yield SQL integer 0.
        // The final source check must preserve the original JSON number type.
        await assert.rejects(store.listControl({ ...request, limit: 100 }, identity), { code: 'RECOVERY_REQUIRED' });
        assert.equal(changed, true);
      } finally {
        t.mock.restoreAll();
        audit.transaction(connection => connection.prepare('UPDATE authorization_grants SET row_json=? WHERE grant_id=?').run(row.row_json, grantId));
      }
      const restored = await store.listControl({ ...request, limit: 100 }, identity);
      assert.deepEqual(canonicalJsonBytes(restored), canonicalJsonBytes(active));
    } finally { audit.close(); }
    for (const change of [{ state: 'revoked' }, { targetKind: 'read_scope' }, { limit: 2 }])
      await assert.rejects(store.listControl({ ...nextRequest, ...change }, identity), { code: 'INVALID_REQUEST' });
  } finally { await disposeFixture({ ...fixture, store }); }
});
