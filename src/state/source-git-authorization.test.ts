import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { authorizationGrantCore, authorizationGrantId, authorizationSummary, decodeAuthorizationGrant,
  decodeAuthorizationConsumptionReceipt, VerifierAuthorizationError } from './authorization-artifacts.js';
import { decodeWireGrantSummary } from '../kernel/control-wire-data.js';
import type { AuthorizationConsumptionReceiptV1, AuthorizationGrantV1 } from '../kernel/authorization.js';
import { mkdir, mkdtemp, readlink, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { signedSourceInspectionMetadata as signedInspectionMetadata } from './testing/source-git-authority.js';
import { createQueuedFixture, disposeFixture, admissionKey, uuidv7 } from './testing/fixtures.js';
import { publishInProcessChannel, openStateStore } from './store.js';
import { testFixture } from '../model/testing/fixtures.js';
import type { WorkspaceIdentityV1 } from '../kernel/types.js';
import { createWorkspaceTrustContext, writePersistedWorkspaceTrust } from '../session/trust.js';
import { fixtureSandboxProfile } from './testing/worker-launch.js';
import { sourceInspectionRequest } from './testing/source-inspection-fixtures.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { KERNEL_DATABASE_FILENAME } from '../config.js';

const digest = 'a'.repeat(64), other = 'b'.repeat(64), start = '2026-10-25T00:00:00.000Z';
function grant(): AuthorizationGrantV1 {
  const base = { schemaVersion: 1 as const, grantId: authorizationGrantId('principal', '01900000-0000-7000-8000-000000000002', digest),
    ownerPrincipalId: 'principal', channelIdentityRef: digest, channelIdentityDigest: digest,
    sourceRequestId: '01900000-0000-7000-8000-000000000002', sourceRequestDigest: digest,
    target: { kind: 'source_git_inspection' as const, purpose: 'source_inspection' as const, sessionId: 'session',
      workspaceIdentityRef: digest, workspaceIdentityDigest: digest, repositoryIdentityRef: other, repositoryIdentityDigest: other,
      scope: 'in_root_git_metadata_and_objects' as const, recipe: 'cliq-source-git-inspection-v1' as const,
      retention: 'ephemeral_raw_reachable_only' as const, resourceCeiling: { ...DEFAULT_SANDBOX_RESOURCES },
      inspector: { runtimeBundleRef: digest, runtimeBundleManifestDigest: other, entryId: 'source_git_inspector' as const,
        entryVersion: '1' as const, entryDigest: other } }, targetDigest: '', maxUses: 1 as const,
    createdAt: start, expiresAt: '2026-10-25T01:00:00.000Z' };
  base.targetDigest = canonicalSha256(base.target);
  const result: AuthorizationGrantV1 = { ...base, rowVersion: 1, grantCoreDigest: canonicalSha256(base), state: 'active', useCount: 0, rowDigest: '' };
  result.rowDigest = digestOmitting(result, 'rowDigest'); return result;
}

test('retained source Git grant and source-inspection receipt have closed independent schemas', () => {
  const input = grant();
  assert.deepEqual(decodeAuthorizationGrant(input), input);
  assert.deepEqual(decodeWireGrantSummary(authorizationSummary(input)).purpose, 'source_inspection');
  const receipt: AuthorizationConsumptionReceiptV1 = { schemaVersion: 1, grantId: input.grantId, ownerPrincipalId: input.ownerPrincipalId,
    targetDigest: input.targetDigest, consumer: { kind: 'source_inspection', inspectionId: 'inspection', admissionIntentDigest: other },
    consumedAt: start, receiptDigest: '' };
  receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest');
  assert.deepEqual(decodeAuthorizationConsumptionReceipt(receipt), receipt);
  for (const consumer of [{ ...receipt.consumer, runId: 'run' }, { ...receipt.consumer, kind: 'run_admission' },
    { kind: 'source_inspection', inspectionId: 'inspection' }, { ...receipt.consumer, admissionIntentDigest: true }]) {
    const bad = { ...receipt, consumer, receiptDigest: '' }; bad.receiptDigest = digestOmitting(bad, 'receiptDigest');
    assert.throws(() => decodeAuthorizationConsumptionReceipt(bad), TypeError);
  }
});

test('retained source Git target cannot broaden scope, reuse ordinary grants, or select a program', () => {
  const input = grant(), target = input.target;
  assert.equal(target.kind, 'source_git_inspection');
  for (const change of [{ kind: 'read_scope' }, { purpose: 'source' }, { scope: 'all_files' }, { retention: 'durable_raw' },
    { inspector: { ...('inspector' in target ? target.inspector : {}), path: '/bin/sh' } },
    { resourceCeiling: {} }, { sourcePath: '/outside' }]) {
    const bad = { ...input, target: { ...target, ...change }, targetDigest: '', grantCoreDigest: '', rowDigest: '' };
    bad.targetDigest = canonicalSha256(bad.target);
    bad.grantCoreDigest = canonicalSha256(authorizationGrantCore(bad as AuthorizationGrantV1));
    bad.rowDigest = digestOmitting(bad, 'rowDigest');
    assert.throws(() => decodeAuthorizationGrant(bad), TypeError);
  }
});

test('real Store inspection consent replays and revokes without opening config or objects', async () => {
  const signed = await signedInspectionMetadata();
  const fixture = await createQueuedFixture('source-git-consent', { runtimeAuthority: { bundle: signed.bundle, releaseKeys: signed.releaseKeys }, assembly: async store => {
    for (const object of signed.objects) await store.artifacts.publishBytes(object.bytes, 'application/octet-stream', 'offline-inspection-object');
    const assembly = testFixture().assembly; return (await store.artifacts.publishCanonical(assembly, assembly.format)).ref;
  } });
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const workspace = path.join(fixture.stateRoot, 'owned-git-workspace');
    await mkdir(path.join(workspace, '.git'), { recursive: true, mode: 0o700 });
    const sentinel = path.join(fixture.stateRoot, 'owned-config-sentinel'); await writeFile(sentinel, 'not authorized to read\n', { mode: 0o600 });
    await symlink(sentinel, path.join(workspace, '.git/config'));
    const session = await fixture.store.createSession({ ...identity, requestId: uuidv7(), admissionKey: admissionKey('git-consent-second'), workspacePath: workspace });
    const captured = await fixture.store.artifacts.readCanonical<WorkspaceIdentityV1>(session.session.workspaceIdentityRef);
    assert.equal(captured.kind, 'live');
    if (captured.kind !== 'live') assert.fail('expected own live descriptor fixture');
    const core = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(), decision: {
      kind: 'source_git_inspection', purpose: 'source_inspection', target: { sessionId: session.session.id,
        expectedWorkspaceIdentityDigest: captured.identityDigest, scope: 'in_root_git_metadata_and_objects',
        recipe: 'cliq-source-git-inspection-v1', retention: 'ephemeral_raw_reachable_only', resourceCeiling: { ...DEFAULT_SANDBOX_RESOURCES } } } };
    const request = { ...core, requestDigest: canonicalSha256(core) };
    const created = await fixture.store.createAuthorization(request, identity);
    assert.equal(created.response.result.grant.purpose, 'source_inspection');
    assert.deepEqual((await fixture.store.createAuthorization(request, identity)).response, created.response);
    assert.equal(await readlink(path.join(workspace, '.git/config')), sentinel);
    const revokeCore = { protocolVersion: 1, method: 'authorization.revoke', requestId: uuidv7(), grantId: created.response.result.grant.grantId };
    const revoke = { ...revokeCore, requestDigest: canonicalSha256(revokeCore) };
    const revoked = await fixture.store.revokeAuthorization(revoke, identity);
    assert.equal(revoked.response.result.method, 'authorization.revoke');
    assert.equal(revoked.response.result.grant.state, 'revoked');
    assert.deepEqual((await fixture.store.createAuthorization(request, identity)).response, created.response);
    const readCore = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(), decision: {
      kind: 'read_scope', purpose: 'source', target: { sessionId: session.session.id,
        expectedWorkspaceIdentityDigest: captured.identityDigest, path: '.git/info/exclude', scope: 'entry' } } };
    const readRequest = { ...readCore, requestDigest: canonicalSha256(readCore) };
    const readCreated = await fixture.store.createAuthorization(readRequest, identity);
    assert.equal(readCreated.response.result.grant.targetKind, 'read_scope');
    assert.equal(readCreated.response.result.grant.purpose, 'source');
    assert.deepEqual((await fixture.store.createAuthorization(readRequest, identity)).response, readCreated.response);
    assert.equal(await readlink(path.join(workspace, '.git/config')), sentinel);
    const readRevokeCore = { protocolVersion: 1, method: 'authorization.revoke', requestId: uuidv7(), grantId: readCreated.response.result.grant.grantId };
    const readRevoke = { ...readRevokeCore, requestDigest: canonicalSha256(readRevokeCore) };
    const readRevoked = await fixture.store.revokeAuthorization(readRevoke, identity);
    assert.equal(readRevoked.response.result.grant.state, 'revoked');
    await fixture.store.close(); fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    const successor = await publishInProcessChannel(fixture.store);
    assert.deepEqual((await fixture.store.revokeAuthorization(revoke, successor)).response, revoked.response);
    assert.deepEqual((await fixture.store.createAuthorization(readRequest, successor)).response, readCreated.response);
    assert.deepEqual((await fixture.store.revokeAuthorization(readRevoke, successor)).response, readRevoked.response);
  } finally { await disposeFixture(fixture); }
});

test('Git inspection consumption and capturing are one real transaction while the unimplemented inspector stays refused', async () => {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'git-consent-capture-'));
  const stateRoot = path.join(directory, 'state'), home = path.join(directory, 'home'), workspace = path.join(directory, 'workspace');
  for (const member of [stateRoot, home, path.join(workspace, '.git')]) await mkdir(member, { recursive: true, mode: 0o700 });
  const sentinel = path.join(directory, 'private-sentinel'); await writeFile(sentinel, 'raw config not authorized for Supervisor\n', { mode: 0o600 });
  await symlink(sentinel, path.join(workspace, '.git/config'));
  await writePersistedWorkspaceTrust(await createWorkspaceTrustContext(workspace, home), 'trusted');
  const signed = await signedInspectionMetadata(), profile = fixtureSandboxProfile();
  profile.allowedOwners = ['source_inspection']; profile.profileDigest = digestOmitting(profile, 'profileDigest');
  const runtime = { bundle: signed.bundle, releaseKeys: signed.releaseKeys, sourceInspection: { controlledHome: home, sandboxProfile: profile } };
  let store = await openStateStore(stateRoot, runtime);
  try {
    for (const object of signed.objects) await store.artifacts.publishBytes(object.bytes, 'application/octet-stream', 'offline-inspection-object');
    const identity = await publishInProcessChannel(store);
    const session = await store.createSession({ ...identity, requestId: uuidv7(), admissionKey: admissionKey('git-capture-session'), workspacePath: workspace });
    const captured = await store.artifacts.readCanonical<WorkspaceIdentityV1>(session.session.workspaceIdentityRef);
    const core = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(), ttlMs: 60_000, decision: {
      kind: 'source_git_inspection', purpose: 'source_inspection', target: { sessionId: session.session.id,
        expectedWorkspaceIdentityDigest: captured.identityDigest, scope: 'in_root_git_metadata_and_objects', recipe: 'cliq-source-git-inspection-v1',
        retention: 'ephemeral_raw_reachable_only', resourceCeiling: { ...DEFAULT_SANDBOX_RESOURCES } } } };
    const created = await store.createAuthorization({ ...core, requestDigest: canonicalSha256(core) }, identity);
    const grantId = created.response.result.grant.grantId;
    const ruleCore = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(), ttlMs: 60_000,
      decision: { kind: 'read_scope', purpose: 'source', target: { sessionId: session.session.id,
        expectedWorkspaceIdentityDigest: captured.identityDigest, path: '.git/info/exclude', scope: 'entry' } } };
    const rules = await store.createAuthorization({ ...ruleCore, requestDigest: canonicalSha256(ruleCore) }, identity);
    const ruleGrantId = rules.response.result.grant.grantId;
    const makeRead = async (readPath: string, scope = 'entry') => {
      const fields = { ...ruleCore, requestId: uuidv7(), decision: { ...ruleCore.decision,
        target: { ...ruleCore.decision.target, path: readPath, scope } } };
      return (await store.createAuthorization({ ...fields, requestDigest: canonicalSha256(fields) }, identity)).response.result.grant.grantId;
    };
    const ordinary = await makeRead('ordinary.txt'), subtree = await makeRead('nested/.gitignore', 'subtree');
    const duplicatePath = await makeRead('.git/info/exclude');
    for (const ignored of [[ordinary], [subtree], [ruleGrantId, duplicatePath]]) {
      await assert.rejects(store.captureSubmittedSource({ request: sourceInspectionRequest({ sessionId: session.session.id,
        workspacePath: workspace, sourceInspectionGrantId: grantId, ignoreReadGrantIds: ignored }), identity }),
      error => error instanceof VerifierAuthorizationError && error.refusalCode === 'AUTHORIZATION_REQUIRED',
      'ordinary file/subtree grants and duplicated rule-file scopes cannot become ignore-rule permission');
    }
    const request = sourceInspectionRequest({ sessionId: session.session.id, workspacePath: workspace, sourceInspectionGrantId: grantId,
      ignoreReadGrantIds: [ruleGrantId] });
    const sql = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      sql.exec("CREATE TRIGGER source_git_capture_rollback BEFORE INSERT ON source_inspection_attempts BEGIN SELECT RAISE(ABORT, 'source Git capture rollback'); END");
      try { await assert.rejects(store.captureSubmittedSource({ request, identity }), /source Git capture rollback/); }
      finally { sql.exec('DROP TRIGGER source_git_capture_rollback'); }
      assert.equal(sql.prepare('SELECT state FROM authorization_grants WHERE grant_id=?').get<{ state: string }>(grantId)?.state, 'active');
      assert.equal(sql.prepare('SELECT state FROM authorization_grants WHERE grant_id=?').get<{ state: string }>(ruleGrantId)?.state, 'active');
      assert.equal(sql.prepare('SELECT count(*) AS n FROM source_inspection_attempts').get<{ n: bigint }>()?.n, 0n);
      const retired = await store.captureSubmittedSource({ request, identity });
      assert.equal(retired.phase, 'retired');
      if (retired.phase !== 'retired') assert.fail('capture must really close its existing staging');
      assert.equal(retired.outcome.kind, 'failed', 'a valid grant does not remove the native inspector production refusal');
      const row = JSON.parse(sql.prepare('SELECT row_json FROM authorization_grants WHERE grant_id=?').get<{ row_json: string }>(grantId)!.row_json);
      const grant = decodeAuthorizationGrant(row);
      assert.equal(grant.state, 'consumed');
      const ruleGrant = decodeAuthorizationGrant(JSON.parse(sql.prepare('SELECT row_json FROM authorization_grants WHERE grant_id=?')
        .get<{ row_json: string }>(ruleGrantId)!.row_json));
      assert.equal(ruleGrant.state, 'consumed', 'rule-read consent shares the actual capturing transaction, not the Git scope');
      const target = await store.artifacts.readCanonical<{ ignoreReadConsents: { grantId: string; receiptRef: string }[] }>(retired.targetRef);
      assert.equal(target.ignoreReadConsents.length, 1); assert.equal(target.ignoreReadConsents[0]!.grantId, ruleGrantId);
      assert.equal(target.ignoreReadConsents[0]!.receiptRef, ruleGrant.consumptionReceiptRef);
      assert(retired.deadlineAt <= grant.expiresAt);
      assert.deepEqual(await store.captureSubmittedSource({ request, identity }), retired, 'failure replays without a second raw read or consumption');
      const revokeCore = { protocolVersion: 1, method: 'authorization.revoke', requestId: uuidv7(), grantId };
      const revoked = await store.revokeAuthorization({ ...revokeCore, requestDigest: canonicalSha256(revokeCore) }, identity);
      assert.equal(revoked.response.result.method, 'authorization.revoke');
      if (revoked.response.result.method !== 'authorization.revoke') assert.fail('revoke response');
      assert.equal(revoked.response.result.disposition, 'already_consumed');
      assert.equal(await readlink(path.join(workspace, '.git/config')), sentinel);
      const anotherCore = { ...core, requestId: uuidv7() };
      const another = await store.createAuthorization({ ...anotherCore, requestDigest: canonicalSha256(anotherCore) }, identity);
      await assert.rejects(store.captureSubmittedSource({ request: sourceInspectionRequest({ sessionId: session.session.id,
        workspacePath: workspace, admissionKey: admissionKey('consumed-ignore-reuse'),
        sourceInspectionGrantId: another.response.result.grant.grantId, ignoreReadGrantIds: [ruleGrantId] }), identity }),
      error => error instanceof VerifierAuthorizationError && error.refusalCode === 'AUTHORIZATION_REQUIRED',
      'a consumed rule-file grant cannot authorize another capture');
    } finally { sql.close(); }
    await store.close(); store = await openStateStore(stateRoot, runtime);
    assert.deepEqual(await store.captureSubmittedSource({ request, identity: await publishInProcessChannel(store) }),
      await store.captureSubmittedSource({ request, identity: await publishInProcessChannel(store) }));
  } finally { await store.close(); await rm(directory, { recursive: true, force: true }); }
});
