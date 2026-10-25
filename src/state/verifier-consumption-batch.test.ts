// Actual CAS and SQLite data lifecycles only. These inert rows do not create a
// StateOwner, trusted toolchain, accepted Run or installed execution proof.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import ts from 'typescript';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { AuthorizationGrantV1 } from '../kernel/authorization.js';
import type { VerifierRequest } from '../kernel/control-submit.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { testFixture } from '../model/testing/fixtures.js';
import { readCanonicalArtifact } from './agent-context.js';
import { ArtifactCatalog } from './artifacts.js';
import { authorizationGrantCore, authorizationGrantId, decodeAuthorizationConsumptionReceipt,
  decodeAuthorizationGrant, VerifierAuthorizationError } from './authorization-artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { consumeOrRevokeAuthorization, readAuthorizationGrant } from './repositories/authorization-grants.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { signedVerifierAuthority } from './testing/verifier-authority.js';
import * as admission from './verifier-admission.js';

async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-verifier-consumption-'));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const catalog = new ArtifactCatalog(new ContentAddressedStore(root)), driver = openSqliteDriver(path.join(directory, 'data.sqlite'));
  t.after(async () => { driver.close(); await rm(directory, { recursive: true, force: true }); });
  driver.exec(`CREATE TABLE authorization_grants (grant_id TEXT PRIMARY KEY, owner_principal_id TEXT, state TEXT, row_json TEXT);
    CREATE TABLE control_requests (principal_id TEXT, method TEXT, request_id TEXT, request_digest TEXT, response_ref TEXT,
      channel_identity_ref TEXT, channel_identity_digest TEXT, committed_at TEXT);
    CREATE TABLE canonical_time_fence (id INTEGER PRIMARY KEY, state_owner_epoch INTEGER, last_accepted_at TEXT,
      observed_wall_clock_at TEXT, state TEXT, updated_at TEXT, fence_digest TEXT)`);
  const signed = await signedVerifierAuthority(), createdAt = '2026-10-25T00:00:00.000Z', admittedAt = '2026-10-25T00:00:01.000Z';
  const grant: AuthorizationGrantV1 = { schemaVersion: 1, grantId: '', ownerPrincipalId: 'inert-principal',
    channelIdentityRef: canonicalSha256('inert channel ref'), channelIdentityDigest: canonicalSha256('inert channel digest'),
    sourceRequestId: '019a1cb4-5000-7000-8000-000000000001', sourceRequestDigest: canonicalSha256('inert request'),
    target: { kind: 'execution_identity_read', purpose: 'verifier', identity: { kind: 'guest_toolchain',
      guestToolchainManifestRef: signed.manifestRef, manifestDigest: signed.manifest.manifestDigest,
      toolId: 'node', executionPath: '/usr/bin/node', executableDigest: signed.manifest.node.digest } },
    targetDigest: '', maxUses: 1, rowVersion: 1, createdAt, expiresAt: '2026-10-25T00:01:00.000Z',
    grantCoreDigest: '', state: 'active', useCount: 0, rowDigest: '' };
  grant.targetDigest = canonicalSha256(grant.target);
  grant.grantId = authorizationGrantId(grant.ownerPrincipalId, grant.sourceRequestId, grant.sourceRequestDigest);
  grant.grantCoreDigest = canonicalSha256(authorizationGrantCore(grant)); grant.rowDigest = digestOmitting(grant, 'rowDigest');
  decodeAuthorizationGrant(grant);
  driver.prepare('INSERT INTO authorization_grants VALUES (?, ?, ?, ?)')
    .run(grant.grantId, grant.ownerPrincipalId, grant.state, canonicalJsonBytes(grant).toString());
  driver.prepare('INSERT INTO control_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(grant.ownerPrincipalId,
    'authorization.create', grant.sourceRequestId, grant.sourceRequestDigest, canonicalSha256('inert response'),
    grant.channelIdentityRef, grant.channelIdentityDigest, createdAt);
  const fence = { schemaVersion: 1, format: 'cliq-canonical-time-fence-v1', stateOwnerEpoch: 1,
    lastAcceptedAt: admittedAt, observedWallClockAt: admittedAt, state: 'healthy', updatedAt: admittedAt, fenceDigest: '' };
  fence.fenceDigest = digestOmitting(fence, 'fenceDigest');
  driver.prepare('INSERT INTO canonical_time_fence VALUES (1, 1, ?, ?, ?, ?, ?)')
    .run(admittedAt, admittedAt, 'healthy', admittedAt, fence.fenceDigest);
  const selected = { manifest: signed.manifest, manifestRef: signed.manifestRef, abiFingerprint: signed.manifest.manifestDigest };
  const assembly = testFixture().assembly;
  Object.assign(assembly.runtime, { guestToolchainManifestRef: selected.manifestRef, guestToolchainManifestDigest: selected.manifest.manifestDigest });
  assembly.assemblyDigest = digestOmitting(assembly, 'assemblyDigest');
  const request: VerifierRequest = { id: 'tests', version: '1', required: true, executable: { kind: 'toolchain', toolId: 'node' },
    argv: [{ kind: 'non_secret_literal', value: '--test' }, { kind: 'non_secret_literal', value: '--test-concurrency=1' },
      { kind: 'non_secret_literal', value: 'test.mjs' }], cwd: '.', env: {}, writableEphemeralPaths: [], identityReadGrantId: grant.grantId };
  const composed = admission.composeVerifierSpec({ requests: [request], toolchain: selected, assembly, sourceProjectionRef: canonicalSha256('source') });
  const resolved = { composed, resolved: [{ request, grant, selected, creationCommittedAt: createdAt }] };
  const consumer = { runId: 'inert-run-data-only', admissionIntentDigest: canonicalSha256('inert admission intent'), admittedAt };
  return { root, catalog, driver, grant, resolved, consumer };
}

async function publisher() {
  // Execute the actual internal data publisher, not its authority resolver.
  // Before the fix the same real triple plus original receipt writer exposes
  // the old eight-directory-sync behavior, keeping the regression red-capable.
  const source = await readFile(new URL('./verifier-admission.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('verifier-admission.ts', source, ts.ScriptTarget.Latest, true);
  const functions = new Map(parsed.statements.filter(ts.isFunctionDeclaration).map(node => [node.name?.text, node]));
  const names = ['publishVerifierArtifacts', 'composeVerifierConsumption', 'verifierConsumptionResult', 'publishInstalledVerifierAdmission'];
  const body = names.flatMap(name => functions.has(name) ? [functions.get(name)!.getText(parsed)] : []).join('\n');
  const fallback = `async function publishInstalledVerifierAdmission(artifacts, resolution, consumer, expectedSpecRef, signal) {
    const {composed,resolved}=resolution;
    const metadata=await publishVerifierArtifacts(artifacts,composed,undefined,signal);
    const preparation={spec:composed.spec,specRef:composed.specRef,metadata,resolved};
    const consumption=await prepareVerifierConsumption(artifacts,preparation,consumer,signal);
    return {preparation,consumption};
  }`;
  const context = { canonicalJsonBytes, canonicalSha256, sha256Bytes, digestOmitting, readCanonicalArtifact,
    KernelStorageError, VerifierAuthorizationError, authorizationGrantCore, decodeAuthorizationGrant,
    decodeAuthorizationConsumptionReceipt, readAuthorizationGrant, consumeOrRevokeAuthorization,
    same: (a: unknown, b: unknown) => canonicalJsonBytes(a).equals(canonicalJsonBytes(b)),
    prepareVerifierConsumption: admission.prepareVerifierConsumption,
    invoke: undefined as unknown as (artifacts: ArtifactCatalog, resolution: Awaited<ReturnType<typeof fixture>>['resolved'],
      consumer: Awaited<ReturnType<typeof fixture>>['consumer'], expectedSpecRef: string, signal?: AbortSignal) =>
      Promise<{ preparation: { metadata: Array<{ ref: string }> }; consumption: Awaited<ReturnType<typeof admission.prepareVerifierConsumption>> }> };
  const code = ts.transpileModule(`${body}\n${functions.has('publishInstalledVerifierAdmission') ? '' : fallback}
    return publishInstalledVerifierAdmission;`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  return new Function(...Object.keys(context), code)(...Object.values(context)) as typeof context.invoke;
}

for (const existing of [false, true]) test(`installed final verifier and its original receipt ${existing ? 'republish' : 'publish'} four complete CAS objects before the unchanged SQLite consumption`, async t => {
  const f = await fixture(t), publish = await publisher(), open = fs.open.bind(fs);
  if (existing) await publish(f.catalog, f.resolved, f.consumer, f.resolved.composed.specRef);
  let roots = 0, files = 0; const active = new Set<object>();
  t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
    const handle = await open(...args); active.add(handle);
    const sync = handle.sync.bind(handle), close = handle.close.bind(handle);
    t.mock.method(handle, 'sync', async () => { await sync(); if (args[0] === f.root) roots++; else files++; });
    t.mock.method(handle, 'close', async () => { await close(); assert(active.delete(handle)); }); return handle;
  });
  const result = await publish(f.catalog, f.resolved, f.consumer, f.resolved.composed.specRef);
  assert.equal(roots, 4, 'the fresh final triple and original receipt share four boundaries, not eight');
  assert.equal(files, 4); assert.equal(active.size, 0);
  assert.equal(readAuthorizationGrant(f.driver, f.grant.grantId)!.state, 'active', 'CAS publication alone consumes no grant');
  const receipt = decodeAuthorizationConsumptionReceipt(await f.catalog.readCanonical(result.consumption.refs[0]!));
  assert.deepEqual(receipt.consumer, { kind: 'run_admission', runId: f.consumer.runId, admissionIntentDigest: f.consumer.admissionIntentDigest });
  assert.equal(receipt.consumedAt, f.consumer.admittedAt);
  assert.deepEqual(result.preparation.metadata.map(value => value.ref), f.resolved.composed.artifacts.map(value => value.ref));
  for (const { ref, value } of f.resolved.composed.artifacts) assert.deepEqual(await f.catalog.readBytes(ref), canonicalJsonBytes(value));
  assert.equal(result.consumption.refs[0], canonicalSha256(receipt));
  assert.deepEqual(await f.catalog.readBytes(result.consumption.refs[0]!), canonicalJsonBytes(receipt));
  assert.throws(() => f.driver.transaction(connection => { result.consumption.commit(connection, f.consumer.admittedAt); throw new Error('rollback original transaction'); }), /rollback original transaction/);
  assert.equal(readAuthorizationGrant(f.driver, f.grant.grantId)!.state, 'active');
  assert.throws(() => f.driver.transaction(connection => result.consumption.commit(connection, f.grant.createdAt)),
    error => error instanceof VerifierAuthorizationError);
  const revoked = { ...f.grant, state: 'revoked' as const, rowVersion: 2, revokedAt: f.consumer.admittedAt,
    revokedByRequestId: '019a1cb4-5000-7000-8000-000000000002', rowDigest: '' };
  revoked.rowDigest = digestOmitting(revoked, 'rowDigest'); decodeAuthorizationGrant(revoked);
  f.driver.prepare('UPDATE authorization_grants SET state=?,row_json=?').run('revoked', canonicalJsonBytes(revoked).toString());
  assert.throws(() => f.driver.transaction(connection => result.consumption.commit(connection, f.consumer.admittedAt)),
    error => error instanceof VerifierAuthorizationError);
  f.driver.prepare('UPDATE authorization_grants SET state=?,row_json=?').run('active', canonicalJsonBytes(f.grant).toString());
  assert.throws(() => f.driver.transaction(connection => result.consumption.commit(connection, f.grant.expiresAt)),
    error => error instanceof VerifierAuthorizationError);
  assert.equal(readAuthorizationGrant(f.driver, f.grant.grantId)!.state, 'active');
  f.driver.transaction(connection => result.consumption.commit(connection, f.consumer.admittedAt));
  const consumed = readAuthorizationGrant(f.driver, f.grant.grantId)!;
  assert.equal(consumed.state, 'consumed'); assert.equal(consumed.useCount, 1);
  assert.throws(() => f.driver.transaction(connection => result.consumption.commit(connection, f.consumer.admittedAt)),
    error => error instanceof VerifierAuthorizationError);
  assert.equal(active.size, 0);
});

test('every final quartet descriptor including the receipt must match its original full bytes before a consumer escapes', async t => {
  const f = await fixture(t), publish = await publisher(), original = f.catalog.publishCanonicalFour.bind(f.catalog);
  const other = await f.catalog.publishBytes(Buffer.from('x'), 'text/plain', 'other-real-data');
  for (const slot of [0, 1, 2, 3]) for (const field of ['ref', 'byteLength', 'mediaType', 'schemaKind', 'missing'] as const) {
    const replacement = t.mock.method(f.catalog, 'publishCanonicalFour', async (...args: Parameters<typeof original>) => {
      const actual = await original(...args), changed = [...actual];
      if (field === 'missing') delete changed[slot]; else changed[slot] = { ...actual[slot]!, [field]: other[field] };
      return changed as unknown as typeof actual;
    });
    try { await assert.rejects(publish(f.catalog, f.resolved, f.consumer, f.resolved.composed.specRef), { code: 'ARTIFACT_MISMATCH' }, `${slot}:${field}`); }
    finally { replacement.mock.restore(); }
    assert.equal(readAuthorizationGrant(f.driver, f.grant.grantId)!.state, 'active');
  }
});

test('an aborted or mismatching final installed quartet opens no CAS resource and changes no row', async t => {
  const f = await fixture(t), publish = await publisher(), owner = new AbortController(), reason = new Error('cancel before quartet');
  owner.abort(reason);
  t.mock.method(fs, 'open', async () => { throw new Error('refused quartet must not open CAS'); });
  await assert.rejects(publish(f.catalog, f.resolved, f.consumer, f.resolved.composed.specRef, owner.signal), error => error === reason);
  await assert.rejects(publish(f.catalog, f.resolved, f.consumer, canonicalSha256('wrong spec')), { code: 'ARTIFACT_MISMATCH' });
  assert.equal(readAuthorizationGrant(f.driver, f.grant.grantId)!.state, 'active'); assert.deepEqual(await readdir(f.root), []);
});

test('only current installed single-verifier admission uses the new quartet after fresh full resolution; ordinary time and final SQL remain original', async () => {
  const verifier = await readFile(new URL('./verifier-admission.ts', import.meta.url), 'utf8');
  const source = await readFile(new URL('./reducers/admission.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('verifier-admission.ts', verifier, ts.ScriptTarget.Latest, true);
  const operation = parsed.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'prepareInstalledVerifierAdmission');
  assert(operation?.body);
  const body = operation.body.getText(parsed);
  assert.match(body, /await resolveVerifierSpec\(driver, artifacts, owner, runtime, input, undefined, signal\)/u);
  assert(body.indexOf('await resolveVerifierSpec') < body.indexOf('publishInstalledVerifierAdmission('));
  assert(!body.includes('assembled') && !body.includes('sampleCanonicalNow'));
  assert.match(source, /if \(installed && verifierRequests\.length === 1\) \{[\s\S]*?await prepareInstalledVerifierAdmission/u);
  assert.match(source, /else verifierPreparation = await prepareVerifierSpec\(driver, reads, owner, runtime, verifierInput, undefined, signal\)/u);
  const metadata = source.indexOf('const referencedMetadata ='), sample = source.indexOf('const now = installed?.data.admittedAt ?? sampleCanonicalNow();', metadata);
  const ordinary = source.indexOf('if (!verifierConsumption && verifierPreparation) verifierConsumption = await prepareVerifierConsumption(', sample);
  assert(metadata >= 0 && sample > metadata && ordinary > sample);
  const transaction = source.indexOf('  driver.transaction((connection) => {', ordinary);
  const fresh = source.indexOf('const freshNow = sampleCanonicalNow();', transaction), consume = source.indexOf('verifierConsumption?.commit(connection, freshNow)', fresh);
  assert(transaction > ordinary && fresh > transaction && consume > fresh);
  for (const check of ['assertSessionContextCut(connection, sessionContext.cut)', 'assertActiveStateOwner(connection, owner)',
    'assertCurrentControlFrame(owner, installed.identity)', 'recheckInstalledRunWorkspace(installed.prepared, driver, owner, installed.identity, connection)'])
    assert(source.slice(transaction, consume).includes(check), check);
});

for (const fault of ['cancel', 'write', 'retirement'] as const)
  test(`final installed quartet preserves actual complete join and original grant during ${fault}`, async t => {
    const f = await fixture(t), publish = await publisher(), owner = new AbortController(), reason = new Error('cancel during actual quartet');
    const writeFailure = new Error('actual write failed after effect'), closeFailure = new Error('actual root close failed after effect');
    const open = fs.open.bind(fs), active = new Set<object>();
    let enter!: () => void, release!: () => void, settled = false, writes = 0;
    const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const handle = await open(...args); active.add(handle);
      const close = handle.close.bind(handle), write = handle.writeFile.bind(handle);
      if (String(args[0]).includes('/.tmp-stream-')) t.mock.method(handle, 'writeFile', async (...values: Parameters<typeof write>) => {
        await write(...values); if (++writes === 1 && fault !== 'cancel') throw writeFailure;
      });
      t.mock.method(handle, 'close', async () => {
        await close(); assert(active.delete(handle));
        if (args[0] === f.root) { enter(); await gate; if (fault === 'retirement') throw closeFailure; }
      }); return handle;
    });
    const pending = publish(f.catalog, f.resolved, f.consumer, f.resolved.composed.specRef, owner.signal);
    void pending.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.race([entered, pending.then(() => { throw new Error('original root join bypassed'); })]);
      assert.equal(writes, 4); assert.equal(active.size, 0);
      assert.equal(readAuthorizationGrant(f.driver, f.grant.grantId)!.state, 'active');
      owner.abort(reason); await new Promise<void>(resolve => setImmediate(resolve)); assert.equal(settled, false); release();
      await assert.rejects(pending, error => fault === 'cancel' ? error === reason : fault === 'write' ? error === writeFailure :
        error instanceof ResourceRetirementError && error.cause === closeFailure);
      assert.equal(readAuthorizationGrant(f.driver, f.grant.grantId)!.state, 'active');
      assert.equal(active.size, 0); assert((await readdir(f.root)).every(name => /^[a-f0-9]{64}$/u.test(name)));
    } finally { release(); await Promise.allSettled([pending]); }
  });
