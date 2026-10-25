// Inert release-reference selection and actual SQLite/CAS data only. No
// StateOwner, creation history, permission, Run, installed or native proof is
// produced by these values; the ordinary full readers remain mandatory.
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { Script } from 'node:vm';
import { transformSync } from 'esbuild';
import ts from 'typescript';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { AuthorizationGrantV1 } from '../kernel/authorization.js';
import type { VerifierRequest } from '../kernel/control-submit.js';
import { digestOmitting } from '../kernel/identity.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { verifyRuntimeBundle } from '../policy/runtime-authority.js';
import { authorizationGrantCore, authorizationGrantId, decodeAuthorizationConsumptionReceipt, VerifierAuthorizationError } from './authorization-artifacts.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import { readRetainedVerifierToolchain } from './guest-toolchain.js';
import { readAuthorizationGrant } from './repositories/authorization-grants.js';
import { signedVerifierAuthority } from './testing/verifier-authority.js';
import * as admission from './verifier-admission.js';

type ReleaseReference = Readonly<{ manifestRef: string; manifestDigest: string }>;
function select(driver: SqliteDriver, bundle: RuntimeBundleManifest, principal: string,
  requests: readonly VerifierRequest[], mode = 'yolo', signal?: AbortSignal): ReleaseReference | undefined {
  const operation = Reflect.get(admission, 'selectVerifierReleaseReference');
  assert.equal(typeof operation, 'function', 'installed selection must not traverse the target/history graph to select its root');
  return operation(driver, bundle, principal, requests, mode, signal);
}
function seal(grant: AuthorizationGrantV1): AuthorizationGrantV1 {
  grant.targetDigest = canonicalSha256(grant.target);
  grant.grantId = authorizationGrantId(grant.ownerPrincipalId, grant.sourceRequestId, grant.sourceRequestDigest);
  grant.grantCoreDigest = canonicalSha256(authorizationGrantCore(grant));
  grant.rowDigest = digestOmitting(grant, 'rowDigest');
  return grant;
}
async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-release-reference-'));
  const driver = openSqliteDriver(path.join(directory, 'ordinary-data.sqlite'));
  t.after(async () => { driver.close(); await rm(directory, { recursive: true, force: true }); });
  driver.exec('CREATE TABLE authorization_grants (grant_id TEXT PRIMARY KEY, owner_principal_id TEXT, state TEXT, row_json TEXT)');
  const signed = await signedVerifierAuthority(); verifyRuntimeBundle(signed.bundle, signed.releaseKeys);
  const now = Date.parse(sampleCanonicalNow()), principal = 'inert-selector-principal';
  const grant = seal({ schemaVersion: 1, grantId: '', ownerPrincipalId: principal,
    channelIdentityRef: canonicalSha256('inert channel ref'), channelIdentityDigest: canonicalSha256('inert channel digest'),
    sourceRequestId: '019a1cb4-5000-7000-8000-000000000001', sourceRequestDigest: canonicalSha256('inert original request'),
    target: { kind: 'execution_identity_read', purpose: 'verifier', identity: { kind: 'guest_toolchain',
      guestToolchainManifestRef: signed.manifestRef, manifestDigest: signed.manifest.manifestDigest,
      toolId: 'node', executionPath: '/usr/bin/node', executableDigest: signed.manifest.node.digest } },
    targetDigest: '', maxUses: 1, rowVersion: 1, createdAt: new Date(now - 60_000).toISOString(),
    expiresAt: new Date(now + 3_600_000).toISOString(), grantCoreDigest: '', state: 'active', useCount: 0, rowDigest: '' });
  const request: VerifierRequest = { id: 'test', version: '1', required: true,
    executable: { kind: 'toolchain', toolId: 'node' },
    argv: [{ kind: 'non_secret_literal', value: '--test' }, { kind: 'non_secret_literal', value: '--test-concurrency=1' },
      { kind: 'non_secret_literal', value: 'test.mjs' }], cwd: '.', env: {}, writableEphemeralPaths: [], identityReadGrantId: grant.grantId };
  const store = (value: AuthorizationGrantV1) => driver.prepare('INSERT OR REPLACE INTO authorization_grants VALUES (?, ?, ?, ?)')
    .run(value.grantId, value.ownerPrincipalId, value.state, canonicalJsonBytes(value).toString());
  store(grant);
  return { directory, driver, signed, principal, grant, request, store };
}

test('the installed first selection returns only the signed root ref/digest without any target CAS being present', async t => {
  const f = await fixture(t);
  const reference = select(f.driver, f.signed.bundle, f.principal, [f.request]);
  assert.deepEqual(reference, { manifestRef: f.signed.manifestRef, manifestDigest: f.signed.manifest.manifestDigest });
  assert.deepEqual(Object.keys(reference!).sort(), ['manifestDigest', 'manifestRef']);
  assert(Object.isFrozen(reference));
});

test('no verifier selects no release and does not even query a grant or require a guest root', async t => {
  const f = await fixture(t);
  f.driver.exec('DROP TABLE authorization_grants');
  const bundle = { ...f.signed.bundle, structuredArtifacts: [], guestToolchainManifestRefs: [] };
  assert.equal(select(f.driver, bundle, f.principal, []), undefined);
});

test('distinct verifier grants may select one root but never waive the original supported policy mode', async t => {
  const f = await fixture(t), grant = structuredClone(f.grant), second = structuredClone(f.request);
  grant.sourceRequestId = '019a1cb4-5000-7000-8000-000000000004'; seal(grant); f.store(grant);
  second.id = 'second'; second.identityReadGrantId = grant.grantId;
  assert.deepEqual(select(f.driver, f.signed.bundle, f.principal, [f.request, second]),
    { manifestRef: f.signed.manifestRef, manifestDigest: f.signed.manifest.manifestDigest });
  assert.throws(() => select(f.driver, f.signed.bundle, f.principal, [f.request], 'default'),
    error => error instanceof VerifierAuthorizationError && error.refusalCode === 'AUTHORIZATION_REQUIRED');
});

for (const fault of ['missing', 'principal', 'consumed', 'revoked', 'future', 'expired', 'row-columns', 'row-digest',
  'target-kind', 'target-purpose', 'target-tool', 'target-ref', 'target-digest', 'executable-digest'] as const)
  test(`release selection refuses ${fault} in the real retained row lookup`, async t => {
    const f = await fixture(t), grant = structuredClone(f.grant), now = Date.now();
    if (fault === 'missing') f.driver.exec('DELETE FROM authorization_grants');
    else if (fault === 'row-columns') f.driver.prepare('UPDATE authorization_grants SET owner_principal_id = ?').run('other');
    else if (fault === 'row-digest') f.driver.prepare('UPDATE authorization_grants SET row_json = ?')
      .run(canonicalJsonBytes({ ...grant, rowDigest: canonicalSha256('wrong row') }).toString());
    else {
      if (fault === 'principal') grant.ownerPrincipalId = 'other-principal';
      if (fault === 'consumed') Object.assign(grant, { state: 'consumed', rowVersion: 2, useCount: 1,
        consumedAt: new Date(now - 1000).toISOString(), consumptionReceiptRef: canonicalSha256('inert receipt') });
      if (fault === 'revoked') Object.assign(grant, { state: 'revoked', rowVersion: 2, useCount: 0,
        revokedAt: new Date(now - 1000).toISOString(), revokedByRequestId: '019a1cb4-5000-7000-8000-000000000002' });
      if (fault === 'future') grant.createdAt = new Date(now + 60_000).toISOString();
      if (fault === 'expired') grant.expiresAt = new Date(now - 1000).toISOString();
      const target = grant.target as Extract<AuthorizationGrantV1['target'], { kind: 'execution_identity_read'; purpose: 'verifier' }>;
      assert.equal(target.identity.kind, 'guest_toolchain');
      if (target.identity.kind !== 'guest_toolchain') assert.fail('inert data branch');
      if (fault === 'target-kind') Object.assign(target, { kind: 'read_scope' });
      if (fault === 'target-purpose') Object.assign(target, { purpose: 'mcp_stdio' });
      if (fault === 'target-tool') target.identity.toolId = 'git';
      if (fault === 'target-ref') target.identity.guestToolchainManifestRef = canonicalSha256('another root');
      if (fault === 'target-digest') target.identity.manifestDigest = canonicalSha256('another semantic digest');
      if (fault === 'executable-digest') target.identity.executableDigest = 'not-a-digest';
      seal(grant); f.store(grant); f.request.identityReadGrantId = grant.grantId;
    }
    assert.throws(() => select(f.driver, f.signed.bundle, f.principal, [f.request]));
  });

for (const fault of ['no-root', 'duplicate-root', 'wrong-entry', 'root-digest', 'request-tool', 'duplicate-request', 'unknown-request-field'] as const)
  test(`release selection refuses ${fault} without reading a target`, async t => {
    const f = await fixture(t), bundle = structuredClone(f.signed.bundle), requests = [f.request];
    const root = bundle.structuredArtifacts.find(root => root.kind === 'guest_toolchain')!;
    if (fault === 'no-root') { bundle.structuredArtifacts = bundle.structuredArtifacts.filter(root => root.kind !== 'guest_toolchain'); bundle.guestToolchainManifestRefs = []; }
    if (fault === 'duplicate-root') { bundle.structuredArtifacts.push({ ...root }); bundle.guestToolchainManifestRefs.push(root.artifactRef); }
    if (fault === 'wrong-entry') bundle.entries.find(entry => entry.entryId === root.rootEntryId)!.executable = true;
    if (fault === 'root-digest') root.semanticDigest = canonicalSha256('changed signed root digest');
    if (fault === 'request-tool') Object.assign(f.request.executable, { toolId: 'git' });
    if (fault === 'duplicate-request') requests.push(structuredClone(f.request));
    if (fault === 'unknown-request-field') Object.assign(f.request, { unrequestedAuthority: true });
    assert.throws(() => select(f.driver, bundle, f.principal, requests));
  });

test('every requested verifier must select the same signed root, not one arbitrary root from the release', async t => {
  const f = await fixture(t), bundle = structuredClone(f.signed.bundle);
  const ref = canonicalSha256('second inert root'), digest = canonicalSha256('second inert semantic digest');
  bundle.entries.push({ entryId: 'second-root-entry', role: 'guest_toolchain', version: '1', relativePath: 'profiles/second.json',
    digest: ref, byteCount: 1, executable: false });
  bundle.structuredArtifacts.push({ kind: 'guest_toolchain', artifactId: 'second-root', rootEntryId: 'second-root-entry',
    artifactRef: ref, semanticDigest: digest, memberRefs: [] });
  bundle.guestToolchainManifestRefs.push(ref);
  const grant = structuredClone(f.grant); grant.sourceRequestId = '019a1cb4-5000-7000-8000-000000000003';
  const target = grant.target;
  if (target.kind !== 'execution_identity_read' || target.identity.kind !== 'guest_toolchain') assert.fail('inert data branch');
  target.identity.guestToolchainManifestRef = ref; target.identity.manifestDigest = digest; seal(grant); f.store(grant);
  const second = structuredClone(f.request); second.id = 'second'; second.identityReadGrantId = grant.grantId;
  assert.throws(() => select(f.driver, bundle, f.principal, [f.request, second]),
    (error: unknown) => error instanceof VerifierAuthorizationError && error.refusalCode === 'UNSUPPORTED_EXECUTION_IDENTITY');
});

test('cancellation preserves its original reason before lookup and before returning a selected reference', async t => {
  const f = await fixture(t), controller = new AbortController(), reason = new Error('original caller cancellation');
  controller.abort(reason);
  assert.throws(() => select(f.driver, f.signed.bundle, f.principal, [f.request], 'yolo', controller.signal), error => error === reason);
  const during = new AbortController(), prepare = f.driver.prepare.bind(f.driver);
  t.mock.method(f.driver, 'prepare', (...args: Parameters<typeof prepare>) => {
    const statement = prepare(...args), get = statement.get.bind(statement);
    t.mock.method(statement, 'get', (...parameters: Parameters<typeof get>) => { const result = get(...parameters); during.abort(reason); return result; });
    return statement;
  });
  assert.throws(() => select(f.driver, f.signed.bundle, f.principal, [f.request], 'yolo', during.signal), error => error === reason);
});

test('a selected reference does not validate executable bytes or bypass the later history and actual CAS image walk', async t => {
  const f = await fixture(t), root = path.join(f.directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const catalog = new ArtifactCatalog(new ContentAddressedStore(root));
  for (const object of f.signed.objects) if (object.ref !== f.signed.manifest.guestImageRef)
    await catalog.publishBytes(object.bytes, 'application/octet-stream', 'inert-signed-data');
  const source = await readFile(new URL('./verifier-admission.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('verifier-admission.ts', source, ts.ScriptTarget.Latest, true);
  const reader = parsed.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'readVerifierRequestIdentities');
  assert(reader);
  let historyCalls = 0, imageReads = 0, rejectHistory = true;
  const failure = new Error('inert history callback refusal; not authority evidence'), readChunks = catalog.readChunks.bind(catalog);
  t.mock.method(catalog, 'readChunks', (...args: Parameters<typeof readChunks>) => {
    if (args[0] === f.signed.manifest.guestImageRef) imageReads++;
    return readChunks(...args);
  });
  const context = { readAuthorizationGrant, sampleCanonicalNow, VerifierAuthorizationError, readRetainedVerifierToolchain,
    decodeAuthorizationConsumptionReceipt, same: (a: unknown, b: unknown) => canonicalJsonBytes(a).equals(canonicalJsonBytes(b)),
    reportInstalledVerifierPreparationPhase: () => undefined,
    readAuthorizationHistory: async () => { historyCalls++; if (rejectHistory) throw failure; return { committedAt: f.grant.createdAt }; },
    invoke: undefined as undefined | ((...args: unknown[]) => Promise<unknown>) };
  new Script(transformSync(`${reader.getText(parsed).replace(/^export /u, '')}; globalThis.invoke = readVerifierRequestIdentities;`,
    { loader: 'ts' }).code).runInNewContext(context);
  const invoke = () => context.invoke!(f.driver, catalog, undefined, { bundle: f.signed.bundle, releaseKeys: f.signed.releaseKeys }, f.principal, [f.request]);
  assert(select(f.driver, f.signed.bundle, f.principal, [f.request]));
  await assert.rejects(invoke(), error => error === failure); assert.equal(historyCalls, 1); assert.equal(imageReads, 0);
  rejectHistory = false;
  await assert.rejects(invoke(), 'the original full reader must reject the missing actual image');
  assert.equal(historyCalls, 2); assert.equal(imageReads, 1);
  const image = f.signed.objects.find(object => object.ref === f.signed.manifest.guestImageRef)!;
  await catalog.publishBytes(image.bytes, 'application/octet-stream', 'inert-image-never-executed');
  const target = f.grant.target;
  if (target.kind !== 'execution_identity_read' || target.identity.kind !== 'guest_toolchain') assert.fail('inert data branch');
  target.identity.executableDigest = canonicalSha256('well-formed but incorrect executable digest'); seal(f.grant); f.store(f.grant);
  assert(select(f.driver, f.signed.bundle, f.principal, [f.request]), 'the selector intentionally returns no executable validation');
  await assert.rejects(invoke(), error => error instanceof VerifierAuthorizationError && error.refusalCode === 'AUTHORIZATION_REQUIRED');
  assert.equal(historyCalls, 3); assert.equal(imageReads, 2);
  target.identity.executableDigest = f.signed.manifest.node.digest; target.identity.executionPath = '/opt/not-the-signed-node';
  seal(f.grant); f.store(f.grant);
  assert(select(f.driver, f.signed.bundle, f.principal, [f.request]), 'an inert reference is not an executable-path proof either');
  await assert.rejects(invoke(), error => error instanceof VerifierAuthorizationError && error.refusalCode === 'AUTHORIZATION_REQUIRED');
  assert.equal(historyCalls, 4); assert.equal(imageReads, 3);
  assert.equal(readAuthorizationGrant(f.driver, f.grant.grantId)!.state, 'active', 'reference/data reads never consume a grant');
});

test('the actual first installed assembly expression uses only reference selection rather than the complete identity reader', async t => {
  const f = await fixture(t), source = await readFile(new URL('./installed-run.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('installed-run.ts', source, ts.ScriptTarget.Latest, true), declarations: string[] = [];
  const assembly = parsed.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'assembleInstalledRun');
  assert(assembly);
  function visit(node: ts.Node) {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) &&
        ['verifierIdentities', 'verifierToolchain'].includes(node.name.text)) declarations.push(`const ${node.getText(parsed)};`);
    ts.forEachChild(node, visit);
  }
  visit(assembly); assert(declarations.length > 0);
  let fullReaderCalls = 0;
  const context = { driver: f.driver, installed: { bundle: f.signed.bundle }, identity: { principalId: f.principal },
    request: { verifiers: [f.request], policyMode: 'yolo' }, signal: undefined, reads: undefined, owner: undefined,
    selectVerifierReleaseReference: Reflect.get(admission, 'selectVerifierReleaseReference'),
    readVerifierRequestIdentities: () => { fullReaderCalls++; throw new Error('old full-reader call reached; inert wiring observation only'); },
    invoke: undefined as undefined | (() => Promise<ReleaseReference>) };
  new Script(transformSync(`async function invoke() { ${declarations.join('\n')} return verifierToolchain; }
    globalThis.invoke = invoke;`, { loader: 'ts' }).code).runInNewContext(context);
  const reference = await context.invoke!();
  assert.deepEqual(reference, { manifestRef: f.signed.manifestRef, manifestDigest: f.signed.manifest.manifestDigest });
  assert.equal(fullReaderCalls, 0, 'the removed traversal is only the original first selection, not a later authority gate');
});
