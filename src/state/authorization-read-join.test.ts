// Execute only the original two historical read statements. These archived
// identity payloads are decoder data, not a StateOwner, Run, authenticated
// frame, native observation or installed/Linux qualification evidence.
import assert from 'node:assert/strict';
import { constants, promises as fs } from 'node:fs';
import { mkdir, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import ts from 'typescript';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { readCanonicalArtifact } from './agent-context.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readRetainedControlChannelClosure } from './control-channel.js';
import { joinResourceOperations, ResourceRetirementError } from './errors.js';

function gate() {
  let release!: () => void;
  return { promise: new Promise<void>(resolve => { release = resolve; }), release };
}
async function originalReadPair() {
  const text = await readFile(new URL('./authorization.ts', import.meta.url), 'utf8');
  const source = ts.createSourceFile('authorization.ts', text, ts.ScriptTarget.Latest, true);
  const body = source.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'readAuthorizationHistory')?.body;
  assert(body, 'use the actual historical reader, never an authority-bearing replacement');
  const at = (name: string) => body.statements.findIndex(node => ts.isVariableStatement(node) &&
    node.declarationList.declarations.some(value => value.name.getText(source) === name));
  const row = at('row'), request = at('request');
  assert(row >= 0 && request > row, 'retain the original creation-row lookup before the independent reads and request decode after them');
  const statements = body.statements.slice(row + 1, request).map(node => node.getText(source)).join('\n');
  const output = ts.transpileModule(`return async (artifacts, owner, grant) => { ${statements}; return { channel, core }; };`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  return new Function('readRetainedControlChannelClosure', 'readCanonicalArtifact', 'joinResourceOperations', output)(
    readRetainedControlChannelClosure, readCanonicalArtifact, joinResourceOperations) as
    (artifacts: ArtifactCatalog, retainedRoot: Parameters<typeof readRetainedControlChannelClosure>[1], source: {
      ownerPrincipalId: string; channelIdentityRef: string; channelIdentityDigest: string; sourceRequestDigest: string
    }) => Promise<{ channel: unknown; core: unknown }>;
}

async function fixture(t: TestContext) {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-authorization-read-join-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const directory = path.join(home, 'objects'); await mkdir(directory, { mode: 0o700 });
  const heldRoot = await fs.open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const info = await heldRoot.stat({ bigint: true }); await heldRoot.close();
  const uid = Number(info.uid), platform = process.platform === 'linux' ? 'linux' : 'macos';
  const cas = new ContentAddressedStore(directory), artifacts = new ArtifactCatalog(cas);
  const root = { schemaVersion: 1 as const, format: 'cliq-state-root-identity-v1' as const, platform,
    canonicalAbsolutePath: await realpath(directory), ownerUid: uid, deviceId: String(info.dev), directoryFileId: String(info.ino),
    mode: 448 as const, openedNoFollow: true as const, layoutVersion: 1 as const, identityDigest: '' };
  root.identityDigest = digestOmitting(root, 'identityDigest');
  const rootRef = (await artifacts.publishCanonical(root, root.format)).ref;
  const principalId = identityHash('cliq-local-principal-v1', root.identityDigest, platform, uid);
  const principal = { schemaVersion: 1, format: 'cliq-local-principal-identity-v1', platform, effectiveUid: uid,
    stateRootIdentityRef: rootRef, stateRootIdentityDigest: root.identityDigest, principalId, identityDigest: '' };
  principal.identityDigest = digestOmitting(principal, 'identityDigest');
  const principalRef = (await artifacts.publishCanonical(principal, principal.format)).ref;
  const openedAt = '2026-10-25T00:00:00.000Z';
  const processIdentity = { schemaVersion: 1, format: 'cliq-platform-process-identity-v1', platform, pid: 1,
    ownerUid: uid, processStartToken: 'archived-decoder-data-only', executableImageDigest: canonicalSha256('not-native-proof'),
    observedAt: openedAt, identityDigest: '' };
  processIdentity.identityDigest = digestOmitting(processIdentity, 'identityDigest');
  const processRef = (await artifacts.publishCanonical(processIdentity, processIdentity.format)).ref;
  const channel = { schemaVersion: 1, format: 'cliq-local-control-channel-identity-v1', client: 'cli', principalId,
    principalIdentityRef: principalRef, principalIdentityDigest: principal.identityDigest, openedAt,
    transport: { kind: 'in_process', processIdentityRef: processRef, processIdentityDigest: processIdentity.identityDigest },
    channelNonceDigest: canonicalSha256('archived-nonce-data-only'), channelIdentityDigest: '' };
  channel.channelIdentityDigest = digestOmitting(channel, 'channelIdentityDigest');
  const channelRef = (await artifacts.publishCanonical(channel, channel.format)).ref;
  const core = { input: 'complete original request-core bytes, never permission' };
  const requestRef = (await artifacts.publishCanonical(core, 'authorization-read-data-only')).ref;
  return { directory, cas, artifacts, channel, core, channelRef, requestRef,
    retainedRoot: { stateRootIdentityRef: rootRef, stateRootIdentityDigest: root.identityDigest, filesystem: { root: { ownerUid: uid } } },
    source: { ownerPrincipalId: principalId, channelIdentityRef: channelRef,
      channelIdentityDigest: channel.channelIdentityDigest, sourceRequestDigest: requestRef } };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;

function observe(t: TestContext, f: Fixture, ordinary = new Map<string, Error>(), retireRef?: string, retirement?: Error) {
  const entered = new Map([f.channelRef, f.requestRef].map(ref => [ref, gate()])), release = new Map([f.channelRef, f.requestRef].map(ref => [ref, gate()]));
  const gated = new Set<string>(), issued: string[] = [], active = new Set<object>(), raw: Promise<unknown>[] = [], errors = new Map<string, unknown>();
  const open = fs.open.bind(fs), read = f.cas.read.bind(f.cas); let opened = 0, closed = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await open(...args); active.add(handle); opened++;
    const close = handle.close.bind(handle), ref = path.basename(String(args[0]));
    t.mock.method(handle, 'close', async () => {
      await close(); assert(active.delete(handle)); closed++;
      if (entered.has(ref) && !gated.has(ref)) {
        gated.add(ref); entered.get(ref)!.release(); await release.get(ref)!.promise;
        if (ref === retireRef) throw retirement;
      }
    });
    return handle;
  });
  t.mock.method(f.cas, 'read', (...args: Parameters<typeof f.cas.read>) => {
    issued.push(args[0]);
    const pending = read(...args).then(value => { if (ordinary.has(args[0])) throw ordinary.get(args[0]); return value; })
      .catch(error => { errors.set(args[0], error); throw error; });
    raw.push(pending); return pending;
  });
  return { entered, release, issued, active, errors, raw,
    releaseAll() { for (const value of release.values()) value.release(); },
    assertJoined() { assert.equal(active.size, 0); assert.equal(opened, closed); } };
}

test('the original historical reader issues both real CAS branches before either returns and retains success field order', async t => {
  const f = await fixture(t), read = await originalReadPair(), seen = observe(t, f);
  const pending = read(f.artifacts, f.retainedRoot, f.source); void pending.catch(() => undefined);
  try {
    await seen.entered.get(f.channelRef)!.promise; await setImmediate();
    assert(seen.issued.includes(f.requestRef), 'the independent original request-core read must already own its real CAS operation');
    assert.deepEqual(seen.issued.slice(0, 2), [f.channelRef, f.requestRef], 'the two actual source reads retain their input order');
    await seen.entered.get(f.requestRef)!.promise;
    seen.release.get(f.requestRef)!.release(); await setImmediate();
    assert(seen.active.size > 0, 'the other branch still owns an original CAS root while its object-close return is gated');
    seen.release.get(f.channelRef)!.release();
    assert.deepEqual(await pending, { channel: f.channel, core: f.core }); seen.assertJoined();
  } finally { seen.releaseAll(); await Promise.allSettled([pending, ...seen.raw]); seen.assertJoined(); }
});

for (const late of ['ordinary', 'retirement'] as const) test(late === 'ordinary'
  ? 'historical reads preserve channel-first error identity even when the request fails first'
  : 'historical reads join and retain a later request CAS retirement failure over ordinary channel failure', async t => {
  const f = await fixture(t), read = await originalReadPair();
  const channelError = new Error('original channel read failed after its actual CAS return'), requestError = new Error('original request failure');
  const seen = observe(t, f, new Map([[f.channelRef, channelError], ...(late === 'ordinary' ? [[f.requestRef, requestError] as const] : [])]),
    late === 'retirement' ? f.requestRef : undefined, requestError);
  let settled = false;
  const pending = read(f.artifacts, f.retainedRoot, f.source); void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    await seen.entered.get(f.channelRef)!.promise; await setImmediate();
    assert(seen.issued.includes(f.requestRef), 'both original read branches must issue before the channel can fail');
    await seen.entered.get(f.requestRef)!.promise;
    seen.release.get(late === 'ordinary' ? f.requestRef : f.channelRef)!.release(); await setImmediate();
    assert.equal(settled, false, 'the first failed return cannot detach its already-issued sibling CAS root');
    assert(seen.active.size > 0);
    seen.release.get(late === 'ordinary' ? f.channelRef : f.requestRef)!.release();
    await assert.rejects(pending, error => late === 'ordinary' ? error === channelError :
      error === seen.errors.get(f.requestRef) && error instanceof ResourceRetirementError && error.cause === requestError);
    seen.assertJoined();
  } finally { seen.releaseAll(); await Promise.allSettled([pending, ...seen.raw]); seen.assertJoined(); }
});

for (const retirement of [false, true]) test(`historical read cancellation joins both issued CAS branches${retirement ? ' and retains later close uncertainty' : ''}`, async t => {
  const f = await fixture(t), read = await originalReadPair(), owner = new AbortController();
  const reason = new Error('original catalog read lifetime cancelled'), closeError = new Error('actual request object close is uncertain');
  const seen = observe(t, f, new Map(), retirement ? f.requestRef : undefined, closeError);
  let settled = false;
  const pending = read(f.artifacts.withReadSignal(owner.signal), f.retainedRoot, f.source);
  void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    await seen.entered.get(f.channelRef)!.promise; await setImmediate();
    assert(seen.issued.includes(f.requestRef), 'cancellation must cover both original issued branches');
    await seen.entered.get(f.requestRef)!.promise; owner.abort(reason);
    seen.release.get(f.channelRef)!.release(); await setImmediate();
    assert.equal(settled, false); assert(seen.active.size > 0);
    seen.release.get(f.requestRef)!.release();
    await assert.rejects(pending, error => retirement ? error === seen.errors.get(f.requestRef) &&
      error instanceof ResourceRetirementError && error.cause === closeError : error === reason);
    seen.assertJoined();
  } finally { seen.releaseAll(); await Promise.allSettled([pending, ...seen.raw]); seen.assertJoined(); }
});
