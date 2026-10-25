// Real CAS and inert retained identity data only. This reader cannot create a
// StateOwner, Run, live channel or native proof, and these tests do not do so.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { LocalControlChannelIdentityV1, LocalPrincipalIdentityV1, LocalSocketPeerObservationV1,
  PlatformProcessIdentityV1, StateRootIdentityV1 } from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readRetainedControlChannelClosure } from './control-channel.js';
import { ResourceRetirementError } from './errors.js';

function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}
const turn = () => new Promise<void>(resolve => setImmediate(resolve));

async function fixture(t: TestContext, transport: 'in_process' | 'uds_peer') {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-retained-channel-read-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const cas = new ContentAddressedStore(root), artifacts = new ArtifactCatalog(cas);
  const ownerUid = process.getuid!(), observedAt = '2026-10-25T00:00:00.000Z';
  const stateRoot: StateRootIdentityV1 = { schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
    canonicalAbsolutePath: '/inert-retained-data-only', ownerUid, deviceId: '1', directoryFileId: '2', mode: 448,
    openedNoFollow: true, layoutVersion: 1, identityDigest: '' };
  stateRoot.identityDigest = digestOmitting(stateRoot, 'identityDigest');
  const stateRootRef = (await artifacts.publishCanonical(stateRoot, stateRoot.format)).ref;
  const principal: LocalPrincipalIdentityV1 = { schemaVersion: 1, format: 'cliq-local-principal-identity-v1',
    stateRootIdentityRef: stateRootRef, stateRootIdentityDigest: stateRoot.identityDigest, platform: 'linux', effectiveUid: ownerUid,
    principalId: identityHash('cliq-local-principal-v1', stateRoot.identityDigest, 'linux', ownerUid), identityDigest: '' };
  principal.identityDigest = digestOmitting(principal, 'identityDigest');
  const principalRef = (await artifacts.publishCanonical(principal, principal.format)).ref;
  const processIdentity: PlatformProcessIdentityV1 = { schemaVersion: 1, format: 'cliq-platform-process-identity-v1',
    platform: 'linux', pid: 123, processStartToken: 'inert-retained-record-not-a-process-observation', ownerUid,
    executableImageDigest: canonicalSha256('inert executable label; never executed'), observedAt, identityDigest: '' };
  processIdentity.identityDigest = digestOmitting(processIdentity, 'identityDigest');
  const processRef = (await artifacts.publishCanonical(processIdentity, processIdentity.format)).ref;
  const peer: LocalSocketPeerObservationV1 = { schemaVersion: 1, format: 'cliq-local-socket-peer-observation-v1', platform: 'linux',
    stateRootIdentityRef: stateRootRef, stateRootIdentityDigest: stateRoot.identityDigest,
    listener: { canonicalRootRelativePath: 'runtime/control-v1.sock', fileType: 'unix_stream_socket', deviceId: '1', fileId: '3', ownerUid, mode: 384 },
    acceptedSocket: { socketType: 'SOCK_STREAM', deviceId: '1', fileId: '4' }, credentialApi: 'linux_so_peercred',
    peerUid: ownerUid, peerGid: ownerUid, peerPid: processIdentity.pid, peerProcessIdentityRef: processRef,
    peerProcessIdentityDigest: processIdentity.identityDigest, observedAt, observationDigest: '' };
  peer.observationDigest = digestOmitting(peer, 'observationDigest');
  const peerRef = (await artifacts.publishCanonical(peer, peer.format)).ref;
  const channel: LocalControlChannelIdentityV1 = { schemaVersion: 1, format: 'cliq-local-control-channel-identity-v1',
    principalIdentityRef: principalRef, principalIdentityDigest: principal.identityDigest, principalId: principal.principalId,
    client: 'cli', transport: transport === 'in_process'
      ? { kind: 'in_process', processIdentityRef: processRef, processIdentityDigest: processIdentity.identityDigest }
      : { kind: 'uds_peer', peerObservationRef: peerRef, peerObservationDigest: peer.observationDigest },
    openedAt: observedAt, channelNonceDigest: canonicalSha256('inert channel label'), channelIdentityDigest: '' };
  channel.channelIdentityDigest = digestOmitting(channel, 'channelIdentityDigest');
  const channelRef = (await artifacts.publishCanonical(channel, channel.format)).ref;
  const owner = { stateRootIdentityRef: stateRootRef, stateRootIdentityDigest: stateRoot.identityDigest,
    filesystem: { root: { ownerUid } } };
  const input = { channelIdentityRef: channelRef, channelIdentityDigest: channel.channelIdentityDigest, principalId: principal.principalId };
  return { root, cas, artifacts, owner, input, channel, channelRef, principalRef, stateRootRef, processRef, peerRef };
}

function observeReads(t: TestContext, f: Awaited<ReturnType<typeof fixture>>) {
  const read = f.cas.read.bind(f.cas), open = fs.open.bind(fs), reads: string[] = [], counts = new Map<string, number>();
  const active = new Set<object>(), failures = new Map<string, Error>();
  const holds = new Map<string, { entered: ReturnType<typeof gate>; release: ReturnType<typeof gate>; failure?: Error }>();
  let opened = 0, closed = 0;
  t.mock.method(f.cas, 'read', (...args: Parameters<typeof f.cas.read>) => { reads.push(args[0]); return read(...args); });
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await open(...args); active.add(handle); opened++;
    const ref = path.dirname(String(args[0])) === f.root ? path.basename(String(args[0])) : '';
    const ordinal = (counts.get(ref) ?? 0) + 1; counts.set(ref, ordinal);
    const close = handle.close.bind(handle), actualRead = handle.read.bind(handle), key = `${ref}:${ordinal}`;
    t.mock.method(handle, 'read', async (...values: Parameters<typeof handle.read>) => {
      const result = await actualRead(...values), failure = failures.get(key);
      if (failure) throw failure;
      return result;
    });
    t.mock.method(handle, 'close', async () => {
      await close(); assert(active.delete(handle)); closed++;
      const hold = holds.get(key);
      if (hold) { hold.entered.release(); await hold.release.promise; if (hold.failure) throw hold.failure; }
    });
    return handle;
  });
  return { reads, active,
    hold(ref: string, ordinal = 1, failure?: Error) {
      const value = { entered: gate(), release: gate(), failure }; holds.set(`${ref}:${ordinal}`, value); return value;
    },
    fail(ref: string, ordinal: number, error: Error) { failures.set(`${ref}:${ordinal}`, error); },
    release() { for (const value of holds.values()) value.release.release(); },
    assertJoined() { assert.equal(active.size, 0); assert.equal(opened, closed); }
  };
}

test('retained principal and root reads overlap while every original CAS handle still joins', async t => {
  const f = await fixture(t, 'in_process'), observed = observeReads(t, f), principal = observed.hold(f.principalRef);
  const pending = readRetainedControlChannelClosure(f.artifacts, f.owner, f.input);
  try {
    await principal.entered.promise; await turn();
    t.diagnostic(JSON.stringify({ readsWhilePrincipalClosePending: observed.reads.length,
      rootReadIssued: observed.reads.includes(f.stateRootRef) }));
    assert(observed.reads.includes(f.stateRootRef), 'the independent retained root read cannot wait for principal close');
    principal.release.release();
    const result = await pending;
    assert.deepEqual(result.channel, f.channel);
    assert.deepEqual(result.metadata.map(value => value.ref), [f.channelRef, f.principalRef, f.processRef]);
    assert.deepEqual(result.metadata.map(value => value.schemaKind), ['cliq-local-control-channel-identity-v1',
      'cliq-local-principal-identity-v1', 'cliq-platform-process-identity-v1']);
    assert.deepEqual([...new Set(observed.reads)].map(ref => [ref, observed.reads.filter(value => value === ref).length]),
      [[f.channelRef, 2], [f.principalRef, 2], [f.stateRootRef, 1], [f.processRef, 2]]);
    observed.assertJoined();
  } finally { observed.release(); await Promise.allSettled([pending]); observed.assertJoined(); }
});

test('retained transport overlaps the original metadata group without crossing the peer-to-process dependency', async t => {
  const f = await fixture(t, 'uds_peer'), observed = observeReads(t, f);
  const metadata = observed.hold(f.channelRef, 2), peer = observed.hold(f.peerRef), process = observed.hold(f.processRef);
  const pending = readRetainedControlChannelClosure(f.artifacts, f.owner, f.input);
  let settled = false; void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    await metadata.entered.promise; await turn();
    t.diagnostic(JSON.stringify({ transportIssuedWhileMetadataClosePending: observed.reads.includes(f.peerRef) }));
    assert(observed.reads.includes(f.peerRef), 'the independent transport closure cannot wait for metadata close');
    await peer.entered.promise;
    assert(!observed.reads.includes(f.processRef), 'the process ref is obtained only from the fully read and decoded peer');
    peer.release.release(); await process.entered.promise; process.release.release(); await turn();
    assert.equal(settled, false, 'transport completion cannot detach either issued metadata read');
    metadata.release.release();
    const result = await pending;
    assert.deepEqual(result.channel, f.channel);
    assert.deepEqual(result.metadata.map(value => value.ref), [f.channelRef, f.principalRef, f.peerRef, f.processRef]);
    assert.deepEqual(result.metadata.map(value => value.schemaKind), ['cliq-local-control-channel-identity-v1',
      'cliq-local-principal-identity-v1', 'cliq-local-socket-peer-observation-v1', 'cliq-platform-process-identity-v1']);
    observed.assertJoined();
  } finally { observed.release(); await Promise.allSettled([pending]); observed.assertJoined(); }
});

test('the two retained UDS metadata reads overlap and return their original order after reversed completion', async t => {
  const f = await fixture(t, 'uds_peer'), observed = observeReads(t, f);
  const peer = observed.hold(f.peerRef, 2), process = observed.hold(f.processRef, 2);
  const pending = readRetainedControlChannelClosure(f.artifacts, f.owner, f.input);
  let settled = false; void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    await peer.entered.promise; await turn();
    const processReads = observed.reads.filter(ref => ref === f.processRef).length;
    t.diagnostic(JSON.stringify({ processReadsWhilePeerMetadataClosePending: processReads }));
    assert.equal(processReads, 2, 'the second original UDS metadata read cannot wait for the first close');
    await process.entered.promise; process.release.release(); await turn();
    assert.equal(settled, false, 'a faster second describe cannot detach the first descriptor');
    peer.release.release();
    const result = await pending;
    assert.deepEqual(result.metadata.map(value => value.ref), [f.channelRef, f.principalRef, f.peerRef, f.processRef]);
    assert.deepEqual([...new Set(observed.reads)].map(ref => [ref, observed.reads.filter(value => value === ref).length]),
      [[f.channelRef, 2], [f.principalRef, 2], [f.stateRootRef, 1], [f.peerRef, 2], [f.processRef, 2]]);
    assert(result.metadata.every(value => value.mediaType === 'application/json' && value.byteLength > 0));
    observed.assertJoined();
  } finally { observed.release(); await Promise.allSettled([pending]); observed.assertJoined(); }
});

test('retained principal/root refusal precedes every transport or metadata read', async t => {
  const f = await fixture(t, 'uds_peer'), observed = observeReads(t, f);
  await assert.rejects(readRetainedControlChannelClosure(f.artifacts,
    { ...f.owner, stateRootIdentityDigest: canonicalSha256('different retained root') }, f.input), /principal identity is not current/u);
  assert.deepEqual(observed.reads, [f.channelRef, f.principalRef, f.stateRootRef]); observed.assertJoined();
  observed.reads.length = 0;
  await assert.rejects(readRetainedControlChannelClosure(f.artifacts, f.owner,
    { ...f.input, principalId: 'different retained principal' }), /identity does not match the caller/u);
  assert.deepEqual(observed.reads, [f.channelRef]); observed.assertJoined();
});

test('ordinary metadata failures retain their original group order after reversed completion and join transport', async t => {
  const f = await fixture(t, 'in_process'), observed = observeReads(t, f);
  const first = new Error('original channel metadata read failure'), second = new Error('original principal metadata read failure');
  observed.fail(f.channelRef, 2, first); observed.fail(f.principalRef, 2, second);
  const channel = observed.hold(f.channelRef, 2), principal = observed.hold(f.principalRef, 2), process = observed.hold(f.processRef);
  const pending = readRetainedControlChannelClosure(f.artifacts, f.owner, f.input);
  let settled = false; void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    await Promise.all([channel.entered.promise, principal.entered.promise, process.entered.promise]);
    principal.release.release(); process.release.release(); await turn();
    assert.equal(settled, false); channel.release.release();
    await assert.rejects(pending, error => error === first);
    assert.equal(observed.reads.filter(ref => ref === f.processRef).length, 1, 'failed transport group cannot enter later metadata');
    observed.assertJoined();
  } finally { observed.release(); await Promise.allSettled([pending]); observed.assertJoined(); }
});

for (const phase of ['principal', 'transport', 'metadata'] as const) {
  test(`retained ${phase} group joins a later real CAS close failure and preserves retirement over an ordinary failure`, async t => {
    const f = await fixture(t, 'uds_peer'), observed = observeReads(t, f);
    const ordinary = new Error('original file read failure'), closeFailure = new Error('original actual close return failed');
    const failed: [string, number] = phase === 'principal' ? [f.principalRef, 1]
      : phase === 'transport' ? [f.channelRef, 2] : [f.peerRef, 2];
    const late: [string, number] = phase === 'principal' ? [f.stateRootRef, 1]
      : phase === 'transport' ? [f.peerRef, 1] : [f.processRef, 2];
    observed.fail(...failed, ordinary);
    const first = observed.hold(...failed), last = observed.hold(...late, closeFailure);
    const pending = readRetainedControlChannelClosure(f.artifacts, f.owner, f.input);
    let settled = false; void pending.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.all([first.entered.promise, last.entered.promise]); first.release.release(); await turn();
      assert.equal(settled, false, 'the group retains its original sibling until the actual close return joins');
      assert(observed.active.size > 0, 'the late file close still owns its original CAS root descriptor');
      last.release.release();
      await assert.rejects(pending, error => error instanceof ResourceRetirementError && error.cause === closeFailure);
      if (phase === 'principal') assert.equal(observed.reads.length, 3);
      if (phase === 'transport') assert(!observed.reads.includes(f.processRef), 'a failed peer never supplies a process ref');
      observed.assertJoined();
    } finally { observed.release(); await Promise.allSettled([pending]); observed.assertJoined(); }
  });

  test(`retained ${phase} cancellation joins all issued real CAS reads and starts no later group`, async t => {
    const f = await fixture(t, 'uds_peer'), observed = observeReads(t, f), abort = new AbortController();
    const reason = new Error('original retained read cancelled'), selected: Array<[string, number]> = phase === 'principal'
      ? [[f.principalRef, 1], [f.stateRootRef, 1]] : phase === 'transport'
        ? [[f.channelRef, 2], [f.principalRef, 2], [f.peerRef, 1]] : [[f.peerRef, 2], [f.processRef, 2]];
    const holds = selected.map(([ref, ordinal]) => observed.hold(ref, ordinal));
    const pending = readRetainedControlChannelClosure(f.artifacts.withReadSignal(abort.signal), f.owner, f.input);
    let settled = false; void pending.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.all(holds.map(value => value.entered.promise)); const issued = observed.reads.length;
      abort.abort(reason); holds[0]!.release.release(); await turn();
      assert.equal(settled, false); assert.equal(observed.reads.length, issued);
      for (const hold of holds) hold.release.release();
      await assert.rejects(pending, error => error === reason);
      assert.equal(observed.reads.length, phase === 'principal' ? 3 : phase === 'transport' ? 6 : 9);
      observed.assertJoined();
    } finally { observed.release(); await Promise.allSettled([pending]); observed.assertJoined(); }
  });
}

test('a pre-cancelled retained view performs no CAS read', async t => {
  const f = await fixture(t, 'in_process'), observed = observeReads(t, f), abort = new AbortController();
  const reason = new Error('retained view was already cancelled'); abort.abort(reason);
  await assert.rejects(readRetainedControlChannelClosure(f.artifacts.withReadSignal(abort.signal), f.owner, f.input), error => error === reason);
  assert.deepEqual(observed.reads, []); observed.assertJoined();
});

test('retained transport cancellation cannot hide a later original actual CAS close failure', async t => {
  const f = await fixture(t, 'uds_peer'), observed = observeReads(t, f), abort = new AbortController();
  const reason = new Error('original retained cancellation'), closeFailure = new Error('original actual close return failed after cancellation');
  const channel = observed.hold(f.channelRef, 2), principal = observed.hold(f.principalRef, 2), peer = observed.hold(f.peerRef, 1, closeFailure);
  const pending = readRetainedControlChannelClosure(f.artifacts.withReadSignal(abort.signal), f.owner, f.input);
  let settled = false; void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    await Promise.all([channel.entered.promise, principal.entered.promise, peer.entered.promise]);
    abort.abort(reason); channel.release.release(); principal.release.release(); await turn();
    assert.equal(settled, false); assert(observed.active.size > 0);
    peer.release.release();
    await assert.rejects(pending, error => error instanceof ResourceRetirementError && error.cause === closeFailure);
    assert.equal(observed.reads.length, 6); observed.assertJoined();
  } finally { observed.release(); await Promise.allSettled([pending]); observed.assertJoined(); }
});
