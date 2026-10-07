import assert from 'node:assert/strict';
import { test, type TestContext } from 'node:test';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { LocalControlChannelIdentityV1, LocalPrincipalIdentityV1, LocalSocketPeerObservationV1 } from '../kernel/types.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { decodeLocalSocketPeerObservation } from './decoders.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { admissionKey, makePrivateDir, uuidv7 } from './testing/fixtures.js';

/** Audit fixture only. No native socket capture or live authority is asserted. */
async function fixture(t: TestContext) {
  const stateRoot = await makePrivateDir('.cliq-peer-history-');
  const store = await openStateStore(stateRoot);
  const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  t.after(async () => { driver.close(); await store.close(); await rm(stateRoot, { recursive: true, force: true }); });
  const current = await publishInProcessChannel(store);
  const channel = await store.artifacts.readCanonical<LocalControlChannelIdentityV1>(current.channelIdentityRef);
  assert.equal(channel.transport.kind, 'in_process');
  if (channel.transport.kind !== 'in_process') throw new Error('fixture must be in process');
  const peer: LocalSocketPeerObservationV1 = {
    schemaVersion: 1, format: 'cliq-local-socket-peer-observation-v1',
    platform: process.platform === 'linux' ? 'linux' : 'macos',
    stateRootIdentityRef: store.stateRootIdentity.ref, stateRootIdentityDigest: store.stateRootIdentity.digest,
    listener: { canonicalRootRelativePath: 'runtime/control-v1.sock', fileType: 'unix_stream_socket',
      deviceId: '11', fileId: '22', ownerUid: process.geteuid!(), mode: 384 },
    acceptedSocket: { socketType: 'SOCK_STREAM', deviceId: '33', fileId: '44' },
    credentialApi: process.platform === 'linux' ? 'linux_so_peercred' : 'macos_getpeereid_local_peerpid',
    peerUid: process.geteuid!(), peerGid: process.getegid!(), peerPid: process.pid,
    peerProcessIdentityRef: channel.transport.processIdentityRef,
    peerProcessIdentityDigest: channel.transport.processIdentityDigest,
    observedAt: channel.openedAt, observationDigest: ''
  };
  peer.observationDigest = digestOmitting(peer, 'observationDigest');
  async function publish(value = peer, openedAt = channel.openedAt) {
    const retained = await store.artifacts.publishCanonical(value, value.format);
    const uds: LocalControlChannelIdentityV1 = { ...channel, openedAt,
      transport: { kind: 'uds_peer', peerObservationRef: retained.ref, peerObservationDigest: value.observationDigest } };
    uds.channelIdentityDigest = digestOmitting(uds, 'channelIdentityDigest');
    const published = await store.artifacts.publishCanonical(uds, uds.format);
    return { principalId: current.principalId, channelIdentityRef: published.ref, channelIdentityDigest: uds.channelIdentityDigest };
  }
  return { store, driver, stateRoot, peer, current, channel, publish };
}

test('retained UDS provenance decodes its complete closure without becoming live request authority', async (t) => {
  const f = await fixture(t);
  const uds = await f.publish();
  const closure = await readHistoricalControlChannel(f.driver, f.store.artifacts, uds);
  assert.equal(closure.channel.transport.kind, 'uds_peer');
  assert.equal(closure.metadata.length, 4);
  const workspace = await makePrivateDir('.cliq-peer-workspace-');
  t.after(() => rm(workspace, { recursive: true, force: true }));
  await assert.rejects(f.store.createSession({ ...uds, requestId: uuidv7(), admissionKey: admissionKey('forged-uds'),
    workspacePath: workspace }), { code: 'ARTIFACT_MISMATCH' });
  assert.equal(f.driver.prepare('SELECT count(*) AS count FROM sessions').get<{ count: bigint }>()!.count, 0n);
  assert.equal(f.driver.prepare('SELECT count(*) AS count FROM control_requests').get<{ count: bigint }>()!.count, 0n);
});

test('retained UDS audit does not require its historical peer process to remain alive', async (t) => {
  const f = await fixture(t);
  const identity = await f.store.artifacts.readCanonical<Record<string, unknown>>(f.peer.peerProcessIdentityRef);
  identity.pid = 2147483647;
  identity.identityDigest = digestOmitting(identity, 'identityDigest');
  const processArtifact = await f.store.artifacts.publishCanonical(identity, 'cliq-platform-process-identity-v1');
  const peer = { ...f.peer, peerPid: identity.pid as number, peerProcessIdentityRef: processArtifact.ref,
    peerProcessIdentityDigest: identity.identityDigest as string };
  peer.observationDigest = digestOmitting(peer, 'observationDigest');
  await readHistoricalControlChannel(f.driver, f.store.artifacts, await f.publish(peer));
});

test('peer observation rejects malformed closed fields even when its digest is recomputed', async (t) => {
  const f = await fixture(t);
  const changes = [
    { extra: true }, { platform: 'windows' }, { peerPid: 0 }, { peerUid: -1 }, { peerGid: 1.5 },
    { credentialApi: f.peer.platform === 'linux' ? 'macos_getpeereid_local_peerpid' : 'linux_so_peercred' },
    { listener: { ...f.peer.listener, extra: true } }, { listener: { ...f.peer.listener, canonicalRootRelativePath: 'other.sock' } },
    { listener: { ...f.peer.listener, ownerUid: f.peer.peerUid + 1 } }, { listener: { ...f.peer.listener, mode: 438 } },
    { listener: { ...f.peer.listener, deviceId: '-1' } }, { listener: { ...f.peer.listener, fileId: '022' } },
    { acceptedSocket: { ...f.peer.acceptedSocket, socketType: 'SOCK_DGRAM' } },
    { acceptedSocket: { ...f.peer.acceptedSocket, fileId: 44 } }, { acceptedSocket: { ...f.peer.acceptedSocket, extra: true } },
    { peerProcessIdentityRef: 'sha256:' + f.peer.peerProcessIdentityRef }, { peerProcessIdentityDigest: 'A'.repeat(64) },
    { observedAt: '2026-10-06T00:00:00Z' }
  ];
  for (const change of changes) {
    const peer = { ...f.peer, ...change };
    peer.observationDigest = digestOmitting(peer, 'observationDigest');
    assert.throws(() => decodeLocalSocketPeerObservation(peer), { code: 'ARTIFACT_MISMATCH' });
  }
  for (const field of Object.keys(f.peer)) {
    const peer = { ...f.peer } as Record<string, unknown>;
    delete peer[field];
    if (field !== 'observationDigest') peer.observationDigest = digestOmitting(peer, 'observationDigest');
    assert.throws(() => decodeLocalSocketPeerObservation(peer), { code: 'ARTIFACT_MISMATCH' });
  }
});

test('retained UDS closure rejects validly hashed substitution of root, process, time and peer identity', async (t) => {
  const f = await fixture(t);
  for (const change of [{ stateRootIdentityRef: canonicalSha256('foreign-root') },
    { stateRootIdentityDigest: canonicalSha256('foreign-root-digest') }, { peerPid: f.peer.peerPid + 1 },
    { peerProcessIdentityDigest: canonicalSha256('foreign-process') },
    { observedAt: new Date(Date.parse(f.peer.observedAt) + 1).toISOString() }]) {
    const peer = { ...f.peer, ...change };
    peer.observationDigest = digestOmitting(peer, 'observationDigest');
    await assert.rejects(readHistoricalControlChannel(f.driver, f.store.artifacts, await f.publish(peer)),
      { code: 'ARTIFACT_MISMATCH' });
  }
  const earlier = new Date(Date.parse(f.peer.observedAt) - 1).toISOString();
  await assert.rejects(readHistoricalControlChannel(f.driver, f.store.artifacts, await f.publish(f.peer, earlier)),
    { code: 'ARTIFACT_MISMATCH' });
  const uds = await f.publish();
  await assert.rejects(readHistoricalControlChannel(f.driver, f.store.artifacts,
    { ...uds, channelIdentityDigest: canonicalSha256('different-channel') }), { code: 'ARTIFACT_MISMATCH' });
});

test('a completely rehashed foreign-platform peer closure cannot contradict its retained StateRoot', async (t) => {
  const f = await fixture(t);
  const principal = await f.store.artifacts.readCanonical<LocalPrincipalIdentityV1>(f.channel.principalIdentityRef);
  const platform = principal.platform === 'linux' ? 'macos' : 'linux';
  principal.platform = platform;
  principal.principalId = identityHash('cliq-local-principal-v1', principal.stateRootIdentityDigest, platform, principal.effectiveUid);
  principal.identityDigest = digestOmitting(principal, 'identityDigest');
  const principalArtifact = await f.store.artifacts.publishCanonical(principal, principal.format);
  const processIdentity = await f.store.artifacts.readCanonical<Record<string, unknown>>(f.peer.peerProcessIdentityRef);
  processIdentity.platform = platform;
  processIdentity.identityDigest = digestOmitting(processIdentity, 'identityDigest');
  const processArtifact = await f.store.artifacts.publishCanonical(processIdentity, 'cliq-platform-process-identity-v1');
  const peer: LocalSocketPeerObservationV1 = { ...f.peer, platform,
    credentialApi: platform === 'linux' ? 'linux_so_peercred' : 'macos_getpeereid_local_peerpid',
    peerProcessIdentityRef: processArtifact.ref, peerProcessIdentityDigest: processIdentity.identityDigest as string };
  peer.observationDigest = digestOmitting(peer, 'observationDigest');
  const peerArtifact = await f.store.artifacts.publishCanonical(peer, peer.format);
  const channel: LocalControlChannelIdentityV1 = { ...f.channel, principalId: principal.principalId,
    principalIdentityRef: principalArtifact.ref, principalIdentityDigest: principal.identityDigest,
    transport: { kind: 'uds_peer', peerObservationRef: peerArtifact.ref, peerObservationDigest: peer.observationDigest } };
  channel.channelIdentityDigest = digestOmitting(channel, 'channelIdentityDigest');
  const channelArtifact = await f.store.artifacts.publishCanonical(channel, channel.format);
  await assert.rejects(readHistoricalControlChannel(f.driver, f.store.artifacts, {
    principalId: principal.principalId, channelIdentityRef: channelArtifact.ref, channelIdentityDigest: channel.channelIdentityDigest
  }), { code: 'ARTIFACT_MISMATCH' });
});
