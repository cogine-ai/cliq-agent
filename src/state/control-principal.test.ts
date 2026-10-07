import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { test } from 'node:test';

import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { LocalControlChannelIdentityV1, LocalPrincipalIdentityV1 } from '../kernel/types.js';
import { decodeLocalPrincipalIdentity } from './decoders.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { admissionKey, digest, makePrivateDir, uuidv7 } from './testing/fixtures.js';

test('in-process clients share the StateRoot-derived principal but receive distinct connection identities', async () => {
  const stateRoot = await makePrivateDir('.cliq-control-principal-clients-');
  const store = await openStateStore(stateRoot);
  try {
    const channelRefs = new Set<string>();
    const nonceDigests = new Set<string>();
    const principalRefs = new Set<string>();
    const platform = process.platform === 'linux' ? 'linux' : 'macos';
    const expected = identityHash('cliq-local-principal-v1', store.stateRootIdentity.digest, platform, process.geteuid!());
    for (const client of ['cli', 'tui', 'jsonl', 'rpc'] as const) {
      const published = await publishInProcessChannel(store, client);
      assert.equal(published.principalId, expected);
      const channel = await store.artifacts.readCanonical<LocalControlChannelIdentityV1>(published.channelIdentityRef);
      const principal = decodeLocalPrincipalIdentity(await store.artifacts.readCanonical(channel.principalIdentityRef));
      assert.equal(channel.client, client);
      assert.equal(channel.principalId, expected);
      assert.equal(principal.principalId, expected);
      assert.equal(principal.stateRootIdentityRef, store.stateRootIdentity.ref);
      assert.equal(principal.effectiveUid, process.geteuid!());
      assert.equal(published.channelIdentityDigest, channel.channelIdentityDigest);
      channelRefs.add(published.channelIdentityRef);
      nonceDigests.add(channel.channelNonceDigest);
      principalRefs.add(channel.principalIdentityRef);
    }
    assert.equal(channelRefs.size, 4);
    assert.equal(nonceDigests.size, 4);
    assert.equal(principalRefs.size, 1);
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('a reconnected client retains its principal and replays the original Session admission after owner reopen', async () => {
  const stateRoot = await makePrivateDir('.cliq-control-principal-reopen-');
  const workspace = await makePrivateDir('.cliq-control-principal-ws-');
  let store = await openStateStore(stateRoot);
  try {
    const first = await publishInProcessChannel(store);
    const request = { requestId: uuidv7(), admissionKey: admissionKey('principal-reopen'), workspacePath: workspace };
    const created = await store.createSession({ ...request, ...first });
    const reconnected = await publishInProcessChannel(store, 'tui');
    assert.equal(reconnected.principalId, first.principalId);
    assert.notEqual(reconnected.channelIdentityRef, first.channelIdentityRef);
    const replay = await store.createSession({ ...request, ...reconnected });
    assert.equal(replay.replayed, true);
    assert.deepEqual(replay.session, created.session);

    await store.close();
    store = await openStateStore(stateRoot);
    const reopened = await publishInProcessChannel(store, 'rpc');
    assert.equal(reopened.principalId, first.principalId);
    assert.notEqual(reopened.channelIdentityRef, first.channelIdentityRef);
    const afterRestart = await store.createSession({ ...request, ...reopened });
    assert.equal(afterRestart.replayed, true);
    assert.deepEqual(afterRestart.session, created.session);
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('rehashing principal and channel artifacts cannot choose a principal or alter its derivation inputs', async () => {
  const stateRoot = await makePrivateDir('.cliq-control-principal-forgery-');
  const workspace = await makePrivateDir('.cliq-control-principal-forgery-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const published = await publishInProcessChannel(store);
    const channel = await store.artifacts.readCanonical<LocalControlChannelIdentityV1>(published.channelIdentityRef);
    const principal = await store.artifacts.readCanonical<LocalPrincipalIdentityV1>(channel.principalIdentityRef);
    const mutations: Array<Partial<LocalPrincipalIdentityV1>> = [
      { principalId: 'caller-selected-principal' },
      { stateRootIdentityDigest: digest('different-StateRoot') },
      { platform: principal.platform === 'linux' ? 'macos' : 'linux' },
      { effectiveUid: principal.effectiveUid + 1 }
    ];
    for (const [index, mutation] of mutations.entries()) {
      const forged = { ...principal, ...mutation };
      forged.identityDigest = digestOmitting(forged, 'identityDigest');
      assert.throws(() => decodeLocalPrincipalIdentity(forged), { code: 'ARTIFACT_MISMATCH' });
      const principalArtifact = await store.artifacts.publishCanonical(forged, forged.format);
      const forgedChannel = { ...channel, principalId: forged.principalId,
        principalIdentityRef: principalArtifact.ref, principalIdentityDigest: forged.identityDigest };
      forgedChannel.channelIdentityDigest = digestOmitting(forgedChannel, 'channelIdentityDigest');
      const channelArtifact = await store.artifacts.publishCanonical(forgedChannel, forgedChannel.format);
      await assert.rejects(store.createSession({
        principalId: forged.principalId,
        requestId: uuidv7(),
        admissionKey: admissionKey(`principal-forgery-${index}`),
        workspacePath: workspace,
        channelIdentityRef: channelArtifact.ref,
        channelIdentityDigest: forgedChannel.channelIdentityDigest
      }), { code: 'ARTIFACT_MISMATCH' });
    }
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});
