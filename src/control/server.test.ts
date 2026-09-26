import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { once } from 'node:events';
import { chmod, lstat, mkdtemp, realpath, rename, rm } from 'node:fs/promises';
import { createConnection, type Socket } from 'node:net';
import path from 'node:path';
import { test } from 'node:test';
import { setTimeout } from 'node:timers/promises';

import { canonicalSha256 } from '../kernel/canonical.js';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import type { LocalControlChannelIdentityV1 } from '../kernel/types.js';
import { KernelStorageError } from '../state/errors.js';
import { openSqliteDriver } from '../state/sqlite-driver.js';
import { openStateStore, type StateStore } from '../state/store.js';
import { testFixture } from '../model/testing/fixtures.js';
import { signedToolBundle } from '../state/testing/tool-authority.js';
import { createWorkspaceTrustContext, writePersistedWorkspaceTrust } from '../session/trust.js';
import { CONTROL_LISTENER_ENTRY_ID } from './native-listener.js';
import { admissionKey, uuidv7 } from '../state/testing/fixtures.js';

async function privateDirectory(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(await realpath('/tmp'), prefix));
  await chmod(dir, 0o700);
  return dir;
}

async function connect(root: string): Promise<Socket> {
  const socket = createConnection(path.join(root, 'runtime', 'control-v1.sock'));
  await once(socket, 'connect');
  return socket;
}

async function call(socket: Socket, id: number, method: string, params: object): Promise<Record<string, unknown>> {
  socket.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  const [bytes] = await once(socket, 'data') as [Buffer];
  return JSON.parse(bytes.toString('utf8').trim()) as Record<string, unknown>;
}

const hello = {
  protocolVersion: 1, clientBuild: 'test-1',
  controlSchemaRange: { min: 1, max: 1 },
  headlessSchemaRange: { min: 1, max: 1 },
  requestedFeatureIds: []
};

test('StateStore UDS authenticates before replay, retains first-channel provenance, and drains on close', async () => {
  const root = await privateDirectory('.cliq-uds-store-');
  const workspace = await privateDirectory('.cliq-uds-workspace-');
  const trustHome = await privateDirectory('.cliq-uds-trust-');
  const movedWorkspace = `${workspace}-moved`;
  const previousCliqHome = process.env.CLIQ_HOME;
  process.env.CLIQ_HOME = trustHome;
  let store: StateStore | undefined;
  let first: Socket | undefined;
  let second: Socket | undefined;
  try {
    const authority = await signedToolBundle(testFixture().assembly, []);
    store = await openStateStore(root, authority);
    await store.serveLocalControl();
    first = await connect(root);
    const rejectedBeforeHello = await call(first, 1, 'session.create', {});
    assert.equal((rejectedBeforeHello.error as { message: string }).message, 'INCOMPATIBLE_PROTOCOL');
    const greeting = await call(first, 2, 'control.hello', hello);
    assert.equal((greeting.result as { protocolVersion: number }).protocolVersion, 1);

    const request = {
      protocolVersion: 1 as const, requestId: uuidv7(), method: 'session.create' as const,
      admissionKey: admissionKey('uds-replay'), workspacePath: workspace
    };
    const params = { ...request, requestDigest: canonicalSha256(request) };
    const injected = await call(first, 3, 'session.create', { ...params, principalId: 'forged' });
    assert.equal((injected.error as { message: string }).message, 'INVALID_REQUEST');
    const untrusted = await call(first, 9, 'session.create', params);
    assert.equal((untrusted.error as { message: string }).message, 'WORKSPACE_TRUST_REQUIRED');
    await writePersistedWorkspaceTrust(await createWorkspaceTrustContext(workspace, trustHome), 'trusted');
    const namedRequest = { ...request, requestId: uuidv7(), admissionKey: admissionKey('uds-name'), name: 'e\u0301' };
    const noncanonicalName = await call(first, 12, 'session.create', {
      ...namedRequest, requestDigest: canonicalSha256(namedRequest)
    });
    assert.equal((noncanonicalName.error as { message: string }).message, 'INVALID_REQUEST');
    const canonicalNameRequest = { ...namedRequest, name: 'é' };
    const canonicalName = await call(first, 13, 'session.create', {
      ...canonicalNameRequest, requestDigest: canonicalSha256(canonicalNameRequest)
    });
    assert.equal((canonicalName.result as { ok: boolean }).ok, true);
    const created = await call(first, 4, 'session.create', params);
    assert.equal((created.result as { ok: boolean }).ok, true);
    const response = created.result;
    const createdSessionId = ((response as {
      result: { snapshot: { session: { id: string } } }
    }).result.snapshot.session.id);
    const query = { protocolVersion: 1, method: 'session.get', sessionId: createdSessionId };
    const page = await call(first, 14, 'session.get', query);
    assert.equal((page.result as { ok: boolean }).ok, true);
    assert.deepEqual((page.result as { result: { items: unknown[] } }).result.items, []);
    assert.equal((page.result as { result: { highWaterItemSeq: number } }).result.highWaterItemSeq, 0);
    const queryWithAuthority = await call(first, 15, 'session.get', { ...query, principalId: 'forged' });
    assert.equal((queryWithAuthority.error as { message: string }).message, 'INVALID_REQUEST');
    const futureCursor = await call(first, 16, 'session.get', { ...query, afterItemSeq: 1 });
    assert.equal((futureCursor.result as { error: { code: string } }).error.code, 'INVALID_REQUEST');
    const unknownSession = await call(first, 17, 'session.get', {
      ...query, sessionId: 'A'.repeat(43)
    });
    assert.equal((unknownSession.result as { error: { code: string } }).error.code, 'NOT_FOUND');
    const inspector = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
    let originalChannel: string;
    try {
      const row = inspector.prepare('SELECT channel_identity_ref FROM control_requests WHERE request_id = ?')
        .get<{ channel_identity_ref: string }>(request.requestId);
      assert.ok(row);
      originalChannel = row.channel_identity_ref;
    } finally {
      inspector.close();
    }

    const oldChannel = await store.artifacts.readCanonical<LocalControlChannelIdentityV1>(originalChannel);
    await assert.rejects(
      store.createSession({
        principalId: oldChannel.principalId,
        channelIdentityRef: originalChannel,
        channelIdentityDigest: oldChannel.channelIdentityDigest,
        requestId: request.requestId,
        admissionKey: request.admissionKey,
        workspacePath: workspace
      }),
      (error) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH'
    );

    // Commit before the client consumes its reply, then replay on a new socket.
    const lostRequest = { ...request, requestId: uuidv7(), admissionKey: admissionKey('uds-lost-reply') };
    const lostParams = { ...lostRequest, requestDigest: canonicalSha256(lostRequest) };
    first.write(`${JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'session.create', params: lostParams })}\n`);
    let committed = false;
    for (let attempt = 0; attempt < 300; attempt++) {
      const reader = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
      try {
        committed = !!reader.prepare('SELECT request_id FROM control_requests WHERE request_id = ?')
          .get(lostRequest.requestId);
      } finally { reader.close(); }
      if (committed) break;
      await setTimeout(10);
    }
    assert.equal(committed, true);

    first.destroy(); first = undefined;
    second = await connect(root);
    await call(second, 5, 'control.hello', hello);
    const replay = await call(second, 6, 'session.create', params);
    assert.deepEqual(replay.result, response);
    const recovered = await call(second, 8, 'session.create', lostParams);
    assert.equal((recovered.result as { ok: boolean }).ok, true);
    await rename(workspace, movedWorkspace);
    const replayAfterPathMoved = await call(second, 10, 'session.create', params);
    assert.deepEqual(replayAfterPathMoved.result, response);
    const newRequest = { ...request, requestId: uuidv7(), admissionKey: admissionKey('uds-missing-path') };
    const newAdmission = await call(second, 11, 'session.create', {
      ...newRequest, requestDigest: canonicalSha256(newRequest)
    });
    assert.equal((newAdmission.result as { ok: boolean }).ok, false);
    const after = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
    try {
      const rows = after.prepare('SELECT channel_identity_ref FROM control_requests WHERE request_id = ?')
        .all<{ channel_identity_ref: string }>(request.requestId);
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.channel_identity_ref, originalChannel);
      const sessions = after.prepare('SELECT count(*) AS count FROM sessions').get<{ count: number }>();
      assert.equal(Number(sessions?.count), 3);
    } finally {
      after.close();
    }
    await store.close();
    await assert.rejects(lstat(path.join(root, 'runtime', 'control-v1.sock')), { code: 'ENOENT' });
  } finally {
    first?.destroy(); second?.destroy();
    await store?.close();
    await rm(root, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
    await rm(movedWorkspace, { recursive: true, force: true });
    await rm(trustHome, { recursive: true, force: true });
    if (previousCliqHome === undefined) delete process.env.CLIQ_HOME;
    else process.env.CLIQ_HOME = previousCliqHome;
  }
});

test('signed owner cannot bind local control without the exact native helper entry', async () => {
  const root = await privateDirectory('.cliq-uds-bundle-');
  const authority = await signedToolBundle(testFixture().assembly, []);
  const bundle = structuredClone(authority.bundle);
  bundle.entries = bundle.entries.filter((entry) => entry.entryId !== CONTROL_LISTENER_ENTRY_ID);
  const { signature: _oldSignature, manifestDigest: _oldDigest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  const keys = generateKeyPairSync('ed25519');
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`),
    keys.privateKey).toString('base64');
  const store = await openStateStore(root, {
    bundle,
    releaseKeys: [{ keyId: bundle.publisherKeyId,
      publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }]
  });
  try {
    await assert.rejects(store.serveLocalControl(), /native control listener differs from the signed RuntimeBundle/);
    await assert.rejects(lstat(path.join(root, 'runtime', 'control-v1.sock')), { code: 'ENOENT' });
  } finally {
    await store.close();
    await rm(root, { recursive: true, force: true });
  }
});
