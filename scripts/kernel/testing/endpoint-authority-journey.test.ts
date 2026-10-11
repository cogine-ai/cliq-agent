import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdtemp, readdir, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeEndpointAuthorityOperation, decodeEndpointAuthorityRecord, type EndpointAuthorityCommandCoreV1,
  type EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { digestOmitting, identityHash } from '../../../src/kernel/identity.js';
import { createInstalledRuntime } from '../../../src/state/installed-runtime.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';

type EndpointRequest =
  | { schemaVersion: 1; kind: 'read'; endpointRegistrationId: string }
  | { schemaVersion: 1; kind: 'commit'; requestId: string; commandCore: EndpointAuthorityCommandCoreV1 };

async function snapshotCas(stateRoot: string) {
  const directory = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
  const root = await lstat(directory, { bigint: true });
  assert(root.isDirectory());
  const entries = [];
  for (const name of (await readdir(directory)).sort()) {
    const filename = path.join(directory, name);
    const before = await lstat(filename, { bigint: true });
    assert(before.isFile(), `Run CAS object ${name} must be a regular file`);
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(filename)) hash.update(chunk);
    const after = await lstat(filename, { bigint: true });
    assert.deepEqual([after.dev, after.ino, after.size, after.mtimeNs, after.ctimeNs],
      [before.dev, before.ino, before.size, before.mtimeNs, before.ctimeNs], 'CAS snapshot must observe one stable object');
    entries.push({ name, dev: before.dev, ino: before.ino, size: before.size, digest: hash.digest('hex') });
  }
  return { dev: root.dev, ino: root.ino, entries };
}

function registerCore(registration: EndpointRegistrationV1): EndpointAuthorityCommandCoreV1 {
  const core = { schemaVersion: 1, kind: 'register', ownerPrincipalId: registration.ownerPrincipalId,
    registration, expectedRegistrationArtifactRef: canonicalSha256(registration), commandDigest: '' } as const;
  return { ...core, commandDigest: digestOmitting(core, 'commandDigest') };
}

// One journey through the signed production entry. Ordinary endpoint metadata
// is not credential enrollment, network access or complete installed I1.
if (process.platform === 'linux') test('installed endpoint registration survives fresh-channel replay and remains revoked after historical replay',
  { timeout: 300000 }, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-endpoint-journey-')));
    try {
      const signed = await buildInstalledSupervisorPackage(fixture);
      const stateRoot = path.join(fixture, 'state');
      const installed = await createInstalledRuntime({ releaseKeys: signed.releaseKeys })
        .installInitial({ packageRoot: signed.packageRoot, stateRoot });
      const casBefore = await snapshotCas(stateRoot);
      const root = await lstat(stateRoot, { bigint: true });
      assert(root.isDirectory()); assert.equal(root.mode & 0o7777n, 0o700n);
      assert.equal(root.uid, BigInt(process.geteuid!()));
      // RFC local-principal identity, derived from the actual installed root.
      // This constructs request bytes, never an authenticated token/channel.
      const rootIdentityDigest = canonicalSha256({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
        canonicalAbsolutePath: stateRoot, ownerUid: Number(root.uid), deviceId: root.dev.toString(),
        directoryFileId: root.ino.toString(), mode: 448, openedNoFollow: true, layoutVersion: 1 });
      const ownerPrincipalId = identityHash('cliq-local-principal-v1', rootIdentityDigest, 'linux', process.geteuid!());
      const trust = signed.bundle.entries.find(entry => entry.entryId === 'default_https_trust_store');
      assert(trust); assert.equal(trust.role, 'trust_store'); assert.equal(trust.executable, false);
      const registration: EndpointRegistrationV1 = {
        schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: 'installed-journey-endpoint',
        registrationKind: 'user', ownerPrincipalId, purposes: ['model_endpoint'],
        target: { scheme: 'https', hostAscii: 'endpoint.invalid', port: 443, basePath: '/v1', redirectPolicy: 'reject_all' },
        tls: { serverNameAscii: 'endpoint.invalid', minimumVersion: 'TLSv1.3', trustStoreRuntimeBundleRef: installed.bundleDigest,
          trustStoreRuntimeBundleManifestDigest: signed.bundle.manifestDigest, trustStoreEntryId: 'default_https_trust_store',
          trustStoreRef: trust.digest, trustStoreDigest: trust.digest, spkiSha256Pins: ['4'.repeat(64)] },
        endpointIdentityDigest: '', tlsPolicyDigest: '', createdAt: '2026-10-11T00:00:00.000Z', registrationDigest: '',
      };
      registration.tlsPolicyDigest = canonicalSha256(registration.tls);
      registration.endpointIdentityDigest = canonicalSha256({ target: registration.target, tlsPolicyDigest: registration.tlsPolicyDigest });
      registration.registrationDigest = digestOmitting(registration, 'registrationDigest');
      const registerRequest = { schemaVersion: 1, kind: 'commit', requestId: '019a0011-0000-7000-8000-000000000011',
        commandCore: registerCore(registration) } as const;
      const readRequest = { schemaVersion: 1, kind: 'read', endpointRegistrationId: registration.endpointRegistrationId } as const;
      const invoke = (request: EndpointRequest) => spawnSync(path.join(stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], {
        input: canonicalJsonBytes(request), encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 65536,
        env: { PATH: process.env.PATH }, cwd: fixture,
      });
      const success = (request: EndpointRequest, field: 'operation' | 'record') => {
        const response = invoke(request);
        assert.equal(response.error, undefined); assert.equal(response.signal, null);
        assert.equal(response.status, 0, response.stderr);
        const value = JSON.parse(response.stdout) as Record<string, unknown>;
        assert.deepEqual(Object.keys(value).sort(), [field, 'schemaVersion']); assert.equal(value.schemaVersion, 1);
        assert.equal(response.stdout, `${canonicalJsonBytes(value).toString('utf8')}\n`);
        return { value: value[field], bytes: response.stdout };
      };
      const refusal = (request: EndpointRequest, code: 'REQUEST_ID_CONFLICT' | 'STATE_TRANSITION_INVALID') => {
        const response = invoke(request);
        assert.equal(response.error, undefined); assert.equal(response.signal, null);
        assert.equal(response.status, 1); assert.equal(response.stdout, '');
        const diagnostics = response.stderr.trim().split('\n').filter(line => line.startsWith('{'))
          .map(line => JSON.parse(line) as { code?: string });
        assert.equal(diagnostics.length, 1); assert.equal(diagnostics[0]!.code, code);
      };

      assert.equal(success(readRequest, 'record').value, null);
      const registeredResponse = success(registerRequest, 'operation');
      const registered = decodeEndpointAuthorityOperation(registeredResponse.value);
      assert.equal(registered.disposition, 'registered'); assert.equal(registered.committedAuthorityRevision, 1);
      assert.deepEqual(registered.commandCore, registerRequest.commandCore);
      const active = decodeEndpointAuthorityRecord(success(readRequest, 'record').value);
      assert.equal(active.state, 'active'); assert.equal(active.authorityRevision, 1);
      assert.deepEqual(active.registration, registration);
      assert.equal(active.sourceRequestId, registerRequest.requestId);
      assert.equal(active.sourceRequestDigest, registerRequest.commandCore.commandDigest);
      assert.equal(active.expectedRegistrationArtifactRef, canonicalSha256(registration));
      assert.equal(active.recordDigest, registered.resultRecordDigest);
      // Every invoke is a fresh verified process and freshly authenticated
      // channel. Exact bytes include the first operation's retained provenance.
      assert.equal(success(registerRequest, 'operation').bytes, registeredResponse.bytes);
      const alreadyRegistered = decodeEndpointAuthorityOperation(success({ ...registerRequest,
        requestId: '019a0011-0000-7000-8000-000000000013' }, 'operation').value);
      assert.equal(alreadyRegistered.disposition, 'already_registered');
      assert.equal(alreadyRegistered.committedAuthorityRevision, 1);
      assert.equal(alreadyRegistered.resultRecordDigest, active.recordDigest);
      assert.deepEqual(alreadyRegistered.commandCore, registerRequest.commandCore);
      assert.notEqual(alreadyRegistered.channelIdentityRef, registered.channelIdentityRef);
      assert.notEqual(alreadyRegistered.channelIdentityDigest, registered.channelIdentityDigest);
      assert.deepEqual(decodeEndpointAuthorityRecord(success(readRequest, 'record').value), active,
        'a different identical registration request must not append another record revision');

      const changed = { ...registration, createdAt: '2026-10-11T00:00:00.001Z', registrationDigest: '' };
      changed.registrationDigest = digestOmitting(changed, 'registrationDigest');
      refusal({ ...registerRequest, commandCore: registerCore(changed) }, 'REQUEST_ID_CONFLICT');
      assert.deepEqual(decodeEndpointAuthorityRecord(success(readRequest, 'record').value), active);

      const revokeCore = { schemaVersion: 1, kind: 'revoke', ownerPrincipalId,
        endpointRegistrationId: registration.endpointRegistrationId, expectedAuthorityRevision: 1, commandDigest: '' } as const;
      const revokeRequest = { schemaVersion: 1, kind: 'commit', requestId: '019a0011-0000-7000-8000-000000000012',
        commandCore: { ...revokeCore, commandDigest: digestOmitting(revokeCore, 'commandDigest') } } as const;
      const revokedResponse = success(revokeRequest, 'operation');
      const revokedOperation = decodeEndpointAuthorityOperation(revokedResponse.value);
      assert.equal(revokedOperation.disposition, 'revoked'); assert.equal(revokedOperation.committedAuthorityRevision, 2);
      assert.deepEqual(revokedOperation.commandCore, revokeRequest.commandCore);
      const revoked = decodeEndpointAuthorityRecord(success(readRequest, 'record').value);
      assert.equal(revoked.state, 'revoked'); assert.equal(revoked.authorityRevision, 2);
      assert.deepEqual(revoked.registration, registration);
      assert.equal(revoked.sourceRequestId, active.sourceRequestId);
      assert.equal(revoked.sourceRequestDigest, active.sourceRequestDigest);
      assert.equal(revoked.revokedByRequestId, revokeRequest.requestId);
      assert.equal(revoked.revokedByRequestDigest, revokeRequest.commandCore.commandDigest);
      assert.equal(revoked.recordDigest, revokedOperation.resultRecordDigest);
      assert.equal(success(revokeRequest, 'operation').bytes, revokedResponse.bytes);
      const alreadyRevoked = decodeEndpointAuthorityOperation(success({ ...revokeRequest,
        requestId: '019a0011-0000-7000-8000-000000000014' }, 'operation').value);
      assert.equal(alreadyRevoked.disposition, 'already_revoked');
      assert.equal(alreadyRevoked.committedAuthorityRevision, 2);
      assert.equal(alreadyRevoked.resultRecordDigest, revoked.recordDigest);
      assert.deepEqual(alreadyRevoked.commandCore, revokeRequest.commandCore);
      assert.notEqual(alreadyRevoked.channelIdentityRef, revokedOperation.channelIdentityRef);
      assert.deepEqual(decodeEndpointAuthorityRecord(success(readRequest, 'record').value), revoked,
        'a later revoke with the old active revision must not append revision 3');
      assert.equal(success(registerRequest, 'operation').bytes, registeredResponse.bytes,
        'historical registration replay must retain revision 1 and the original authenticated channel');
      assert.deepEqual(decodeEndpointAuthorityRecord(success(readRequest, 'record').value), revoked,
        'historical replay must not reactivate or append another endpoint revision');
      refusal({ ...registerRequest, requestId: '019a0011-0000-7000-8000-000000000015' }, 'STATE_TRANSITION_INVALID');
      assert.deepEqual(decodeEndpointAuthorityRecord(success(readRequest, 'record').value), revoked,
        'a new registration request cannot reactivate the terminal endpoint');

      assert.deepEqual(await snapshotCas(stateRoot), casBefore, 'ordinary endpoint metadata must not write or replace Run CAS');
      for (const relative of [KERNEL_DATABASE_FILENAME, 'runtime/state-owner.lock', 'runtime/keeper.ready', 'runtime/control-v1.sock'])
        await assert.rejects(lstat(path.join(stateRoot, relative)), { code: 'ENOENT' });
    } finally { await rm(fixture, { recursive: true, force: true }); }
  });
