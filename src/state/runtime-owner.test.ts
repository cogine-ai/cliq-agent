import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { once } from 'node:events';
import { chmod, copyFile, mkdir, readdir, rename, rm, symlink } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { PlatformProcessIdentityV1, StateOwnerAcquisitionEvidenceV1 } from '../kernel/types.js';
import { testFixture } from '../model/testing/fixtures.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readLatestStateOwner } from './state-owner.js';
import { openStateStore, type StateStore, type StateStoreRuntimeAuthority } from './store.js';
import { makePrivateDir } from './testing/fixtures.js';
import { STATE_OWNER_NATIVE_ENTRY_ID } from './native-owner.js';
import { signedToolBundle } from './testing/tool-authority.js';

function resign(bundle: RuntimeBundleManifest): StateStoreRuntimeAuthority {
  const keys = generateKeyPairSync('ed25519');
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  return { bundle, releaseKeys: [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }] };
}
function ownerAt(stateRoot: string) {
  const reader = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  try { return readLatestStateOwner(reader)!; } finally { reader.close(); }
}

for (const mode of ['replacement', 'removed-after-open'] as const) {
test(`signed bootstrap refuses ${mode === 'replacement' ? 'a substituted executable pathname' : 'a deleted running image after warming the digest cache'} before touching state`, async () => {
  const images = await makePrivateDir('.cliq-runtime-owner-images-');
  const stateRoot = await makePrivateDir('.cliq-runtime-owner-image-state-');
  const executable = path.join(images, 'bin', 'supervisor-node');
  try {
    await mkdir(path.dirname(executable), { mode: 0o700 });
    // Preserve Node's installation-relative dynamic library search, without
    // modifying the installed runtime or the disposable executable's bytes.
    await symlink(path.resolve(process.execPath, '../../lib'), path.join(images, 'lib'), 'dir');
    await copyFile(process.execPath, executable);
    await chmod(executable, 0o500);
    const warmState = path.join(images, 'warm-state');
    await mkdir(warmState, { mode: 0o700 });
    const child = fork(new URL('./testing/supervisor-image-child.ts', import.meta.url), [stateRoot, mode, warmState], {
      execPath: executable, execArgv: ['--import', 'tsx'], stdio: ['ignore', 'ignore', 'pipe', 'ipc']
    });
    const exited = once(child, 'exit');
    let diagnostic = '';
    child.stderr!.on('data', (bytes: Buffer) => { diagnostic = (diagnostic + bytes.toString()).slice(-4096); });
    try {
      const [reply] = await Promise.race([
        once(child, 'message', { signal: AbortSignal.timeout(30_000) }),
        exited.then(([code, signal]) => { throw new Error(`image child exited before replying: ${code}/${signal}`); }),
      ])
        .catch(error => { throw new Error(`image regression child did not reply: ${diagnostic}`, { cause: error }); });
      const result = reply as { accepted: boolean; substituted: boolean; observedBeforeSubstitution: boolean; code?: string };
      assert.equal(result.observedBeforeSubstitution, true, `native image preflight failed: ${diagnostic}`);
      assert.equal(result.substituted, true, `image regression did not reach substitution: ${diagnostic}`);
      assert.equal(result.accepted, false, 'a signature of the replacement pathname must not authenticate the running image');
      assert.equal(result.code, 'ARTIFACT_MISMATCH');
      assert.deepEqual(await readdir(stateRoot), []);
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await exited;
    }
  } finally {
    await rm(images, { recursive: true, force: true });
    await rm(stateRoot, { recursive: true, force: true });
  }
});
}

test('signed state-owner bootstrap authenticates the actual process before publishing authority', async () => {
  const stateRoot = await makePrivateDir('.cliq-runtime-owner-bootstrap-');
  let store: StateStore | undefined;
  try {
    const authority = await signedToolBundle(testFixture().assembly, []);
    const altered = structuredClone(authority.bundle);
    altered.entries.find(entry => entry.role === 'supervisor')!.digest = canonicalSha256('another executable');
    await assert.rejects(openStateStore(stateRoot, resign(altered)), /does not match this process/);
    const incompatible = structuredClone(authority.bundle);
    incompatible.stateSchemaRange = { min: 99, max: 99 };
    await assert.rejects(openStateStore(stateRoot, resign(incompatible)), /state schema/);
    await assert.rejects(openStateStore(stateRoot, { ...authority, releaseKeys: [] }), /trusted release signature/);
    const unsigned = structuredClone(authority.bundle);
    unsigned.bundleVersion = 'altered after signing';
    await assert.rejects(openStateStore(stateRoot, { ...authority, bundle: unsigned }), /RuntimeBundle identity/);
    assert.deepEqual(await readdir(stateRoot), []);

    // Snapshot all trusted bootstrap input before its first asynchronous process/filesystem read.
    const expectedBundle = structuredClone(authority.bundle);
    const opening = openStateStore(stateRoot, authority);
    authority.bundle.entries[0]!.digest = canonicalSha256('mutated caller input');
    store = await opening;
    const owner = ownerAt(stateRoot);
    const supervisor = expectedBundle.entries.find(entry => entry.role === 'supervisor')!;
    assert.equal(owner.runtimeBundleRef, canonicalSha256(expectedBundle));
    assert.equal(owner.runtimeBundleManifestDigest, expectedBundle.manifestDigest);
    assert.equal(owner.supervisorEntryId, supervisor.entryId);
    assert.equal(owner.supervisorEntryVersion, supervisor.version);
    assert.equal(owner.supervisorExecutableDigest, supervisor.digest);
    const process = await store.artifacts.readCanonical<PlatformProcessIdentityV1>(owner.processIdentityRef);
    assert.equal(process.executableImageDigest, supervisor.digest);
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(owner.acquisitionEvidenceRef);
    assert.equal(acquisition.evidenceDigest, digestOmitting(acquisition, 'evidenceDigest'));
    assert.equal(acquisition.runtimeBundleRef, owner.runtimeBundleRef);
    assert.equal(acquisition.instanceNonceDigest, owner.instanceNonceDigest);
    assert.equal(acquisition.kind, 'genesis');
  } finally { await store?.close(); await rm(stateRoot, { recursive: true, force: true }); }
});

test('signed-owner reopen requires explicit trusted roots and the same runtime, with a fresh owner nonce', async () => {
  const stateRoot = await makePrivateDir('.cliq-runtime-owner-reopen-');
  let store: StateStore | undefined;
  try {
    const authority = await signedToolBundle(testFixture().assembly, []);
    store = await openStateStore(stateRoot, authority);
    const first = ownerAt(stateRoot);
    await store.close();
    const released = ownerAt(stateRoot);
    await assert.rejects(openStateStore(stateRoot), /same signed Supervisor authority/);
    await assert.rejects(openStateStore(stateRoot, { ...authority, releaseKeys: [] }), /trusted release signature/);
    const changed = structuredClone(authority.bundle);
    changed.bundleVersion = 'new unadmitted runtime';
    await assert.rejects(openStateStore(stateRoot, resign(changed)), /runtime upgrades need their own transition/);
    assert.deepEqual(ownerAt(stateRoot), released);
    const writer = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    const forged = { ...released, supervisorEntryVersion: 'foreign-entry', rowDigest: '' };
    forged.rowDigest = digestOmitting(forged, 'rowDigest');
    const trigger = writer.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'state_owners_validate_update'").get<{ sql: string }>()!.sql;
    // Deliberate corruption in this disposable database; normal writers cannot rewrite historical owners.
    const rewrite = (value: typeof released) => writer.transaction((connection) => {
      connection.exec('DROP TRIGGER state_owners_validate_update');
      connection.prepare('UPDATE state_owners SET record_json = ?, row_digest = ? WHERE owner_epoch = ?')
        .run(JSON.stringify(value), value.rowDigest, BigInt(value.ownerEpoch));
      connection.exec(trigger);
    });
    try {
      rewrite(forged);
      await assert.rejects(openStateStore(stateRoot, authority), /same signed Supervisor authority/);
    } finally { rewrite(released); writer.close(); }
    store = await openStateStore(stateRoot, authority);
    const second = ownerAt(stateRoot);
    assert.equal(second.ownerEpoch, first.ownerEpoch + 1);
    assert.equal(second.runtimeBundleRef, first.runtimeBundleRef);
    assert.equal(second.supervisorExecutableDigest, first.supervisorExecutableDigest);
    assert.notEqual(second.instanceNonceDigest, first.instanceNonceDigest);
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(second.acquisitionEvidenceRef);
    assert.equal(acquisition.kind, 'acquire_after_graceful_release');
    assert.equal(acquisition.instanceNonceDigest, second.instanceNonceDigest);
  } finally { await store?.close(); await rm(stateRoot, { recursive: true, force: true }); }
});

test('signed-owner reopen refuses a missing retained runtime before committing a successor', async () => {
  const stateRoot = await makePrivateDir('.cliq-runtime-owner-missing-');
  let store: StateStore | undefined;
  try {
    const authority = await signedToolBundle(testFixture().assembly, []);
    store = await openStateStore(stateRoot, authority);
    await store.close();
    const released = ownerAt(stateRoot);
    const retained = path.join(stateRoot, KERNEL_CAS_DIRECTORY, released.runtimeBundleRef);
    const saved = path.join(stateRoot, 'saved-runtime');
    await rename(retained, saved);
    try {
      await assert.rejects(async () => { store = await openStateStore(stateRoot, authority); }, { code: 'ENOENT' });
      assert.deepEqual(ownerAt(stateRoot), released);
    } finally { await rename(saved, retained); }
    store = await openStateStore(stateRoot, authority);
    assert.equal(ownerAt(stateRoot).ownerEpoch, released.ownerEpoch + 1);
  } finally { await store?.close(); await rm(stateRoot, { recursive: true, force: true }); }
});

test('signed bootstrap binds the native helper bytes, path, role and version before touching state', async () => {
  const stateRoot = await makePrivateDir('.cliq-runtime-owner-native-');
  try {
    const authority = await signedToolBundle(testFixture().assembly, []);
    const helperMismatch = {
      code: 'ARTIFACT_MISMATCH',
      message: 'StateOwner native helper does not match the signed RuntimeBundle'
    };
    const changes = [
      { digest: canonicalSha256('foreign native helper') }, { byteCount: 1 },
      { relativePath: 'native/foreign/state-owner.node' }, { role: 'tool_adapter' },
      { version: '2' }, { executable: false }
    ];
    for (const change of changes) {
      const bundle = structuredClone(authority.bundle);
      Object.assign(bundle.entries.find(entry => entry.entryId === STATE_OWNER_NATIVE_ENTRY_ID)!, change);
      await assert.rejects(openStateStore(stateRoot, resign(bundle)), helperMismatch);
      assert.deepEqual(await readdir(stateRoot), []);
    }
    const missing = structuredClone(authority.bundle);
    missing.entries = missing.entries.filter(entry => entry.entryId !== STATE_OWNER_NATIVE_ENTRY_ID);
    await assert.rejects(openStateStore(stateRoot, resign(missing)), helperMismatch);
    assert.deepEqual(await readdir(stateRoot), []);
    const store = await openStateStore(stateRoot, authority);
    await store.close();
  } finally { await rm(stateRoot, { recursive: true, force: true }); }
});
