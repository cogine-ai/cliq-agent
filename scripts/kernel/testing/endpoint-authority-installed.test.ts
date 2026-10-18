import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, readFile, readdir, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { isSea } from 'node:sea';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../../src/config.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { stateRootIdentityFromDescriptor } from '../../../src/state/native-owner.js';
import { createInstalledRuntime, loadInstalledCredentialPlatform, loadInstalledManagerObserver } from '../../../src/state/installed-runtime.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';

// The actual signed production entry, not a qualification-only producer entry
// or a structural token factory. Linux positive evidence comes from the runner.
if (process.platform === 'linux') test('signed installed endpoint read works without a keeper or StateOwner and does not write Run CAS', { timeout: 180000 }, async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-endpoint-installed-')));
  try {
    const signed = await buildInstalledSupervisorPackage(fixture);
    const stateRoot = path.join(fixture, 'state');
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot: signed.packageRoot, stateRoot });
    const casBefore = await readdir(path.join(stateRoot, KERNEL_CAS_DIRECTORY));
    const casDigests = async () => Promise.all((await readdir(path.join(stateRoot, KERNEL_CAS_DIRECTORY))).sort().map(async ref =>
      [ref, sha256Bytes(await readFile(path.join(stateRoot, KERNEL_CAS_DIRECTORY, ref)))]));
    const bytesBefore = await casDigests();
    // This is the actual signed addon, built against the fixed SEA carrier's
    // headers, dlopened by the ordinary Node client (not a fake native facade).
    // It proves the restricted capability boundary, not systemd availability
    // or the authenticated Supervisor/peer/hello chain qualified separately.
    assert.equal(isSea(), false);
    const selected = await runtime.openSelected(stateRoot);
    let observer: Awaited<ReturnType<typeof loadInstalledManagerObserver>> | undefined;
    try {
      observer = await loadInstalledManagerObserver(selected);
      assert(Object.isFrozen(observer));
      assert.deepEqual(Reflect.ownKeys(observer).sort(), ['currentUser', 'inspect']);
      assert.equal('secretService' in observer, false); assert.equal('userManager' in observer, false);
      const user = observer.currentUser();
      assert(Object.isFrozen(user)); assert.equal(user.uid, process.geteuid!()); assert.equal(user.gid, process.getegid!());
      assert(user.uid > 0);
      for (const copy of [{ ...observer }, Object.create(observer)]) {
        assert.throws(() => copy.currentUser(), TypeError);
        await assert.rejects(copy.inspect('cliq-not-this-selection.service'), TypeError);
      }
      const originalRead = observer.currentUser;
      assert.throws(() => originalRead(), TypeError);
      assert.throws(() => (originalRead as (...args: unknown[]) => unknown).call(observer, true), TypeError);
      let accessed = false;
      const getter = Object.defineProperty({}, 'kind', { get() { accessed = true; throw new Error('untrusted getter'); } });
      for (const input of [undefined, '', 'cliq-not-this-selection.service', 'start', 'reload',
        { kind: 'inspect', unit: 'cliq-not-this-selection.service' }, { kind: 'start', unit: 'cliq-not-this-selection.service' }, getter])
        await assert.rejects(observer.inspect(input as string), TypeError);
      assert.equal(accessed, false);
      const root = await lstat(stateRoot, { bigint: true });
      const identity = stateRootIdentityFromDescriptor(stateRoot, {
        deviceId: root.dev.toString(), fileId: root.ino.toString(), ownerUid: Number(root.uid),
      });
      const unit = `cliq-${identity.identityDigest}-supervisor.service`;
      await assert.rejects((observer.inspect as (...args: unknown[]) => Promise<unknown>).call(observer, unit, true), TypeError);
      await assert.rejects(loadInstalledCredentialPlatform(selected), { code: 'UNSUPPORTED_PLATFORM' });
      assert.throws(() => loadInstalledManagerObserver({ ...selected }), { code: 'ARTIFACT_MISMATCH' });
      assert.deepEqual(await casDigests(), bytesBefore);
    } finally { await selected.close(); }
    assert(observer);
    assert.throws(() => observer.currentUser(), { code: 'ARTIFACT_MISMATCH' });
    await assert.rejects(observer.inspect('cliq-not-this-selection.service'), { code: 'ARTIFACT_MISMATCH' });
    // The ordinary manager observer must not acquire credential authority.
    // The following real endpoint read does acquire its separate native scope,
    // which legitimately creates the private credential directory and lock.
    await assert.rejects(lstat(path.join(stateRoot, 'credentials')), { code: 'ENOENT' });
    const response = spawnSync(path.join(stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], {
      input: JSON.stringify({ schemaVersion: 1, kind: 'read', endpointRegistrationId: 'missing-endpoint' }),
      encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 65536,
      env: { PATH: process.env.PATH }, cwd: fixture,
    });
    assert.equal(response.error, undefined); assert.equal(response.signal, null);
    assert.equal(response.status, 0, response.stderr);
    assert.deepEqual(JSON.parse(response.stdout), { schemaVersion: 1, record: null });
    assert.deepEqual(await readdir(path.join(stateRoot, KERNEL_CAS_DIRECTORY)), casBefore);
    assert.deepEqual(await casDigests(), bytesBefore);
    const credentials = await lstat(path.join(stateRoot, 'credentials'));
    assert(credentials.isDirectory() && !credentials.isSymbolicLink());
    assert.equal(credentials.uid, process.geteuid!()); assert.equal(credentials.mode & 0o7777, 0o700);
    for (const relative of [KERNEL_DATABASE_FILENAME, 'runtime/state-owner.lock', 'runtime/keeper.ready', 'runtime/control-v1.sock'])
      await assert.rejects(lstat(path.join(stateRoot, relative)), { code: 'ENOENT' });
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux') test('signed endpoint entry rejects malformed ids before creating credential authority files', { timeout: 180000 }, async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-endpoint-invalid-')));
  try {
    const signed = await buildInstalledSupervisorPackage(fixture);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    for (const [index, endpointRegistrationId] of ['', 'e\u0301', 'canary\u0000private', '\ud800'].entries()) {
      const stateRoot = path.join(fixture, `state-${index}`);
      await runtime.installInitial({ packageRoot: signed.packageRoot, stateRoot });
      const response = spawnSync(path.join(stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], {
        input: JSON.stringify({ schemaVersion: 1, kind: 'read', endpointRegistrationId }),
        encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 65536,
        env: { PATH: process.env.PATH }, cwd: fixture,
      });
      assert.equal(response.error, undefined); assert.equal(response.signal, null);
      assert.equal(response.status, 1, response.stderr);
      assert.equal(response.stdout, '');
      assert.equal(JSON.parse(response.stderr).code, 'INVALID_REQUEST');
      assert.equal(response.stderr.includes('canary'), false);
      await assert.rejects(lstat(path.join(stateRoot, 'credentials')), { code: 'ENOENT' });
    }
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
