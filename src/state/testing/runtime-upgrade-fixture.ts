import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { sign } from 'node:crypto';
import { once } from 'node:events';
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { digestOmitting, encodeCanonicalTime, sha256Bytes } from '../../kernel/identity.js';
import { testFixture } from '../../model/testing/fixtures.js';
import type { RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_PATH, STATE_OWNER_NATIVE_ENTRY_ID } from '../native-owner.js';
import { schemaConversionProfile, signedKernelSchemaProfile } from '../signed-schema.js';
import { openSqliteDriver } from '../sqlite-driver.js';
import { readTimeFence } from '../canonical-time.js';
import { readLatestStateOwner } from '../state-owner.js';
import { createInstalledQualificationPublisher, qualificationPublisherMaterial } from './qualification-publisher.js';
import type { StateStoreRuntimeAuthority } from '../store.js';

async function originalSource(legacyRoot: string, sourceManifest: string, expectedManifestDigest: string) {
  assert.equal(sha256Bytes(await readFile(sourceManifest)), expectedManifestDigest);
  const manifest = JSON.parse(await readFile(sourceManifest, 'utf8')) as { inventory: Array<{ path: string; sha256: string; size: number }> };
  // Complete exact old source bytes, including schema and Store, before loading.
  for (const member of manifest.inventory) {
    const bytes = await readFile(path.join(legacyRoot, member.path));
    assert.equal(bytes.length, member.size); assert.equal(sha256Bytes(bytes), member.sha256);
  }
  return await import(pathToFileURL(path.join(legacyRoot, 'src/state/testing/tool-authority.ts')).href) as typeof import('./tool-authority.js');
}
function signed(bundle: RuntimeBundleManifest, keys: ReturnType<typeof qualificationPublisherMaterial>): RuntimeBundleManifest {
  const value = structuredClone(bundle); value.publisherKeyId = keys.releaseKeys[0]!.keyId;
  const { signature: _signature, manifestDigest: _digest, ...core } = value;
  value.manifestDigest = canonicalSha256(core);
  value.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${value.manifestDigest}`), keys.privateKey).toString('base64');
  return value;
}
async function run(mode: string, root: string, authorityFile: string, legacyRoot: string) {
  const child = fork(new URL('./runtime-upgrade-child.ts', import.meta.url), [mode, root, authorityFile, legacyRoot],
    { execArgv: ['--import', 'tsx'], stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  const messages: Array<Record<string, unknown>> = []; let stderr = '';
  child.on('message', value => messages.push(value as Record<string, unknown>));
  child.stderr!.on('data', chunk => { stderr = (stderr + chunk.toString()).slice(-8192); });
  const exit = once(child, 'exit');
  try {
    const [code, signal] = await Promise.race([exit, new Promise<never>((_, reject) => {
      const timer = setTimeout(() => reject(new Error('owned upgrade component did not join')), 15_000); timer.unref();
    })]);
    assert.equal(signal, null, stderr); return { code, messages, stderr };
  } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); await exit; }
}

export async function exerciseSignedRuntimeUpgradeSource(input: Readonly<{ sourceRoot: string; sourceManifest: string; expectedManifestDigest: string }>) {
  const legacyRoot = input.sourceRoot;
  // Generic Store/process mechanism component: no installed image, worker,
  // provider, official release or Linux upgrade qualification is asserted.
  const old = await originalSource(legacyRoot, input.sourceManifest, input.expectedManifestDigest);
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-upgrade-component-')));
  const root = path.join(fixture, 'state');
  const { mkdir } = await import('node:fs/promises'); await mkdir(root, { mode: 0o700 }); await chmod(fixture, 0o700);
  try {
    const publisher = createInstalledQualificationPublisher(), keys = qualificationPublisherMaterial(publisher);
    const legacy = await old.signedToolBundle(testFixture().assembly, []);
    const source = signed(legacy.bundle, keys);
    const sourceAuthority = { bundle: source, releaseKeys: keys.releaseKeys };
    const sourceFile = path.join(fixture, 'source-authority.json');
    await writeFile(sourceFile, canonicalJsonBytes(sourceAuthority), { mode: 0o400, flag: 'wx' });
    const initial = await run('legacy', root, sourceFile, legacyRoot); assert.equal(initial.code, 0, JSON.stringify(initial));
    assert.deepEqual(initial.messages, [{ kind: 'opened', epoch: 1 }]);
    const target = structuredClone(source), schema = signedKernelSchemaProfile(), conversion = schemaConversionProfile(source);
    const helper = await readFile(STATE_OWNER_NATIVE_PATH);
    Object.assign(target.entries.find(entry => entry.entryId === STATE_OWNER_NATIVE_ENTRY_ID)!, { digest: sha256Bytes(helper), byteCount: helper.length });
    target.bundleVersion = 'explicit-upgrade-component-v8'; target.stateSchemaRange = { min: 8, max: 8 };
    target.entries.push({ entryId: 'kernel_schema', role: 'schema', relativePath: 'schema/kernel-v8.json', version: '8', executable: false,
      digest: canonicalSha256(schema), byteCount: canonicalJsonBytes(schema).length },
    { entryId: 'schema_conversion', role: 'schema', relativePath: 'schema/convert-v7-to-v8.json', version: '7-to-8', executable: false,
      digest: canonicalSha256(conversion), byteCount: canonicalJsonBytes(conversion).length });
    const targetAuthority: StateStoreRuntimeAuthority = { bundle: signed(target, keys), releaseKeys: keys.releaseKeys };
    const targetFile = path.join(fixture, 'target-authority.json'); await writeFile(targetFile, canonicalJsonBytes(targetAuthority), { mode: 0o400, flag: 'wx' });
    // Negative retained-data input only: change no OS clock and mint no
    // successful owner, grant or death proof. Restore the exact original row
    // before the independent genuine upgrade positive below.
    const originalDatabase = openSqliteDriver(path.join(root, 'kernel.sqlite3'));
    const originalFence = readTimeFence(originalDatabase)!;
    const writeFence = (fence: typeof originalFence) => originalDatabase.prepare(`UPDATE canonical_time_fence SET
      state_owner_epoch=?,last_accepted_at=?,observed_wall_clock_at=?,state=?,updated_at=?,fence_digest=? WHERE id=1`)
      .run(fence.stateOwnerEpoch, fence.lastAcceptedAt, fence.observedWallClockAt, fence.state, fence.updatedAt, fence.fenceDigest);
    try {
      const future = encodeCanonicalTime(Date.now() + 60_000), invalid = { ...originalFence, lastAcceptedAt: future,
        observedWallClockAt: future, updatedAt: future, fenceDigest: '' };
      invalid.fenceDigest = digestOmitting(invalid, 'fenceDigest'); writeFence(invalid);
      const rejected = await run('upgrade', root, targetFile, legacyRoot);
      assert.equal(rejected.code, 2, JSON.stringify(rejected)); assert.equal(rejected.messages[0]?.code, 'RECOVERY_REQUIRED');
      const retained = readTimeFence(originalDatabase)!;
      assert.equal(retained.state, 'clock_regressed'); assert.equal(retained.lastAcceptedAt, future);
      assert.equal(originalDatabase.prepare('SELECT user_version FROM pragma_user_version').get()?.user_version, 7n);
      assert.equal(readLatestStateOwner(originalDatabase)!.ownerEpoch, 1);
      const repeated = await run('upgrade', root, targetFile, legacyRoot);
      assert.equal(repeated.code, 2); assert.equal(readTimeFence(originalDatabase)!.state, 'clock_regressed');
    } finally { writeFence(originalFence); assert.deepEqual(readTimeFence(originalDatabase), originalFence); originalDatabase.close(); }
    const refusedPublication = await run('upgrade-resource-fail', root, targetFile, legacyRoot);
    assert.equal(refusedPublication.code, 2, JSON.stringify(refusedPublication));
    assert.equal(refusedPublication.messages[0]?.message, 'owned resource index post-durability failure');
    const untouched = openSqliteDriver(path.join(root, 'kernel.sqlite3'));
    try {
      assert.equal(untouched.prepare('SELECT user_version FROM pragma_user_version').get()?.user_version, 7n);
      assert.equal(readLatestStateOwner(untouched)!.ownerEpoch, 1);
      assert.deepEqual(readTimeFence(untouched), originalFence);
    } finally { untouched.close(); }
    const upgraded = await run('upgrade', root, targetFile, legacyRoot); assert.equal(upgraded.code, 0, JSON.stringify(upgraded));
    assert.equal(upgraded.messages[0]?.kind, 'upgraded');
    const receipt = upgraded.messages[0]!.receipt;
    const repeated = await run('upgrade', root, targetFile, legacyRoot); assert.equal(repeated.code, 0, JSON.stringify(repeated));
    assert.deepEqual(repeated.messages[0]!.receipt, receipt);
    const reopened = await run('current', root, targetFile, legacyRoot); assert.equal(reopened.code, 0, JSON.stringify(reopened));
    assert.deepEqual(reopened.messages, [{ kind: 'opened', epoch: 3 }]);
    const database = path.join(root, 'kernel.sqlite3');
    const before = await readFile(database), refused = await run('legacy-refuse', root, sourceFile, legacyRoot);
    assert.equal(refused.code, 2); assert.equal(refused.messages[0]?.kind, 'refused');
    assert.match(String(refused.messages[0]?.message), /unsupported kernel schema version 8/);
    assert((await readFile(database)).equals(before), 'old7 must not mutate the committed8 database');
    const driver = openSqliteDriver(database);
    try { assert.equal(readLatestStateOwner(driver)!.ownerEpoch, 3); } finally { driver.close(); }
  } finally { await rm(fixture, { recursive: true, force: true }); }
}
