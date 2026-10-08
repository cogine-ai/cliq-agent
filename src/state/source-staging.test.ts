import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import * as owner from './native-owner.js';
import { ResourceRetirementError } from './errors.js';

const inspectionId = 'i'.repeat(43), stagingNonceDigest = 'a'.repeat(64);
// SHA-256/JCS of this fixed pair, independently worked from the RFC's H rule.
const stagingId = 'MznvIAd_9VZP6q73rK-tw3RRhSTM_yeR7wCj_nvoZTI';

test('a source inspection reserves a real private root and retires that exact root before producing an absence observation', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-staging-'));
  const native = await owner.loadNativeStateOwner(), lock = native.acquireLock(root, true);
  t.after(async () => { lock.close(); await rm(root, { recursive: true, force: true }); });
  const staging = lock.createSourceInspectionStaging(inspectionId, stagingNonceDigest);
  const reserved = owner.readSourceInspectionStaging(lock, staging);
  const actual = await lstat(path.join(root, 'runtime/source-inspections', stagingId), { bigint: true });
  assert.deepEqual(reserved, { inspectionId, stagingNonceDigest, stagingIdentity: {
    deviceId: String(actual.dev), fileId: String(actual.ino), ownerUid: Number(actual.uid), mode: 448
  } });
  assert.equal(actual.mode & 0o7777n, 0o700n);
  assert.equal(actual.dev.toString(), lock.root.deviceId);
  staging.close();
  const receipt = await owner.retireSourceInspectionStaging(lock, staging);
  assert.deepEqual(owner.readSourceInspectionStagingRetirement(lock, receipt), {
    ...reserved, stagingObservation: 'exact_reserved_root_absent', directoryFsyncComplete: true
  });
  await assert.rejects(lstat(path.join(root, 'runtime/source-inspections', stagingId)), { code: 'ENOENT' });
  lock.assertHeld();
});

test('partial source staging retires descriptor-relatively without following an external symlink', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-staging-'));
  const native = await owner.loadNativeStateOwner(), lock = native.acquireLock(root, true);
  t.after(async () => { lock.close(); await rm(root, { recursive: true, force: true }); });
  const staging = lock.createSourceInspectionStaging(inspectionId, stagingNonceDigest);
  const reserved = owner.readSourceInspectionStaging(lock, staging);
  const directory = path.join(root, 'runtime/source-inspections', stagingId), outside = path.join(root, 'outside');
  await mkdir(path.join(directory, 'partial'), { mode: 0o700 });
  await writeFile(path.join(directory, 'partial', 'bytes'), 'partial capture', { mode: 0o600 });
  await writeFile(outside, 'must remain outside staging', { mode: 0o600 });
  await symlink(outside, path.join(directory, 'outside-link'));
  const receipt = await owner.retireSourceInspectionStaging(lock, staging);
  assert.deepEqual(owner.readSourceInspectionStagingRetirement(lock, receipt), {
    ...reserved, stagingObservation: 'exact_reserved_root_absent', directoryFsyncComplete: true
  });
  await assert.rejects(lstat(directory), { code: 'ENOENT' });
  assert.equal(await readFile(outside, 'utf8'), 'must remain outside staging');
  lock.assertHeld();
});

async function faultFixture(t: import('node:test').TestContext) {
  const container = await mkdtemp(path.join(process.cwd(), '.cliq-source-staging-fault-'));
  t.after(() => rm(container, { recursive: true, force: true }));
  const root = path.join(container, 'state'), binary = path.join(container, 'fault.node');
  await mkdir(root, { mode: 0o700 });
  const includes = JSON.parse(execFileSync(process.execPath, [
    fileURLToPath(new URL('../../scripts/kernel/build-state-owner-native.mjs', import.meta.url)), '--print-includes'
  ], { encoding: 'utf8' })) as string[];
  const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
    ...(process.platform === 'linux' ? ['-shared', '-fPIC'] : ['-bundle', '-undefined', 'dynamic_lookup']),
    ...includes.flatMap(include => ['-I', include]),
    fileURLToPath(new URL('./testing/quarantine-fault-native.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
  assert.equal(compiled.status, 0, compiled.stderr);
  return { root, binary };
}

test('replacement during rmdir cannot retire the still-linked original staging directory', async t => {
  const { root, binary } = await faultFixture(t);
  // The real child owns the lock. A failed physical retirement cannot be
  // "cleaned up" by resetting its sticky error or fabricating a join proof.
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { Module } from 'node:module';
    import { mkdirSync, renameSync, lstatSync, existsSync } from 'node:fs';
    import path from 'node:path';
    const [binary, root, stagingId] = process.argv.slice(1);
    const module = new Module(binary); process.dlopen(module, binary);
    const binding = module.exports, lock = binding.acquireLock(root, true);
    const staging = lock.createSourceInspectionStaging(stagingId);
    const directory = path.join(root, 'runtime/source-inspections', stagingId), saved = directory + '.saved';
    binding.setFault('before_unlink', 1, () => { renameSync(directory, saved); mkdirSync(directory, {mode: 0o700}); return 0; });
    let retired = false, errorCode;
    try { while (!staging.retireStep()) {} retired = true; } catch (error) { errorCode = error.code; }
    let releaseRefused = false;
    try { lock.close(); } catch (error) { releaseRefused = error.code === 'ERR_CLIQ_RESOURCE_RETIREMENT'; }
    let stillHeld = false;
    try { binding.acquireLock(root, false).close(); } catch { stillHeld = true; }
    console.log(JSON.stringify({retired, errorCode, releaseRefused, stillHeld, originalFileId: String(lstatSync(saved).ino),
      reservedFileId: staging.identity.fileId, locatorAbsent: !existsSync(directory)}));
    process.exit(0);
  `, binary, root, stagingId], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  const observed = JSON.parse(result.stdout.trim()) as { retired: boolean; errorCode: string; releaseRefused: boolean;
    stillHeld: boolean; originalFileId: string; reservedFileId: string; locatorAbsent: boolean };
  assert.equal(observed.originalFileId, observed.reservedFileId);
  assert.equal(observed.retired, false);
  assert.equal(observed.errorCode, 'ERR_CLIQ_RESOURCE_RETIREMENT');
  assert.equal(observed.releaseRefused, true); assert.equal(observed.stillHeld, true);
  assert.equal(observed.locatorAbsent, true);
  // Actual process death, rather than an invented successful close, releases
  // this test-only authority. No source-retirement artifact is manufactured.
  const successor = (await owner.loadNativeStateOwner()).acquireLock(root, false);
  successor.close();
});

test('an ancestor rename during rmdir cannot yield a retirement receipt for a replaced source-inspections scope', async t => {
  const { root, binary } = await faultFixture(t);
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { Module } from 'node:module';
    import { mkdirSync, renameSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
    import path from 'node:path';
    const [binary, root, stagingId] = process.argv.slice(1);
    const module = new Module(binary); process.dlopen(module, binary);
    const binding = module.exports, lock = binding.acquireLock(root, true);
    const staging = lock.createSourceInspectionStaging(stagingId);
    const parent = path.join(root, 'runtime/source-inspections'), saved = parent + '.saved';
    writeFileSync(path.join(parent, 'untouched'), 'must preserve a sibling');
    binding.setFault('before_unlink', 1, () => {
      renameSync(parent, saved); mkdirSync(parent, {mode: 0o700});
      mkdirSync(path.join(parent, stagingId), {mode: 0o700});
      writeFileSync(path.join(parent, stagingId, 'replacement'), 'must preserve a replacement'); return 0;
    });
    let retired = false, errorCode;
    try { while (!staging.retireStep()) {} retired = true; } catch (error) { errorCode = error.code; }
    let releaseRefused = false;
    try { lock.close(); } catch (error) { releaseRefused = error.code === 'ERR_CLIQ_RESOURCE_RETIREMENT'; }
    console.log(JSON.stringify({retired, errorCode, releaseRefused,
      originalAbsent: !existsSync(path.join(saved, stagingId)),
      sibling: readFileSync(path.join(saved, 'untouched'), 'utf8'),
      replacement: readFileSync(path.join(parent, stagingId, 'replacement'), 'utf8')}));
    process.exit(0);
  `, binary, root, stagingId], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), {
    retired: false, errorCode: 'ERR_CLIQ_RESOURCE_RETIREMENT', releaseRefused: true,
    originalAbsent: true, sibling: 'must preserve a sibling', replacement: 'must preserve a replacement'
  });
  const successor = (await owner.loadNativeStateOwner()).acquireLock(root, false); successor.close();
});

test('pending exact staging cleanup prevents StateOwner release until the actual operation is joined', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-staging-'));
  const native = await owner.loadNativeStateOwner(), lock = native.acquireLock(root, true);
  t.after(async () => { lock.close(); await rm(root, { recursive: true, force: true }); });
  const staging = lock.createSourceInspectionStaging(inspectionId, stagingNonceDigest);
  const pending = owner.retireSourceInspectionStaging(lock, staging);
  assert.equal(owner.retireSourceInspectionStaging(lock, staging), pending);
  assert.throws(() => lock.close(), ResourceRetirementError);
  lock.assertHeld();
  assert.throws(() => native.acquireLock(root, false), /already held/);
  const receipt = await pending;
  assert.equal(owner.readSourceInspectionStagingRetirement(lock, receipt).stagingObservation, 'exact_reserved_root_absent');
  lock.close();
  const successor = native.acquireLock(root, false); successor.close();
});

test('a stale retirement receipt only observes absence and never removes a later locator replacement', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-staging-'));
  const native = await owner.loadNativeStateOwner(), lock = native.acquireLock(root, true);
  t.after(async () => { lock.close(); await rm(root, { recursive: true, force: true }); });
  const staging = lock.createSourceInspectionStaging(inspectionId, stagingNonceDigest);
  const receipt = await owner.retireSourceInspectionStaging(lock, staging);
  const directory = path.join(root, 'runtime/source-inspections', stagingId);
  await mkdir(directory, { mode: 0o700 });
  await writeFile(path.join(directory, 'replacement'), 'must not delete a replacement', { mode: 0o600 });
  const before = await lstat(directory, { bigint: true });
  assert.throws(() => owner.readSourceInspectionStagingRetirement(lock, receipt), ResourceRetirementError);
  assert.equal(await readFile(path.join(directory, 'replacement'), 'utf8'), 'must not delete a replacement');
  assert.equal((await lstat(directory, { bigint: true })).ino, before.ino);
  lock.assertHeld();
});
