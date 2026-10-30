// Real private files and OS flock only. No StateOwner, Run, native execution,
// credential, death evidence or installed qualification is constructed here.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { chmod, link, lstat, mkdtemp, open, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadNativeStateOwner, tryLockClientDataDirectory, type HeldClientDataLock, type NativeStateOwner } from './native-owner.js';

test('private client flock owns its duplicate directory, refuses contention and releases without unlinking', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-client-lock-'))); await chmod(root, 0o700);
  const native = await loadNativeStateOwner(), directory = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let held: HeldClientDataLock | null = null;
  try {
    held = tryLockClientDataDirectory(native, directory.fd); assert(held); held.assertHeld();
    assert.equal(tryLockClientDataDirectory(native, directory.fd), null);
    assert.throws(() => held!.assertHeld.call({} as HeldClientDataLock));
    assert.throws(() => Reflect.apply(held!.close, held, [1]));
    const before = await lstat(path.join(root, 'client-mutation.lock'), { bigint: true });
    assert.equal(before.mode & 0o7777n, 0o600n); assert.equal(before.nlink, 1n); assert.equal(before.size, 0n);
    await directory.close(); held.assertHeld(); // The native owner retained its own CLOEXEC duplicate.
    const second = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      assert.equal(tryLockClientDataDirectory(native, second.fd), null);
      held.close(); held.close(); assert.throws(() => held!.assertHeld()); held = null;
      const next = tryLockClientDataDirectory(native, second.fd); assert(next); next.assertHeld(); next.close();
    } finally { await second.close(); }
    const after = await lstat(path.join(root, 'client-mutation.lock'), { bigint: true });
    assert.equal(after.ino, before.ino); assert.equal(after.dev, before.dev);
    assert.deepEqual(await readdir(root), ['client-mutation.lock']);
  } finally { held?.close(); if (directory.fd >= 0) await directory.close(); await rm(root, { recursive: true, force: true }); }
});

test('private client flock rejects unsafe fixed files and detects replacement while held', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-client-lock-reject-'))); await chmod(root, 0o700);
  const native = await loadNativeStateOwner(), directory = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const filename = path.join(root, 'client-mutation.lock'); let held: HeldClientDataLock | null = null;
  try {
    for (const kind of ['symlink', 'linked', 'nonempty', 'mode'] as const) {
      const other = path.join(root, 'other');
      if (kind === 'symlink') { await writeFile(other, '', { mode: 0o600 }); await symlink(other, filename); }
      else {
        await writeFile(filename, kind === 'nonempty' ? 'x' : '', { mode: 0o600 });
        if (kind === 'linked') await link(filename, other);
        if (kind === 'mode') await chmod(filename, 0o644);
      }
      await assert.rejects(async () => tryLockClientDataDirectory(native, directory.fd), { code: 'ARTIFACT_MISMATCH' });
      await rm(filename); await rm(other, { force: true });
    }
    await chmod(root, 0o755);
    assert.throws(() => tryLockClientDataDirectory(native, directory.fd), { code: 'ARTIFACT_MISMATCH' }); await chmod(root, 0o700);
    held = tryLockClientDataDirectory(native, directory.fd); assert(held);
    await rename(filename, path.join(root, 'original')); await writeFile(filename, '', { mode: 0o600 });
    assert.throws(() => held!.assertHeld(), { code: 'ARTIFACT_MISMATCH' }); held.close(); held = null;
    assert.throws(() => tryLockClientDataDirectory({} as NativeStateOwner, directory.fd), { code: 'ARTIFACT_MISMATCH' });
  } finally { held?.close(); await directory.close(); await rm(root, { recursive: true, force: true }); }
});

test('another real process holds the private client flock until its actual OS exit', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-client-lock-process-'))); await chmod(root, 0o700);
  const native = await loadNativeStateOwner(), directory = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
    import { open, constants } from 'node:fs/promises';
    const { loadNativeStateOwner, tryLockClientDataDirectory } = await import(process.argv[2]);
    const directory = await open(process.argv[1], constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const held = tryLockClientDataDirectory(await loadNativeStateOwner(), directory.fd);
    if (!held) throw Error('fixture did not own its lock'); held.assertHeld();
    process.stdout.write('held\\n'); setInterval(() => held.assertHeld(), 1000);
  `, root, new URL('./native-owner.ts', import.meta.url).href], { stdio: ['ignore', 'pipe', 'pipe'] });
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  let output = '', error = '', held: HeldClientDataLock | null = null;
  const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
  try {
    await new Promise<void>((resolve, reject) => {
      child.once('error', reject);
      child.once('close', () => { if (output !== 'held\n') reject(new Error('fixture lock owner exited before readiness')); });
      child.stdout.on('data', bytes => { output += bytes.toString(); if (output === 'held\n') resolve(); else if (output.length > 64) reject(new Error('fixture output bound')); });
      child.stderr.on('data', bytes => { error += bytes.toString(); if (error.length > 4096) child.kill('SIGKILL'); });
    });
    assert.equal(error, ''); assert.equal(tryLockClientDataDirectory(native, directory.fd), null);
    child.kill('SIGKILL'); assert.deepEqual(await closed, { code: null, signal: 'SIGKILL' });
    held = tryLockClientDataDirectory(native, directory.fd); assert(held); held.assertHeld();
  } finally {
    clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await closed; held?.close(); await directory.close(); await rm(root, { recursive: true, force: true });
  }
});
