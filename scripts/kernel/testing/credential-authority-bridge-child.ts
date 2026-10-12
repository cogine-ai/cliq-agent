// Fixed real native/SQLite seam; not installed credentials or platform authority.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { loadHeldStateOwnerImage, withHeldCredentialNativeScope } from '../../../src/state/native-owner.js';

async function main() {
  const image = await open(process.argv[2]!, constants.O_RDONLY | constants.O_NOFOLLOW);
  const root = await open(process.argv[3]!, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const native = await loadHeldStateOwnerImage(image);
    const input = { image, root, rootIdentity: await root.stat({ bigint: true }), stateRoot: process.argv[3]! };
    let old!: Readonly<{ assertHeld(): void }>;
    const scope = <T>(operation: (token: Readonly<{ assertHeld(): void }>) => Promise<T>) =>
      withHeldCredentialNativeScope(native, input, async held => {
        const db = new DatabaseSync('file:cliq-credential-authority?vfs=cliq-credential-vfs-v1', { allowExtension: false });
        try {
          assert.equal(db.prepare('PRAGMA locking_mode=EXCLUSIVE').get()?.locking_mode, 'exclusive');
          db.exec('PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA synchronous=FULL');
          assert.equal(db.prepare('PRAGMA journal_mode=WAL').get()?.journal_mode, 'wal');
          db.exec('BEGIN IMMEDIATE; COMMIT');
          return await operation(held);
        } finally { db.close(); }
      });
    assert.equal(await scope(async token => {
      old = token; token.assertHeld();
      assert.throws(() => token.assertHeld.call({}), /invalid/);
      return 'callback-result';
    }), 'callback-result');
    assert.throws(() => old.assertHeld(), /closed|inactive|retired/);
    const failure = new Error('exact callback failure');
    await assert.rejects(scope(async token => { token.assertHeld(); throw failure; }), error => error === failure);
    // Undefined is a legal JavaScript thrown value, not an absent failure.
    let rejected = false;
    try { await scope(async token => { token.assertHeld(); throw undefined; }); }
    catch (error) { rejected = true; assert.equal(error, undefined); }
    assert.equal(rejected, true, 'even an undefined callback rejection must survive the native bridge');
    assert.equal(await scope(async token => { token.assertHeld(); return 17; }), 17);
    assert.throws(() => old.assertHeld(), /closed|inactive|retired/);
    const holder = spawn(process.execPath, ['--no-warnings', '-e', `
      const fs=require('node:fs'); const m={exports:{}};
      process.dlopen(m,${JSON.stringify(process.argv[2])});
      const fd=fs.openSync(${JSON.stringify(process.argv[3])},fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
      const s=fs.fstatSync(fd,{bigint:true});
      const held=m.exports.acquireCredentialScope(fd,${JSON.stringify(process.argv[3])},[s.dev,s.ino,s.uid,s.gid,s.mode]);
      process.stdout.write('READY\\n');
      process.stdin.once('data',()=>{held.close();fs.closeSync(fd);process.stdin.destroy();});
    `], { stdio: ['pipe', 'pipe', 'pipe'] });
    let childError: unknown;
    holder.on('error', error => { childError = error; });
    holder.stdin.on('error', error => { childError ??= error; });
    let stderr = ''; holder.stderr.on('data', chunk => { stderr += chunk; });
    const exit = once(holder, 'exit');
    void exit.catch(() => undefined);
    const watchdog = setTimeout(() => holder.kill('SIGKILL'), 5000);
    try {
      const [ready] = await Promise.race([once(holder.stdout, 'data'), exit.then(() => {
        throw new Error('credential holder exited before READY');
      })]);
      assert.equal(ready.toString(), 'READY\n');
      await assert.rejects(scope(async () => 0), error =>
        (error as { code?: unknown } | null)?.code === 'ERR_CLIQ_CREDENTIAL_BUSY');
    } finally {
      if (holder.exitCode === null && holder.signalCode === null) holder.stdin.end('release');
      try {
        const [code, signal] = await exit;
        assert.equal(childError, undefined); assert.equal(signal, null); assert.equal(code, 0, stderr);
      } finally { clearTimeout(watchdog); }
    }
    assert.equal(await scope(async token => { token.assertHeld(); return 'healthy-retry'; }), 'healthy-retry');
    assert(root.fd >= 0); assert(image.fd >= 0);
    console.log(JSON.stringify({ diagnosticOnly: true, sameEnginePrivateScope: true, installedQualification: false }));
  } finally { await Promise.all([root.close(), image.close()]); }
}
void main().catch(error => { console.error(error); process.exitCode = 1; });
