// Qualification-only signed-image/installed-producer seam. No platform secret,
// endpoint authorization, broker release, StateOwner or default CLI activation.
import assert from 'node:assert/strict';
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { isSea } from 'node:sea';
import { KERNEL_DATABASE_FILENAME } from '../../config.js';
import { KernelStorageError } from '../errors.js';
import { createInstalledRuntime, withCredentialAuthorityLock, type HeldCredentialAuthorityLock } from '../installed-runtime.js';
import { writeInstalledControlPackage } from './installed-control-fixture.js';

async function main() {
  assert(isSea()); assert.equal(process.versions.node, '24.21.0'); assert.equal(process.platform, 'linux');
  const fixture = process.argv[2]!;
  const source = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  const signed = await writeInstalledControlPackage(source);
  const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
  await runtime.installInitial({ packageRoot: source, stateRoot });
  const selected = await runtime.openSelected(stateRoot);
  let release = () => {};
  let entered = () => {};
  const enteredScope = new Promise<void>(resolve => { entered = resolve; });
  const holdScope = new Promise<void>(resolve => { release = resolve; });
  try {
    let old!: HeldCredentialAuthorityLock;
    const first = withCredentialAuthorityLock(selected, async token => {
      old = token; token.assertHeld();
      assert.deepEqual(Object.keys(token), ['assertHeld']);
      assert.throws(() => withCredentialAuthorityLock(selected, async () => 0), /acquiring|active|draining/);
      assert.throws(() => ({ ...token }).assertHeld(), /receiver/);
      return 'first';
    });
    // This observes the real pre-enqueue reservation, not just the active body.
    assert.throws(() => withCredentialAuthorityLock(selected, async () => 0), /acquiring|active|draining/);
    assert.equal(await first, 'first');
    assert.throws(() => old.assertHeld(), error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    const failure = new Error('callback failed');
    await assert.rejects(withCredentialAuthorityLock(selected, async token => { token.assertHeld(); throw failure; }),
      error => error === failure);
    assert.equal(await withCredentialAuthorityLock(selected, async token => { token.assertHeld(); return 17; }), 17);
    const secondRuntime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const second = await secondRuntime.openSelected(stateRoot);
    try {
      const pending = withCredentialAuthorityLock(selected, async token => {
        token.assertHeld();
        assert.throws(() => withCredentialAuthorityLock(second, async () => 0), /acquiring|active|draining/);
        entered(); await holdScope; token.assertHeld(); return 'drained';
      });
      void pending.catch(() => undefined);
      await Promise.race([enteredScope, pending]);
      const closing = selected.close();
      let closed = false;
      void closing.then(() => { closed = true; }, () => { closed = true; });
      await Promise.resolve(); assert.equal(closed, false);
      release(); assert.equal(await pending, 'drained'); await closing;
      assert.equal(await withCredentialAuthorityLock(second, async token => { token.assertHeld(); return 'next'; }), 'next');
    } finally { release(); await second.close(); }
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, 'runtime/state-owner.lock')), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, 'runtime/keeper.ready')), { code: 'ENOENT' });
    console.log(JSON.stringify({ diagnosticOnly: true, signedImageInstalledProducerScope: true,
      stateOwnerAcquired: false, platformCredentialsQualified: false, installedI1Qualified: false }));
  } finally { release(); await selected.close(); }
}
void main().catch(error => { console.error(error); process.exitCode = 1; });
