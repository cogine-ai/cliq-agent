import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { promises as fs } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { admissionKey, makePrivateDir, uuidv7 } from './testing/fixtures.js';
import { loadNativeStateOwner, STATE_OWNER_NATIVE_PATH } from './native-owner.js';
import { ResourceRetirementError } from './errors.js';

test('source capture without trusted installation fails closed and leaves Store releasable', async t => {
  const stateRoot = await makePrivateDir('.cliq-source-uninstalled-');
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  const store = await openStateStore(stateRoot);
  t.after(() => store.close());
  const identity = await publishInProcessChannel(store);
  const core = { protocolVersion: 1, method: 'run.submit', requestId: uuidv7(),
    admissionKey: admissionKey('uninstalled-source'), sessionId: 'not-opened', expectedContextRevision: 1,
    workspacePath: '/must-not-open-untrusted-workspace', objective: 'capture',
    model: { provider: 'ollama', model: 'local' }, policyMode: 'default', verifiers: [], dependency: { mode: 'none' },
    sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: true };
  await assert.rejects(store.captureSubmittedSource({ request: { ...core, requestDigest: canonicalSha256(core) }, identity }),
    { code: 'UNSUPPORTED_PLATFORM' });
  await store.close();
});

test('a real native image read close failure remains resource uncertainty before a source row exists', async () => {
  const actualOpen = fs.open;
  const failure = Object.assign(new Error('uncertainty after actual installed image close'), { code: 'EIO' });
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args);
    if (args[0] === STATE_OWNER_NATIVE_PATH) {
      const close = handle.close.bind(handle);
      handle.close = async () => { await close(); throw failure; };
    }
    return handle;
  }) as typeof fs.open;
  syncBuiltinESMExports();
  try { await assert.rejects(loadNativeStateOwner(), error => error instanceof ResourceRetirementError && error.cause === failure); }
  finally { fs.open = actualOpen; syncBuiltinESMExports(); }
  assert.ok(await loadNativeStateOwner());
});

test('source authentication joins real parallel CAS reads before reporting failure or releasing owner', async t => {
  const stateRoot = await makePrivateDir('.cliq-source-auth-join-');
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  await promisify(execFile)(process.execPath, ['--import', 'tsx',
    fileURLToPath(new URL('./testing/source-inspection-auth-child.ts', import.meta.url)), stateRoot], { timeout: 30_000 });
  // Only the actual exited owning process makes this uncertain read releasable.
  const successor = await openStateStore(stateRoot);
  assert.equal(successor.ownerEpoch, 2);
  await successor.close();
});
