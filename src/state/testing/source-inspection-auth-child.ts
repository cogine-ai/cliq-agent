import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../config.js';
import { canonicalSha256 } from '../../kernel/canonical.js';
import type { LocalControlChannelIdentityV1 } from '../../kernel/types.js';
import { ResourceRetirementError } from '../errors.js';
import { openSqliteDriver } from '../sqlite-driver.js';
import { readActiveStateOwner } from '../state-owner.js';
import { openStateStore, publishInProcessChannel } from '../store.js';
import { admissionKey, uuidv7 } from './fixtures.js';

// Isolated real Supervisor: the injected close uncertainty must retain its
// owner until this process actually exits, not be reset by test code.
const stateRoot = process.argv[2]!;
const store = await openStateStore(stateRoot);
const identity = await publishInProcessChannel(store);
const channel = await store.artifacts.readCanonical<LocalControlChannelIdentityV1>(identity.channelIdentityRef);
assert.equal(channel.transport.kind, 'in_process');
if (channel.transport.kind !== 'in_process') throw new Error('expected real in-process channel');
const reader = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
const owner = readActiveStateOwner(reader)!;
reader.close();
assert.notEqual(owner.processIdentityRef, channel.transport.processIdentityRef);
const missingPath = path.join(stateRoot, KERNEL_CAS_DIRECTORY, owner.processIdentityRef);
const savedPath = `${missingPath}.fault-fixture`;
const delayedPath = path.join(stateRoot, KERNEL_CAS_DIRECTORY, channel.transport.processIdentityRef);
const failure = Object.assign(new Error('uncertainty after actual authenticated CAS read close'), { code: 'EIO' });
const actualOpen = fs.open;
let enter!: () => void, release!: () => void, delayedReads = 0, settled = false;
const entered = new Promise<void>(resolve => { enter = resolve; });
const held = new Promise<void>(resolve => { release = resolve; });
let reading: Promise<unknown> | undefined;
await fs.rename(missingPath, savedPath);
fs.open = (async (...args: Parameters<typeof fs.open>) => {
  const handle = await actualOpen(...args);
  // The retained closure first reads then describes this real artifact. The
  // third open is the current-process read parallel to the missing owner ref.
  if (args[0] === delayedPath && ++delayedReads === 3) {
    const close = handle.close.bind(handle);
    handle.close = async () => { await close(); enter(); await held; throw failure; };
  }
  return handle;
}) as typeof fs.open;
try {
  const core = { protocolVersion: 1, method: 'run.submit', requestId: uuidv7(), admissionKey: admissionKey('auth-join'),
    sessionId: 'must-not-open', expectedContextRevision: 1, workspacePath: '/must-not-open', objective: 'capture',
    model: { provider: 'ollama', model: 'local' }, policyMode: 'default', verifiers: [], dependency: { mode: 'none' },
    sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: true };
  reading = store.captureSubmittedSource({ request: { ...core, requestDigest: canonicalSha256(core) }, identity });
  void reading.then(() => { settled = true; }, () => { settled = true; });
  await entered;
  await setImmediate();
  assert.equal(settled, false, 'authentication cannot finish while its sibling real CAS read is unjoined');
  release();
  await assert.rejects(reading, error => error instanceof ResourceRetirementError && error.cause === failure);
  fs.open = actualOpen;
  await fs.rename(savedPath, missingPath);
  const retry = { ...core, requestId: uuidv7() };
  await assert.rejects(store.captureSubmittedSource({ request: { ...retry, requestDigest: canonicalSha256(retry) }, identity }),
    error => error instanceof ResourceRetirementError && error.cause === failure);
  await assert.rejects(store.close(), ResourceRetirementError);
} finally {
  release();
  await reading?.catch(() => {});
  fs.open = actualOpen;
  await fs.rename(savedPath, missingPath).catch(error => { if (error.code !== 'ENOENT') throw error; });
}
