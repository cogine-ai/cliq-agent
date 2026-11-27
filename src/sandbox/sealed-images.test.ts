import assert from 'node:assert/strict';
import { closeSync, fstatSync, openSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import { SealedImages } from './sealed-images.js';

// Real owned descriptors exercise resource ownership; these objects are data,
// not native image tags, launch capabilities, StateOwners or execution proof.
async function fixture(t: TestContext) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-seal-owner-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'data'); await writeFile(file, 'owned bytes', { mode: 0o400 });
  return () => { const fd = openSync(file, 'r'); return { fd, close() { closeSync(fd); } }; };
}
const closed = (fd: number) => assert.throws(() => fstatSync(fd), { code: 'EBADF' });
const fenced = (error: unknown) => error instanceof KernelStorageError && error.code === 'LEASE_FENCED';

test('image ownership is lazy, concurrent borrowers share the real resource, and close retires it once', async t => {
  const open = await fixture(t), owner = new SealedImages<ReturnType<typeof open>>();
  let calls = 0;
  const acquire = () => owner.get('signed-data', async () => { calls++; return open(); });
  assert.equal(calls, 0);
  const first = acquire(), second = acquire(); assert.equal(first, second);
  const image = await first; assert.equal(await second, image); assert.equal(calls, 1);
  assert(fstatSync(image.fd).isFile()); assert.equal(await acquire(), image);
  const close = owner.close(); assert.equal(owner.close(), close); await close; closed(image.fd);
  assert.throws(acquire, fenced); assert.equal(calls, 1);
});

test('closing joins an actual in-flight open before retiring its descriptor and refuses new construction', async t => {
  const open = await fixture(t), owner = new SealedImages<ReturnType<typeof open>>();
  let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  let image: ReturnType<typeof open> | undefined;
  const opening = owner.get('signed-data', async () => { image = open(); await gate; return image; });
  let joined = false; const close = owner.close().then(() => { joined = true; });
  await Promise.resolve(); assert.equal(joined, false); assert(fstatSync(image!.fd).isFile());
  assert.throws(() => owner.get('other', async () => open()), fenced);
  release(); await opening; await close; closed(image!.fd);
});

test('ordinary construction refusal can be retried but uncertain retirement stays owned and blocks close', async t => {
  const open = await fixture(t), owner = new SealedImages<ReturnType<typeof open>>();
  const refusal = new Error('validation refused after complete cleanup');
  await assert.rejects(owner.get('retry', async () => { throw refusal; }), error => error === refusal);
  const image = await owner.get('retry', async () => open());
  const retirement = new ResourceRetirementError('original close failed', new Error('owned fault'));
  const failed = owner.get('uncertain', async () => { throw retirement; });
  await assert.rejects(failed, error => error === retirement);
  assert.equal(owner.get('uncertain', async () => assert.fail('cannot retry uncertain ownership')), failed);
  await assert.rejects(owner.close(), error => error instanceof ResourceRetirementError &&
    error.cause instanceof AggregateError && error.cause.errors.includes(retirement));
  closed(image.fd);
});

test('a real descriptor close followed by failure does not skip other resources or lose the failure on repeated close', async t => {
  const open = await fixture(t), owner = new SealedImages<ReturnType<typeof open>>();
  const failure = new Error('failure after actual retirement');
  const first = await owner.get('first', async () => {
    const image = open(); return { fd: image.fd, close() { image.close(); throw failure; } };
  });
  const second = await owner.get('second', async () => open());
  const close = owner.close();
  await assert.rejects(close, error => error instanceof ResourceRetirementError &&
    error.cause instanceof AggregateError && error.cause.errors.includes(failure));
  assert.equal(owner.close(), close); closed(first.fd); closed(second.fd);
});
