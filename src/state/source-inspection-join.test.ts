import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { KERNEL_CAS_DIRECTORY } from '../config.js';
import type { SourceInspectionAttemptV1 } from '../kernel/execution.js';
import { admissionKey, uuidv7 } from './testing/fixtures.js';
import { createSourceInspectionFixture, sourceInspectionRequest } from './testing/source-inspection-fixtures.js';

async function fixture(t: TestContext) {
  const created = await createSourceInspectionFixture(t, 'join');
  await writeFile(path.join(created.workspace, 'source'), 'actual user source, not a fake native observation\n');
  function request(overrides: Record<string, unknown> = {}) {
    return sourceInspectionRequest({ ...created.request, requestId: uuidv7(), admissionKey: admissionKey('join-source'),
      sourceIncludes: [{ path: 'source', scope: 'entry' }], ...overrides });
  }
  return { ...created, request };
}
function errorRef(row: SourceInspectionAttemptV1): string {
  if (row.phase !== 'retired' || row.outcome.kind !== 'failed') assert.fail('the unsupported include must retire as its real failure');
  return row.outcome.errorResponseRef;
}
async function bounded<T>(operation: Promise<T>, timeout = 10_000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error('actual source task did not settle at its observed OS barrier')), timeout);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}
function pauseFailurePublication(stateRoot: string) {
  const originalOpen = fs.open;
  let reached!: () => void, release!: () => void, paused = false, matches = 0;
  const observed = new Promise<void>(resolve => { reached = resolve; }), resume = new Promise<void>(resolve => { release = resolve; });
  // Pause only a real CAS write of this recipe's known redacted response. The
  // original write executes, actual source/task/retirement results are never
  // mocked, and every opened OS handle retains its original close method.
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    if (typeof args[0] === 'string' && args[0].startsWith(path.join(stateRoot, KERNEL_CAS_DIRECTORY, '.tmp-stream-'))) {
      const actualWrite = handle.writeFile.bind(handle);
      handle.writeFile = async (...writeArgs: Parameters<typeof handle.writeFile>) => {
        await actualWrite(...writeArgs);
        if (writeArgs[0] instanceof Uint8Array && Buffer.from(writeArgs[0]).includes(Buffer.from('"messageCode":"source_capture_rejected"'))) {
          matches++;
          if (!paused) { paused = true; reached(); await resume; }
        }
      };
    }
    return handle;
  }) as typeof fs.open;
  return { observed, release, restore() { release(); fs.open = originalOpen; }, count() { return matches; } };
}

test('concurrent source follower retains the same failure response and durably binds its own request id without recapture', async t => {
  const { store, stateRoot, identity, request } = await fixture(t);
  const primaryRequest = request(), followerRequest = request({ ...primaryRequest, requestId: uuidv7() });
  const barrier = pauseFailurePublication(stateRoot);
  const primary = store.captureSubmittedSource({ request: primaryRequest, identity });
  let follower: Promise<SourceInspectionAttemptV1> | undefined;
  try {
    await bounded(barrier.observed);
    follower = store.captureSubmittedSource({ request: followerRequest, identity });
    barrier.release();
    const [first, joined] = await bounded(Promise.all([primary, follower]));
    assert.equal(errorRef(joined), errorRef(first)); assert.deepEqual(joined, first);
    // The same public seam must now reject reuse of the follower's request id
    // for other bytes. This proves its durable response association, without
    // a private SQL side channel or caller-authored retirement proof.
    await assert.rejects(store.captureSubmittedSource({ identity, request: request({ ...followerRequest,
      admissionKey: admissionKey('join-rebound'), objective: 'different request bytes' }) }), { code: 'REQUEST_ID_CONFLICT' });
    assert.equal(barrier.count(), 1, 'follower replay must not capture or republish the first error');
  } finally { barrier.restore(); await Promise.allSettled([primary, ...(follower ? [follower] : [])]); }
});

test('a source follower with a previously bound request id is rejected while the actual primary is still in flight', async t => {
  const { store, stateRoot, identity, request } = await fixture(t);
  const previousRequest = request({ admissionKey: admissionKey('join-previous') });
  errorRef(await store.captureSubmittedSource({ request: previousRequest, identity }));
  const primaryRequest = request(), conflictRequest = request({ ...primaryRequest, requestId: previousRequest.requestId });
  const barrier = pauseFailurePublication(stateRoot);
  const primary = store.captureSubmittedSource({ request: primaryRequest, identity });
  let follower: Promise<SourceInspectionAttemptV1> | undefined;
  try {
    await bounded(barrier.observed);
    follower = store.captureSubmittedSource({ request: conflictRequest, identity });
    await bounded(assert.rejects(follower, { code: 'REQUEST_ID_CONFLICT' }));
    assert.equal(barrier.count(), 1, 'request conflict cannot create a second capture/response');
    barrier.release(); errorRef(await bounded(primary));
  } finally { barrier.restore(); await Promise.allSettled([primary, ...(follower ? [follower] : [])]); }
});
