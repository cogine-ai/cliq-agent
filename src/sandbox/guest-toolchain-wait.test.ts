import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { test } from 'node:test';
import { waitForGuestToolchainReady } from './guest-toolchain-wait.js';

// Scheduling/data callbacks only; no native owner or execution proof is made.
test('pending extraction leaves CPU time for its producer instead of polling every event-loop turn', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let ready = false, polls = 0, checks = 0;
  const pending = waitForGuestToolchainReady(() => { polls++; return ready; }, () => { checks++; });
  try {
    await setImmediate(); await setImmediate();
    assert.equal(polls, 1, 'no new observation before the bounded polling interval');
    assert.equal(checks, 2, 'original current checks surround the observation');
    t.mock.timers.tick(1); await Promise.resolve();
    assert.equal(polls, 2); assert.equal(checks, 3);
    ready = true; t.mock.timers.tick(1); await pending;
    assert.equal(polls, 3); assert.equal(checks, 4);
  } finally { ready = true; t.mock.timers.runAll(); await pending; }
});

for (const boundary of ['before_poll', 'after_ready', 'during_wait'] as const)
test(`extraction observation preserves original cancellation at ${boundary}`, async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const abort = new AbortController(), reason = new Error('original extraction cancelled'); let polls = 0;
  if (boundary === 'before_poll') abort.abort(reason);
  const pending = waitForGuestToolchainReady(() => {
    polls++; if (boundary === 'after_ready') { abort.abort(reason); return true; } return false;
  }, () => abort.signal.throwIfAborted());
  const rejected = assert.rejects(pending, error => error === reason);
  if (boundary === 'during_wait') { abort.abort(reason); t.mock.timers.tick(1); }
  await rejected;
  assert.equal(polls, boundary === 'before_poll' ? 0 : boundary === 'after_ready' ? 1 : 2);
});

test('ready observation still rejects an actual current-identity failure', async () => {
  const failure = new Error('selected original object changed'); let checks = 0;
  await assert.rejects(waitForGuestToolchainReady(() => true, () => { if (++checks === 2) throw failure; }), error => error === failure);
  const pollFailure = new Error('original native extraction refused');
  await assert.rejects(waitForGuestToolchainReady(() => { throw pollFailure; }, () => {}), error => error === pollFailure);
});
