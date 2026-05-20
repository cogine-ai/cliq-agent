import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import type { ApprovalSubject } from '../policy/types.js';
import { createApprovalBridge } from './approval-bridge.js';
import { createInitialState, createUiStore } from './store.js';

const subject: ApprovalSubject = {
  kind: 'tool',
  toolName: 'bash',
  access: 'exec',
  channel: { kind: 'bash', commandHead: 'ls', compound: false },
  action: { bash: 'ls' } as never,
  display: { title: 'Allow bash command?', command: 'ls' }
};

const newStore = () =>
  createUiStore(
    createInitialState({
      policy: 'confirm-bash',
      model: { provider: 'ollama', model: 'qwen3:4b' },
      session: { id: 'ses_t', cwd: '/tmp/t' }
    })
  );

test('reentrant requestApproval force-denies the prior in-flight request', async () => {
  const store = newStore();
  const bridge = createApprovalBridge(store);

  const p1 = bridge.requestApproval(subject);
  const p2 = bridge.requestApproval(subject);

  // p1 must settle as 'deny' synchronously when p2 replaces it — otherwise
  // the caller that started p1 would await forever.
  assert.equal(await p1, 'deny');

  // p2 is now the live pending.
  const pending = store.getState().pendingApproval;
  assert.ok(pending);
  assert.match(pending.id, /^pa_/);
  pending.resolve('allow');
  assert.equal(await p2, 'allow');
});

test('resolving the pending entry through the wrapped resolve clears bridge state', async () => {
  const store = newStore();
  const bridge = createApprovalBridge(store);

  const promise = bridge.requestApproval(subject);
  const pending = store.getState().pendingApproval!;
  pending.resolve('allow-turn');
  assert.equal(await promise, 'allow-turn');

  // After resolution the bridge has no pending — cancelPending becomes a no-op.
  bridge.cancelPending();
  assert.equal(store.getState().pendingApproval, pending);
  // (store only clears on approval-resolve action; the test verifies the
  // bridge does not double-dispatch when it has no pending tracked.)
});

test('cancelPending force-denies the in-flight approval and clears state', async () => {
  const store = newStore();
  const bridge = createApprovalBridge(store);

  const promise = bridge.requestApproval(subject);
  assert.notEqual(store.getState().pendingApproval, null);

  bridge.cancelPending();
  assert.equal(await promise, 'deny');
  assert.equal(store.getState().pendingApproval, null);
});

test('cancelPending is a no-op when no approval is in flight', () => {
  const store = newStore();
  const bridge = createApprovalBridge(store);

  // Should not throw, should not dispatch any action.
  let dispatches = 0;
  store.subscribe(() => {
    dispatches += 1;
  });
  bridge.cancelPending();
  assert.equal(dispatches, 0);
});
