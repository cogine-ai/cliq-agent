import test from 'node:test';
import assert from 'node:assert/strict';

import type { RuntimeEvent } from '../runtime/events.js';
import { emptyHeadlessArtifacts } from './contract.js';
import { createHeadlessEventFactory, mergeArtifacts, runtimeEventToHeadless } from './events.js';

test('createHeadlessEventFactory emits versioned envelopes with optional session fields', () => {
  const factory = createHeadlessEventFactory({
    runId: 'run_test',
    now: () => '2026-05-03T00:00:00.000Z'
  });

  const preSession = factory('error', {
    code: 'invalid-input',
    stage: 'input',
    message: 'prompt is required',
    recoverable: false
  });

  assert.equal(preSession.schemaVersion, 1);
  assert.equal(preSession.runId, 'run_test');
  assert.equal(preSession.sessionId, undefined);
  assert.equal(preSession.turn, undefined);
  assert.equal(preSession.type, 'error');
  assert.equal(preSession.timestamp, '2026-05-03T00:00:00.000Z');

  const scoped = factory(
    'run-start',
    {
      cwd: '/workspace',
      policy: 'auto',
      model: { provider: 'ollama', model: 'qwen3:4b', baseUrl: 'http://localhost:11434' }
    },
    { sessionId: 'sess_test', turn: 3 }
  );

  assert.equal(scoped.sessionId, 'sess_test');
  assert.equal(scoped.turn, 3);
  assert.notEqual(scoped.eventId, preSession.eventId);
});

test('runtimeEventToHeadless maps existing runtime events without raw deltas', () => {
  const runtimeEvent: RuntimeEvent = { type: 'model-progress', chunks: 2, chars: 50 };
  const mapped = runtimeEventToHeadless(runtimeEvent);

  assert.deepEqual(mapped, {
    type: 'model-progress',
    payload: { chunks: 2, chars: 50 }
  });
});

test('runtimeEventToHeadless maps checkpoint-created artifacts', () => {
  const runtimeEvent: RuntimeEvent = {
    type: 'checkpoint-created',
    checkpointId: 'chk_test',
    kind: 'auto',
    workspaceCheckpointId: 'wchk_test',
    workspaceSnapshotStatus: 'available'
  };

  const mapped = runtimeEventToHeadless(runtimeEvent);

  assert.deepEqual(mapped, {
    type: 'checkpoint-created',
    payload: {
      checkpointId: 'chk_test',
      kind: 'auto',
      workspaceCheckpointId: 'wchk_test',
      workspaceSnapshotStatus: 'available'
    },
    artifacts: {
      checkpoints: ['chk_test'],
      workspaceCheckpoints: ['wchk_test'],
      compactions: [],
      handoffs: [],
      transactions: []
    }
  });
});

test('mergeArtifacts unions transactions[] without duplicates', () => {
  const target = emptyHeadlessArtifacts();
  target.transactions.push('tx_a');
  const source = emptyHeadlessArtifacts();
  source.transactions.push('tx_a', 'tx_b');
  mergeArtifacts(target, source);
  assert.deepEqual(target.transactions, ['tx_a', 'tx_b']);
});
