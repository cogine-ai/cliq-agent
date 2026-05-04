import test from 'node:test';
import assert from 'node:assert/strict';

import type { RuntimeEventEnvelope } from './contract.js';
import { writeJsonlEvent } from './jsonl.js';

test('writeJsonlEvent writes one parseable JSON object per line', () => {
  const chunks: string[] = [];
  const event: RuntimeEventEnvelope = {
    schemaVersion: 1,
    eventId: 'evt_1',
    runId: 'run_1',
    timestamp: '2026-05-03T00:00:00.000Z',
    type: 'error',
    payload: {
      code: 'invalid-input',
      stage: 'input',
      message: 'prompt is required',
      recoverable: false
    }
  };

  writeJsonlEvent(event, (chunk) => {
    chunks.push(chunk);
  });

  assert.equal(chunks.length, 1);
  assert.equal(chunks[0]?.endsWith('\n'), true);
  assert.deepEqual(JSON.parse(chunks[0]!), event);
});
