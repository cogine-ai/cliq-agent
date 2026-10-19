// Pure canonical timing contract only; no terminal, native or publication authority.
import assert from 'node:assert/strict';
import test from 'node:test';
import { assertRunResultPreparationTime } from './run-result-recovery.js';

test('atomic delivery truthfully prepares immutable result bytes after observation and before its SQL Checkpoints', () => {
  assert.doesNotThrow(() => assertRunResultPreparationTime('delivery', '2026-01-01T00:00:01.000Z',
    '2026-01-01T00:00:02.000Z', '2026-01-01T00:00:02.000Z', '2026-01-01T00:00:00.000Z'));
  assert.throws(() => assertRunResultPreparationTime('agent', '2026-01-01T00:00:01.000Z',
    '2026-01-01T00:00:02.000Z', '2026-01-01T00:00:02.000Z'));
});

test('terminal timing refuses missing observations, future preparation and a separate publication transaction', () => {
  const observation = '2026-01-01T00:00:01.000Z', preparation = '2026-01-01T00:00:02.000Z', commit = '2026-01-01T00:00:03.000Z';
  const invalid: Parameters<typeof assertRunResultPreparationTime>[] = [
    ['delivery', preparation, commit, commit],
    ['delivery', observation, commit, commit, preparation],
    ['delivery', commit, preparation, preparation, observation],
    ['delivery', preparation, preparation, commit, observation],
    ['delivery', preparation, commit, commit, 'not-canonical'],
  ];
  for (const values of invalid) assert.throws(() => assertRunResultPreparationTime(...values));
  assert.throws(() => assertRunResultPreparationTime('unknown' as never, preparation, preparation, commit));
  assert.doesNotThrow(() => assertRunResultPreparationTime('delivery', observation, observation, observation, observation));
  assert.doesNotThrow(() => assertRunResultPreparationTime('agent', preparation, observation, commit));
});
