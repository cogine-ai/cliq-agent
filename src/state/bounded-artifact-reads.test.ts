import assert from 'node:assert/strict';
import { test } from 'node:test';

import { mapArtifactReads, RECOVERY_ARTIFACT_READ_CONCURRENCY } from './bounded-artifact-reads.js';

test('recovery artifact reads bound pending work and preserve source order', async () => {
  let releaseFirstWave!: () => void;
  const firstWave = new Promise<void>((resolve) => { releaseFirstWave = resolve; });
  let active = 0;
  let peak = 0;
  const started: number[] = [];
  const values = Array.from({ length: 40 }, (_, index) => index);
  const pending = mapArtifactReads(values, async (value) => {
    started.push(value);
    active += 1;
    peak = Math.max(peak, active);
    if (value < RECOVERY_ARTIFACT_READ_CONCURRENCY) await firstWave;
    active -= 1;
    return value * 2;
  });
  assert.deepEqual(started, values.slice(0, RECOVERY_ARTIFACT_READ_CONCURRENCY));
  releaseFirstWave();
  assert.deepEqual(await pending, values.map((value) => value * 2));
  assert.equal(peak, RECOVERY_ARTIFACT_READ_CONCURRENCY);
  assert.equal(active, 0);
});

test('a failed artifact read drains in-flight work and schedules no later reads', async () => {
  const failure = new Error('corrupt artifact');
  let releaseOtherReads!: () => void;
  const otherReads = new Promise<void>((resolve) => { releaseOtherReads = resolve; });
  const started: number[] = [];
  const pending = mapArtifactReads(Array.from({ length: 40 }, (_, index) => index), async (value) => {
    started.push(value);
    if (value === 0) throw failure;
    await otherReads;
    return value;
  });
  releaseOtherReads();
  await assert.rejects(pending, (error) => error === failure);
  assert.ok(started.length <= RECOVERY_ARTIFACT_READ_CONCURRENCY);
});
