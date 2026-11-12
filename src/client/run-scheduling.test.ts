import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { DEFAULT_RUN_SCHEDULING, decodeRunScheduling } from '../kernel/run-scheduling.js';
import { readRunScheduling, schedulingCommand, writeRunScheduling } from './run-scheduling.js';

test('one closed account preference configures the next start without accepting workspace or permission fields', () => {
  assert.equal(schedulingCommand(['settings']), undefined);
  for (const value of [1]) assert.deepEqual(schedulingCommand(['settings', '--run-concurrency', String(value)]),
    { schemaVersion: 1, maxConcurrentRuns: value });
  for (const args of [['settings', '--run-concurrency', '0'], ['settings', '--run-concurrency', '33'],
    ['settings', '--run-concurrency', '02'], ['settings', '--run-concurrency', '2e0'],
    ['settings', '--run-concurrency', '2', '--workspace', '/repo']]) assert.throws(() => schedulingCommand(args));
  for (const key of ['workspace', 'policyMode', 'budget', 'runtimeBundle', 'home', 'credentials'])
    assert.throws(() => decodeRunScheduling({ schemaVersion: 1, maxConcurrentRuns: 2, [key]: 'not_authority' }));
  let read = false;
  assert.throws(() => decodeRunScheduling({ schemaVersion: 1, get maxConcurrentRuns() { read = true; return 2; } }));
  assert.equal(read, false);
});

test('the actual private-file port preserves strict UTF-8/JCS and never defaults past corruption or a failed write', async () => {
  let bytes: Buffer | undefined, file: string | undefined;
  const directory = { async read(name: string, maximum: number) { assert.equal(maximum, 1024); file = name; return bytes; },
    async replace(name: string, value: Uint8Array) { file = name; bytes = Buffer.from(value); } };
  assert.equal(await readRunScheduling(directory), DEFAULT_RUN_SCHEDULING);
  const settings = await writeRunScheduling(directory, { schemaVersion: 1, maxConcurrentRuns: 1 });
  assert.equal(file, 'run-scheduling.json'); assert.deepEqual(bytes, canonicalJsonBytes(settings));
  assert.deepEqual(await readRunScheduling(directory), settings);
  for (const bad of [Buffer.from('{"schemaVersion":1,"maxConcurrentRuns":2}'), Buffer.from([0xff]), Buffer.alloc(1025),
    Buffer.from('{"maxConcurrentRuns":2,"maxConcurrentRuns":3,"schemaVersion":1}')]) {
    bytes = bad; await assert.rejects(readRunScheduling(directory));
  }
  const failure = new Error('actual private write failed');
  await assert.rejects(writeRunScheduling({ async replace() { throw failure; } }, settings), error => error === failure);
});

test('preview refuses unsupported capacity before persistence or Supervisor startup without rewriting old preferences', async () => {
  for (const maxConcurrentRuns of [2, 32]) {
    const settings = { schemaVersion: 1, maxConcurrentRuns };
    let writes = 0;
    assert.throws(() => schedulingCommand(['settings', '--run-concurrency', String(maxConcurrentRuns)]), /one active task/u);
    await assert.rejects(writeRunScheduling({ async replace() { writes++; } }, settings), /one active task/u);
    assert.equal(writes, 0);
    const bytes = canonicalJsonBytes(settings), original = Buffer.from(bytes);
    await assert.rejects(readRunScheduling({ async read() { return bytes; } }), /one active task/u);
    assert.deepEqual(bytes, original);
  }
});
