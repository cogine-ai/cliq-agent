import assert from 'node:assert/strict';
import test from 'node:test';
import { BoundedRunQueue } from './bounded-run-queue.js';

function gate() {
  let resolve!: () => void;
  const promise = new Promise<void>(ready => { resolve = ready; });
  return { promise, resolve };
}

test('a blocked Run does not stall the other lane and newly free lanes retain FIFO order', async () => {
  const queue = new BoundedRunQueue(2), entered: string[] = [];
  const gates = Array.from({ length: 4 }, gate);
  const starts = Array.from({ length: 4 }, gate);
  const jobs = gates.map((gate, index) => queue.run(async () => {
    entered.push(String(index)); starts[index]!.resolve(); await gate.promise;
  }));
  await Promise.all([starts[0]!.promise, starts[1]!.promise]);
  assert.deepEqual(entered, ['0', '1']);
  gates[1]!.resolve(); await starts[2]!.promise;
  assert.deepEqual(entered, ['0', '1', '2']);
  gates[2]!.resolve(); await starts[3]!.promise;
  assert.deepEqual(entered, ['0', '1', '2', '3']);
  gates[3]!.resolve(); gates[0]!.resolve(); await Promise.all(jobs);
});

test('failure remains observable to its caller and releases a lane only after the original operation settles', async () => {
  const queue = new BoundedRunQueue(1), joined = gate(), started = gate();
  const failure = new Error('owned data failure'); let originalJoined = false, successorRan = false;
  const failed = queue.run(async () => { started.resolve(); await joined.promise; originalJoined = true; throw failure; });
  const observed = assert.rejects(failed, error => error === failure);
  const successor = queue.run(async () => { assert.equal(originalJoined, true); successorRan = true; });
  await started.promise; assert.equal(successorRan, false);
  joined.resolve(); await Promise.all([observed, successor]); assert.equal(successorRan, true);
});

test('invalid capacities never create an unbounded or disabled driver queue', () => {
  for (const value of [0, -1, 1.5, 33, NaN, Infinity]) assert.throws(() => new BoundedRunQueue(value));
});
