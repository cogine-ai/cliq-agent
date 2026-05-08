import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { withPathLock } from './path-lock.js';

test('withPathLock serializes concurrent callbacks for the same target', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-path-lock-'));
  try {
    const target = path.join(dir, 'shared-resource');
    // Assert SERIALIZATION (no interleaving), not acquisition ORDER.
    // The lock primitive does not promise FIFO/fairness, so under load `b`
    // can win the race; what matters is that one critical section completes
    // entirely before the other starts.
    const order: string[] = [];
    const work = (label: string, durationMs: number) =>
      withPathLock(target, async () => {
        order.push(`${label}-start`);
        await new Promise((r) => setTimeout(r, durationMs));
        order.push(`${label}-end`);
      });
    await Promise.all([work('a', 25), work('b', 5)]);
    assert.equal(order.length, 4, 'both critical sections must run');
    const [first0, first1, second0, second1] = order;
    assert.ok(first0.endsWith('-start'));
    assert.ok(first1.endsWith('-end'));
    assert.equal(first0.split('-')[0], first1.split('-')[0], 'first holder must finish before second');
    assert.ok(second0.endsWith('-start'));
    assert.ok(second1.endsWith('-end'));
    assert.equal(second0.split('-')[0], second1.split('-')[0], 'second holder must run as one block');
    assert.notEqual(first0.split('-')[0], second0.split('-')[0], 'each holder runs once');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('withPathLock returns the callback result and releases the lock', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-path-lock-result-'));
  try {
    const target = path.join(dir, 'thing');
    const value = await withPathLock(target, async () => 42);
    assert.equal(value, 42);

    // Subsequent acquire on the same target should not block (lock released).
    const second = await withPathLock(target, async () => 'ok');
    assert.equal(second, 'ok');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('withPathLock for distinct targets does not contend', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-path-lock-distinct-'));
  try {
    const targetA = path.join(dir, 'a');
    const targetB = path.join(dir, 'b');
    const order: string[] = [];

    // If these contended, b-end could not arrive before a-end. Hold A
    // longer than B; with no contention B finishes first.
    const a = withPathLock(targetA, async () => {
      order.push('a-start');
      await new Promise((r) => setTimeout(r, 50));
      order.push('a-end');
    });
    const b = withPathLock(targetB, async () => {
      order.push('b-start');
      await new Promise((r) => setTimeout(r, 5));
      order.push('b-end');
    });

    await Promise.all([a, b]);
    // The 'b-end' event must come before 'a-end' because the locks are
    // independent and B's callback completes first.
    assert.ok(
      order.indexOf('b-end') < order.indexOf('a-end'),
      `expected b-end before a-end, got ${order.join(',')}`
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
