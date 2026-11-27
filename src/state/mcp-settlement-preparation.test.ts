import assert from 'node:assert/strict';
import test from 'node:test';
import { retainMcpSettlementPreparation, retainMcpTerminalAcknowledgement } from './mcp-settlement-preparation.js';

// Promise/publication data only. No native owner, claim, settlement or proof.
test('one failed publication remains observable without poisoning an explicit later local preparation', async () => {
  const originalData = Object.freeze({ ref: 'original-inert-data' }), failure = new Error('owned storage refused');
  let started!: () => void, join!: () => void, attempts = 0;
  const entered = new Promise<void>(resolve => { started = resolve; });
  const joined = new Promise<void>(resolve => { join = resolve; });
  const prepare = retainMcpSettlementPreparation(async () => {
    if (++attempts === 1) { started(); await joined; throw failure; }
    return originalData;
  });
  const first = prepare(), concurrent = prepare(); assert.equal(first, concurrent);
  const rejected = assert.rejects(first, error => error === failure);
  await entered; assert.equal(attempts, 1); assert.equal(prepare(), first);
  join(); await rejected; await assert.rejects(concurrent, error => error === failure);
  assert.equal(attempts, 1, 'failure creates no automatic retry');
  const next = prepare(); assert.notEqual(next, first); assert.equal(await next, originalData);
  assert.equal(prepare(), next); assert.equal(await prepare(), originalData); assert.equal(attempts, 2);
});

test('a synchronous preparation error has the same explicit retry and original error semantics', async () => {
  const failure = new TypeError('inert invalid publication'); let attempts = 0;
  const prepare = retainMcpSettlementPreparation(() => { attempts++; throw failure; });
  await assert.rejects(prepare(), error => error === failure); assert.equal(attempts, 1);
  await assert.rejects(prepare(), error => error === failure); assert.equal(attempts, 2);
});
test('a successful original release is never repeated when the subsequent original close fails', () => {
  const failure = new Error('inert input close refused'); let releases = 0, closes = 0;
  const acknowledge = retainMcpTerminalAcknowledgement(() => { releases++; }, () => { if (++closes === 1) throw failure; });
  assert.throws(acknowledge, error => error === failure); assert.equal(releases, 1); assert.equal(closes, 1);
  acknowledge(); acknowledge(); assert.equal(releases, 1); assert.equal(closes, 2);
});
test('a refused original release neither advances the close phase nor conceals its error', () => {
  const failure = new Error('inert native release refused'); let releases = 0, closes = 0;
  const acknowledge = retainMcpTerminalAcknowledgement(() => { if (++releases === 1) throw failure; }, () => { closes++; });
  assert.throws(acknowledge, error => error === failure); assert.equal(closes, 0);
  acknowledge(); acknowledge(); assert.equal(releases, 2); assert.equal(closes, 1);
});
