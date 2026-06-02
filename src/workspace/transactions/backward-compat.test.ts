import test from 'node:test';
import assert from 'node:assert/strict';

import { parseWorkspaceConfig } from '../config.js';
import { isSessionRecord } from '../../session/store.js';
import type { SessionRecord } from '../../session/types.js';

/**
 * Backward-compat regression tests for v0.8.
 *
 * These exercise the contract that adding the v0.8 transaction runtime did
 * not break v0.7 behaviour:
 *   - workspace config without a `transactions` block parses cleanly with the
 *     transactions field omitted (NOT defaulted to {mode:'off'}).
 *   - sessions without any tx records still validate via the existing
 *     isSessionRecord type guard.
 */

test('workspace config without transactions block resolves with no tx fields set', () => {
  const cfg = parseWorkspaceConfig({});
  assert.equal(cfg.transactions, undefined);
  assert.deepEqual(cfg.instructionFiles, []);
  assert.deepEqual(cfg.extensions, []);
  assert.deepEqual(cfg.defaultSkills, []);
});

test('workspace config with explicit transactions.mode=off parses through', () => {
  const cfg = parseWorkspaceConfig({ transactions: { mode: 'off' } });
  assert.ok(cfg.transactions);
  assert.equal(cfg.transactions?.mode, 'off');
});

test('Session records without tx kinds still pass isSessionRecord', () => {
  const userRec: SessionRecord = {
    id: 'r1',
    ts: '2026-05-06T00:00:00.000Z',
    kind: 'user',
    role: 'user',
    content: 'hello'
  };
  const sysRec: SessionRecord = {
    id: 'r0',
    ts: '2026-05-06T00:00:00.000Z',
    kind: 'system',
    role: 'system',
    content: 'sys'
  };
  assert.equal(isSessionRecord(userRec), true);
  assert.equal(isSessionRecord(sysRec), true);
});
