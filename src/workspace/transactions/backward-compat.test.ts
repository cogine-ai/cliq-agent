import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { parseWorkspaceConfig } from '../config.js';
import { isSessionRecord } from '../../session/store.js';
import type { SessionRecord } from '../../session/types.js';

const execFileAsync = promisify(execFile);

/**
 * Backward-compat regression tests for v0.8.
 *
 * These exercise the contract that adding the v0.8 transaction runtime did
 * not break v0.7 behaviour:
 *   - workspace config without a `transactions` block parses cleanly with the
 *     transactions field omitted (NOT defaulted to {mode:'off'}).
 *   - the CLIQ_TX_MODE env var defaults to undefined when unset.
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

test('CLIQ_TX_MODE env defaults to undefined when unset', async () => {
  // The config module captures process.env once at import time, so reading
  // the export inside the test process tells us nothing about a fresh boot:
  // whatever value happened to be set when this suite started would already
  // be baked in. Spawn an isolated `node` (with tsx loader so the .ts source
  // is honoured without a build step) and import config.ts with CLIQ_TX_MODE
  // explicitly removed. We assert strict equality with 'undefined' to verify
  // the default-on-first-load behaviour, not just the type.
  const env = { ...process.env };
  delete env.CLIQ_TX_MODE;
  const { stdout } = await execFileAsync(
    process.execPath,
    [
      '--import',
      'tsx',
      '--input-type=module',
      '-e',
      "import('./src/config.ts').then(m => process.stdout.write(String(m.CLIQ_TX_MODE)))"
    ],
    { env, cwd: process.cwd() }
  );
  assert.equal(stdout, 'undefined');
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
