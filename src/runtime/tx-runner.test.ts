import test from 'node:test';
import assert from 'node:assert/strict';

import { assertHeadlessCompatible, type TxRunnerOptions } from './tx-runner.js';

function baseOpts(overrides: Partial<TxRunnerOptions> = {}): TxRunnerOptions {
  return {
    mode: 'edit',
    auto: 'per-turn',
    applyPolicy: 'auto-on-pass',
    bashPolicy: 'passthrough',
    headless: false,
    validatorsConfig: {},
    stagedViewConfig: { copyMode: 'auto', bindPaths: [] },
    workspaceId: 'ws',
    workspaceRealPath: '/tmp/ws',
    ...overrides
  };
}

test('assertHeadlessCompatible passes for non-interactive applyPolicy under headless', () => {
  assertHeadlessCompatible(baseOpts({ headless: true, applyPolicy: 'auto-on-pass' }));
  assertHeadlessCompatible(baseOpts({ headless: true, applyPolicy: 'manual-only', auto: 'manual' }));
});

test('assertHeadlessCompatible passes for interactive applyPolicy with TTY (headless: false)', () => {
  assertHeadlessCompatible(baseOpts({ headless: false, applyPolicy: 'interactive' }));
});

test('assertHeadlessCompatible throws when applyPolicy=interactive + headless', () => {
  assert.throws(
    () => assertHeadlessCompatible(baseOpts({ headless: true, applyPolicy: 'interactive' })),
    /interactive requires a TTY/
  );
});
