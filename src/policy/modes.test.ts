import assert from 'node:assert/strict';
import test from 'node:test';

import {
  formatPolicyModeError,
  isPolicyMode,
  POLICY_MODE_LIST,
  POLICY_MODES,
  policyModeMigrationHint
} from './modes.js';

test('POLICY_MODES lists the canonical public order', () => {
  assert.deepEqual([...POLICY_MODES], ['default', 'accept-edits', 'plan', 'yolo']);
  assert.equal(POLICY_MODE_LIST, 'default, accept-edits, plan, yolo');
});

test('isPolicyMode accepts only canonical presets', () => {
  for (const mode of POLICY_MODES) {
    assert.equal(isPolicyMode(mode), true);
  }
  assert.equal(isPolicyMode('read-only'), false);
  assert.equal(isPolicyMode(''), false);
});

test('policyModeMigrationHint maps legacy presets to replacements', () => {
  assert.equal(policyModeMigrationHint('auto'), 'auto has been replaced by yolo');
  assert.equal(policyModeMigrationHint('confirm-write'), 'confirm-write has been replaced by default');
  assert.equal(policyModeMigrationHint('read-only'), 'read-only has been replaced by plan');
  assert.equal(policyModeMigrationHint('confirm-bash'), 'confirm-bash has been replaced by accept-edits');
  assert.match(policyModeMigrationHint('confirm-all') ?? '', /confirm-all is no longer available/i);
  assert.equal(policyModeMigrationHint('default'), undefined);
});

test('formatPolicyModeError includes migration guidance and the valid preset list', () => {
  assert.match(formatPolicyModeError('read-only'), /read-only has been replaced by plan/);
  assert.match(formatPolicyModeError('read-only'), new RegExp(`expected one of: ${POLICY_MODE_LIST}`));

  assert.match(formatPolicyModeError('totally-unknown'), /Unknown policy mode: totally-unknown/);
  assert.match(formatPolicyModeError('totally-unknown', 'headless policy'), /Unknown headless policy: totally-unknown/);
});
