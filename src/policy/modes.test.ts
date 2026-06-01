import assert from 'node:assert/strict';
import test from 'node:test';

import {
  POLICY_MODES,
  formatPolicyModeError,
  isPolicyMode,
  policyModeMigrationHint
} from './modes.js';

test('POLICY_MODES lists the unified presets in canonical order', () => {
  assert.deepEqual(POLICY_MODES, ['default', 'accept-edits', 'plan', 'yolo']);
});

test('isPolicyMode accepts only unified presets', () => {
  for (const mode of POLICY_MODES) {
    assert.equal(isPolicyMode(mode), true);
  }
  assert.equal(isPolicyMode('auto'), false);
  assert.equal(isPolicyMode('read-only'), false);
  assert.equal(isPolicyMode(''), false);
});

test('policyModeMigrationHint maps retired presets to replacements', () => {
  assert.match(policyModeMigrationHint('auto') ?? '', /yolo/i);
  assert.match(policyModeMigrationHint('read-only') ?? '', /plan/i);
  assert.match(policyModeMigrationHint('confirm-bash') ?? '', /accept-edits/i);
  assert.match(policyModeMigrationHint('confirm-write') ?? '', /default/i);
  assert.equal(policyModeMigrationHint('default'), undefined);
});

test('formatPolicyModeError includes migration guidance and expected values', () => {
  assert.match(formatPolicyModeError('auto'), /yolo/i);
  assert.match(formatPolicyModeError('auto'), /default, accept-edits, plan, yolo/);
  assert.match(formatPolicyModeError('nope'), /Unknown policy mode: nope/i);
  assert.match(formatPolicyModeError('nope', 'permissions.preset'), /Unknown permissions\.preset: nope/i);
});
