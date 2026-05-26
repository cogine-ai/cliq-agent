import assert from 'node:assert/strict';
import test from 'node:test';

import {
  formatPolicyModeError,
  isPolicyMode,
  POLICY_MODE_LIST,
  POLICY_MODES,
  policyModeMigrationHint
} from './modes.js';

test('POLICY_MODES lists the four canonical presets in public order', () => {
  assert.deepEqual([...POLICY_MODES], ['default', 'accept-edits', 'plan', 'yolo']);
  assert.equal(POLICY_MODE_LIST, 'default, accept-edits, plan, yolo');
});

test('isPolicyMode accepts canonical presets and rejects unknown tokens', () => {
  for (const mode of POLICY_MODES) {
    assert.equal(isPolicyMode(mode), true);
  }

  assert.equal(isPolicyMode('invalid'), false);
  assert.equal(isPolicyMode('read-only'), false);
});

test('policyModeMigrationHint maps every legacy preset to guidance', () => {
  assert.match(policyModeMigrationHint('auto') ?? '', /yolo/i);
  assert.match(policyModeMigrationHint('confirm-write') ?? '', /default/i);
  assert.match(policyModeMigrationHint('read-only') ?? '', /plan/i);
  assert.match(policyModeMigrationHint('confirm-bash') ?? '', /accept-edits/i);
  assert.match(policyModeMigrationHint('confirm-all') ?? '', /no longer available/i);
  assert.equal(policyModeMigrationHint('default'), undefined);
});

test('formatPolicyModeError prefixes migration hints and lists valid presets', () => {
  assert.match(
    formatPolicyModeError('read-only'),
    /^read-only has been replaced by plan; expected one of: default, accept-edits, plan, yolo$/
  );
  assert.match(
    formatPolicyModeError('frobnicate', 'permissions.preset'),
    /^Unknown permissions\.preset: frobnicate; expected one of: default, accept-edits, plan, yolo$/
  );
});
