import assert from 'node:assert/strict';
import test from 'node:test';

import {
  formatPolicyModeError,
  isPolicyMode,
  POLICY_MODE_LIST,
  POLICY_MODES,
  policyModeMigrationHint
} from './modes.js';
import type { PolicyMode } from './types.js';

const LEGACY_MIGRATIONS: ReadonlyArray<[string, PolicyMode]> = [
  ['auto', 'yolo'],
  ['confirm-write', 'default'],
  ['read-only', 'plan'],
  ['confirm-bash', 'accept-edits']
];

test('POLICY_MODE_LIST stays in sync with POLICY_MODES order', () => {
  assert.equal(POLICY_MODE_LIST, POLICY_MODES.join(', '));
});

test('isPolicyMode accepts every canonical policy mode', () => {
  for (const mode of POLICY_MODES) {
    assert.equal(isPolicyMode(mode), true, mode);
  }
});

test('isPolicyMode rejects unknown and legacy preset names', () => {
  for (const value of ['', 'AUTO', 'yolo-mode', 'confirm-all', ...LEGACY_MIGRATIONS.map(([legacy]) => legacy)]) {
    assert.equal(isPolicyMode(value), false, value);
  }
});

test('policyModeMigrationHint maps retired presets to replacement guidance', () => {
  for (const [legacy, replacement] of LEGACY_MIGRATIONS) {
    const hint = policyModeMigrationHint(legacy);
    assert.ok(hint, legacy);
    assert.match(hint ?? '', new RegExp(replacement.replace('-', '\\-')));
  }

  assert.match(
    policyModeMigrationHint('confirm-all') ?? '',
    /confirm-all is no longer available/i
  );
  assert.match(
    policyModeMigrationHint('confirm-all') ?? '',
    /default.*plan/i
  );
});

test('policyModeMigrationHint returns undefined for unknown values', () => {
  assert.equal(policyModeMigrationHint('not-a-mode'), undefined);
  assert.equal(policyModeMigrationHint('default'), undefined);
});

test('formatPolicyModeError prefixes legacy migration hints and lists valid modes', () => {
  assert.equal(
    formatPolicyModeError('read-only'),
    `read-only has been replaced by plan; expected one of: ${POLICY_MODE_LIST}`
  );
});

test('formatPolicyModeError uses the subject label for unknown values without migration hints', () => {
  assert.equal(
    formatPolicyModeError('bogus', 'headless policy'),
    `Unknown headless policy: bogus; expected one of: ${POLICY_MODE_LIST}`
  );
});
