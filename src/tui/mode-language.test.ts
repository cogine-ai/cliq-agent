import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import type { PolicyMode } from '../policy/types.js';
import {
  describePolicyMode,
  formatModeForHelp,
  formatModeForStatus,
  listPolicyModeDescriptions
} from './mode-language.js';

const ALL_MODES: readonly PolicyMode[] = [
  'auto',
  'confirm-write',
  'read-only',
  'confirm-bash',
  'confirm-all'
];

test('policy mode language maps every internal mode to a user-facing label', () => {
  for (const mode of ALL_MODES) {
    const description = describePolicyMode(mode);
    assert.equal(description.mode, mode);
    assert.notEqual(description.label, mode);
    assert.ok(description.label.length > 0);
    assert.ok(description.shortLabel.length > 0);
    assert.ok(description.description.length > 20);
  }
});

test('status label marks low-friction auto mode distinctly', () => {
  assert.match(formatModeForStatus('auto'), /^! Auto Run$/);
  assert.equal(describePolicyMode('auto').risk, 'danger');
  assert.equal(describePolicyMode('read-only').risk, 'safe');
});

test('help formatter uses the same labels as the mode descriptions', () => {
  const rows = listPolicyModeDescriptions();
  assert.deepEqual(
    rows.map((row) => row.mode),
    ALL_MODES
  );

  for (const row of rows) {
    assert.match(formatModeForHelp(row.mode), new RegExp(row.label));
    assert.match(formatModeForHelp(row.mode), new RegExp(row.mode));
  }
});
