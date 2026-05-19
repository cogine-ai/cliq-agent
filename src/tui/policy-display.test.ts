import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  POLICY_MODE_DISPLAY,
  POLICY_MODE_ORDER,
  formatPolicyModeDetail,
  formatPolicyModeLabels,
  formatPolicyModeSummary
} from './policy-display.js';

test('policy display maps every internal mode to a TUI label and behavior description', () => {
  assert.deepEqual(Object.keys(POLICY_MODE_DISPLAY).sort(), [
    'auto',
    'confirm-all',
    'confirm-bash',
    'confirm-write',
    'read-only'
  ]);

  assert.deepEqual(POLICY_MODE_DISPLAY['read-only'], {
    label: 'plan',
    description: 'allow read tools only; block writes, shell, permission requests, and transaction apply',
    severity: 'safe',
    color: 'cyan'
  });
  assert.deepEqual(POLICY_MODE_DISPLAY['confirm-all'], {
    label: 'ask all',
    description: 'ask before every tool, permission request, and transaction apply',
    severity: 'guarded',
    color: 'green'
  });
  assert.deepEqual(POLICY_MODE_DISPLAY['confirm-write'], {
    label: 'ask edits',
    description: 'ask before writes, permission requests, and transaction apply; allow reads and shell',
    severity: 'caution',
    color: 'yellow'
  });
  assert.deepEqual(POLICY_MODE_DISPLAY['confirm-bash'], {
    label: 'ask shell',
    description: 'ask before shell and permission requests; allow reads, writes, and transaction apply',
    severity: 'caution',
    color: 'yellow'
  });
  assert.deepEqual(POLICY_MODE_DISPLAY.auto, {
    label: 'auto run',
    description: 'run tools, permission requests, and transaction apply without confirmation',
    severity: 'danger',
    color: 'red'
  });
});

test('policy display formatters use the shared mapping', () => {
  assert.equal(formatPolicyModeSummary('read-only'), 'plan (read-only)');
  assert.equal(
    formatPolicyModeDetail('auto'),
    'auto run (auto): run tools, permission requests, and transaction apply without confirmation'
  );
  assert.equal(
    formatPolicyModeLabels(POLICY_MODE_ORDER),
    'plan → ask all → ask edits → ask shell → auto run'
  );
});
