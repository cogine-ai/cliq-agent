import test from 'node:test';
import assert from 'node:assert/strict';
import { OwnedImportRetainedDataBudget } from './owned-import-budget.js';

test('the import retained index shares a fixed complete-operation record and text budget', () => {
  const records = new OwnedImportRetainedDataBudget();
  for (let index = 0; index < 65_536; index++) records.reserve('');
  assert.throws(() => records.reserve(''), { code: 'RECOVERY_REQUIRED' });
  const text = new OwnedImportRetainedDataBudget(), fragment = 'é'.repeat(262_144);
  for (let index = 0; index < 64; index++) text.reserve(fragment);
  assert.throws(() => text.reserve('x'), { code: 'RECOVERY_REQUIRED' });
});
