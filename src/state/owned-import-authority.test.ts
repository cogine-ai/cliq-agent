// Brand-refusal data only. No StateOwner, Run, credentials or native proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assertOwnedImportCredentialAuthority } from './store.js';
import { observeHeldMigrationWorkspaceIdentity } from './native-owner.js';
import { installedMigrationNeedsRecovery } from './migration-startup.js';

test('owned import authenticates even an empty credential scope before invoking a structural token', () => {
  let invoked = false;
  for (const token of [{ assertHeld() { invoked = true; } }, new Proxy({}, {
    get() { invoked = true; throw new Error('untrusted accessor must not run'); }
  })]) {
    assert.throws(() => Reflect.apply(assertOwnedImportCredentialAuthority, undefined,
      [token, undefined, undefined, 'original-principal', undefined]), { code: 'ARTIFACT_MISMATCH' });
  }
  assert.equal(invoked, false);
});

test('candidate workspace identity does not invoke a forged scope or a development native factory', () => {
  let invoked = false;
  const scope = { assertHeld() { invoked = true; }, close() { invoked = true; } };
  assert.throws(() => observeHeldMigrationWorkspaceIdentity(scope, '/ordinary', 'principal'), TypeError);
  assert.equal(invoked, false);
});

test('startup rejects a structural account participant before reading a supplied context or native factory', async () => {
  let invoked = false;
  const account = { assertShared() { invoked = true; } };
  await assert.rejects(Reflect.apply(installedMigrationNeedsRecovery, undefined,
    [undefined, undefined, account, undefined, undefined]), TypeError);
  assert.equal(invoked, false);
});
