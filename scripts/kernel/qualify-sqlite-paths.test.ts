import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const driver = fileURLToPath(new URL('./qualify-sqlite-paths.ts', import.meta.url));
const loader = createRequire(import.meta.url).resolve('tsx');

test('SQLite path diagnostic CLI describes all eight closed cuts without claiming OS qualification', () => {
  const result = spawnSync(process.execPath, ['--import', loader, driver, '--describe'],
    { cwd: '/', encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  const described = JSON.parse(result.stdout);
  assert.equal(described.diagnosticOnly, true);
  assert.equal(described.productionCredentialAuthorityQualified, false);
  assert.equal(described.installedI1Qualified, false);
  assert.equal(described.carrierVersion, '24.21.0');
  assert.deepEqual(described.cases, [
    { pathKind: 'canonical', cut: 'normal' },
    { pathKind: 'canonical', cut: 'parent_before_open' },
    { pathKind: 'canonical', cut: 'parent_after_open' },
    { pathKind: 'canonical', cut: 'leaf_before_open' },
    { pathKind: 'held_parent', cut: 'normal' },
    { pathKind: 'held_parent', cut: 'parent_before_open' },
    { pathKind: 'held_parent', cut: 'parent_after_open' },
    { pathKind: 'held_parent', cut: 'leaf_before_open' },
  ]);
  assert.equal(described.preopenBarrier, 'test-only unique call-site insertion after production prepareDatabasePath');
  assert.equal(described.observerDescriptorCloseOrder, 'all SQLite connections close before extra DB descriptors');
  assert.deepEqual(described.privateVfsMechanism.modes, ['unregistered', 'scoped', 'permanent', 'dual', 'tampered']);
  assert.equal(described.privateVfsMechanism.physicalBindingQualified, false);
  assert.equal(described.privateVfsMechanism.productionCredentialAuthorityQualified, false);
});

test('SQLite path diagnostic CLI rejects unknown modes instead of opening a caller-selected database', () => {
  const result = spawnSync(process.execPath, ['--import', loader, driver, '--database', '/tmp/not-authority.sqlite'],
    { cwd: '/', encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /usage: qualify-sqlite-paths/u);
});
