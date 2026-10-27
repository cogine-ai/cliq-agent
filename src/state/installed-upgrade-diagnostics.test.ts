import assert from 'node:assert/strict';
import { test } from 'node:test';
import { INSTALLED_RUNTIME_UPGRADE_PHASES, installedRuntimeUpgradeFailureMarker, readInstalledRuntimeUpgradeFailureMarker } from './installed-upgrade-diagnostics.js';

test('upgrade diagnostics emit only fixed phases and codes, with no exception or caller property execution', () => {
  const secret = 'dedicated-diagnostic-secret-never-emit';
  for (const phase of INSTALLED_RUNTIME_UPGRADE_PHASES) {
    const marker = installedRuntimeUpgradeFailureMarker(phase, { code: 'ARTIFACT_MISMATCH', message: secret, path: secret });
    assert.equal(marker, `CLIQ_INSTALLED_UPGRADE_FAILURE_V1:${phase}:ARTIFACT_MISMATCH\n`); assert(!marker.includes(secret));
  }
  let calls = 0;
  const accessor = Object.defineProperty({}, 'code', { get() { calls++; throw new Error(secret); } });
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { calls++; throw new Error(secret); } });
  for (const error of [accessor, proxy, secret, null, { code: secret }])
    assert.equal(installedRuntimeUpgradeFailureMarker(secret, error), 'CLIQ_INSTALLED_UPGRADE_FAILURE_V1:unknown:unclassified\n');
  assert.equal(calls, 0);
});

test('only one exact bounded source marker can be forwarded after scanning original stderr', () => {
  const marker = installedRuntimeUpgradeFailureMarker('stage_owner_history', { code: 'RECOVERY_REQUIRED' });
  const input = Buffer.from('untrusted child error text\n' + marker + 'other error text\n');
  const copied = readInstalledRuntimeUpgradeFailureMarker(input);
  assert.deepEqual(copied, Buffer.from(marker)); input.fill(0); assert.deepEqual(copied, Buffer.from(marker));
  for (const bytes of [Buffer.from(marker + marker), Buffer.from(marker.replace('RECOVERY_REQUIRED', 'foreign')),
    Buffer.from('prefix-' + marker), Buffer.from(marker.replace('stage_owner_history', 'foreign')), Buffer.alloc(2 * 1024 * 1024 + 1),
    new Proxy(Buffer.from(marker), {})]) assert.equal(readInstalledRuntimeUpgradeFailureMarker(bytes), undefined);
});
