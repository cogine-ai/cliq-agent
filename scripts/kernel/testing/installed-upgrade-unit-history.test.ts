import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createCredentialSecretScanner } from './credential-secret-scan.js';
import { withUpgradeUnitHistory } from './installed-upgrade-unit-history.js';

// Actual child/pipe ownership tests only. A child frame is not a D-Bus/native
// retirement receipt and these tests never create a Run or execution grant.
test('the retained-unit wrapper uses the existing one-byte release protocol and joins both original pipes', async () => {
  const scanner = createCredentialSecretScanner([Buffer.from('owned-never-output-secret')], { maxStreams: 16, maxBytes: 65536 });
  let calls = 0;
  await withUpgradeUnitHistory({ executable: process.execPath, args: ['--input-type=module', '-e',
    "process.stdout.write('systemd_units_retained\\n');let input='';for await(const c of process.stdin)input+=c;if(input!=='R')process.exit(23);process.stdout.write('systemd_units_released\\n');"],
    cwd: process.cwd(), env: { PATH: '/usr/bin:/bin' }, scanner }, async () => { calls++; });
  assert.equal(calls, 1); assert.equal(scanner.stats().streamsOpened, 2); assert.equal(scanner.stats().streamsClosed, 2); scanner.close();
});
test('a truncated retained frame never admits the body and both pipes still join', async () => {
  const scanner = createCredentialSecretScanner([Buffer.from('owned-never-output-secret')], { maxStreams: 16, maxBytes: 65536 });
  let calls = 0;
  await assert.rejects(withUpgradeUnitHistory({ executable: process.execPath, args: ['--input-type=module', '-e',
    "process.stdout.write('systemd_units_retained');"], cwd: process.cwd(), env: { PATH: '/usr/bin:/bin' }, scanner }, async () => { calls++; }));
  assert.equal(calls, 0); assert.equal(scanner.stats().streamsOpened, 2); assert.equal(scanner.stats().streamsClosed, 2); scanner.close();
});
