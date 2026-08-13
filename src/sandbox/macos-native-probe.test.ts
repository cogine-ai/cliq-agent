import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const helperSourceUrl = new URL(
  '../../native/macos/CliqKernelProbe/Sources/CliqKernelProbe/main.swift',
  import.meta.url
);
const buildScriptUrl = new URL('../../scripts/kernel/build-macos-execution-probe.sh', import.meta.url);

test('macOS helper hashes its actual bundle executable rather than caller-controlled argv[0]', async () => {
  const source = await readFile(helperSourceUrl, 'utf8');

  assert.match(source, /Bundle\.main\.executableURL/);
  assert.doesNotMatch(source, /sha256\(URL\(fileURLWithPath: CommandLine\.arguments\[0\]\)\)/);
});

test('macOS receipt binds guest denials and the no-share/no-network VM configuration', async () => {
  const source = await readFile(helperSourceUrl, 'utf8');

  assert.match(source, /configuration\.directorySharingDevices\.isEmpty/);
  assert.match(source, /configuration\.networkDevices\.isEmpty/);
  for (const observation of [
    'workspaceReadDenied',
    'workspaceWriteDenied',
    'stateReadDenied',
    'stateWriteDenied',
    'homeReadDenied',
    'directNetworkDenied'
  ]) {
    assert.match(source, new RegExp(`${observation}: observedReceipt\\.${observation}`));
    assert.doesNotMatch(source, new RegExp(`${observation}: true`));
  }
});

test('macOS forced-termination evidence comes from destructive VM stop completion', async () => {
  const source = await readFile(helperSourceUrl, 'utf8');

  assert.match(source, /try await virtualMachine\.stop\(\)/);
  assert.match(source, /let forcedTerminationEmpty = virtualMachine\.state == \.stopped/);
  assert.match(source, /forcedTerminationEmpty: forcedTerminationEmpty/);
  assert.doesNotMatch(source, /forcedTerminationEmpty: true/);
});

test('macOS release signing uses a secure timestamp unless explicitly disabled', async () => {
  const source = await readFile(buildScriptUrl, 'utf8');

  assert.match(source, /timestamp_flag=--timestamp\n/);
  assert.match(source, /if \[ "\$\{CLIQ_CODESIGN_TIMESTAMP:-1\}" = "0" \]; then\n\s+timestamp_flag=--timestamp=none/);
});
