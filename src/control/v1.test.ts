import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import * as generated from './v1.js';
import * as canonical from '../kernel/control-wire.js';

test('the checked-in v1 contract is current for its canonical source closure', () => {
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const child = spawnSync(process.execPath, ['--import', 'tsx', 'scripts/kernel/generate-control-v1.ts', '--check'],
    { cwd: root, encoding: 'utf8', timeout: 15000, maxBuffer: 16384,
      // Data-only code generation is not a native/installed launch. Suppress
      // Node 26's unrelated tsx loader deprecation, not application failures.
      env: { ...process.env, NODE_NO_WARNINGS: '1' } });
  assert.equal(child.error, undefined); assert.equal(child.signal, null);
  assert.equal(child.status, 0, 'canonical source changes require actual contract regeneration');
  assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});

test('generated schemas are the original executable codecs, not lossy inferred validators', () => {
  assert.equal(generated.decodeControlFrame, canonical.decodeControlFrame);
  assert.equal(generated.decodeInstalledControlRequest, canonical.decodeInstalledControlRequest);
  assert.equal(generated.decodeInstalledControlEnvelope, canonical.decodeInstalledControlEnvelope);
  assert.equal(generated.decodeInstalledControlResponse, canonical.decodeInstalledControlResponse);
  assert.equal(generated.CONTROL_V1_CONNECTED_METHOD_METADATA, canonical.INSTALLED_CONTROL_FEATURES);
  assert.equal(generated.CONTROL_V1_DECLARED_METHOD_METADATA, canonical.CONTROL_METHODS_V1);
  assert.equal(generated.HEADLESS_SCHEMA_VERSION, 3);
  assert.equal(generated.CONTROL_PROTOCOL_VERSION, 1);
  assert.equal(generated.decodeHeadlessControlRequest, canonical.decodeHeadlessControlRequest);
  assert.equal(generated.decodeHeadlessControlResponse, canonical.decodeHeadlessControlResponse);
  assert.equal(generated.headlessControlHello, canonical.headlessControlHello);
  assert.equal(generated.headlessRunEvent, canonical.headlessRunEvent);
  assert(generated.CONTROL_V1_CONNECTED_METHOD_METADATA.some(method => String(method) === 'session.list'));
  for (const name of ['src/kernel/types.ts', 'src/kernel/authorization.ts', 'src/kernel/execution.ts',
    'src/kernel/control-wire.ts', 'src/kernel/control-wire-data.ts', 'src/kernel/control-submit.ts', 'src/kernel/control-apply.ts', 'src/kernel/session-continuity.ts'])
    assert(Object.hasOwn(generated.CONTROL_V1_SOURCE_MANIFEST.sources, name));
  assert(Object.isFrozen(generated.CONTROL_V1_SOURCE_MANIFEST.sources));
  assert(Object.isFrozen(generated.CONTROL_V1_SOURCE_MANIFEST.externalImports));
  assert.deepEqual(generated.decodeInstalledControlRequest({ protocolVersion: 1, method: 'session.list' }), { protocolVersion: 1, method: 'session.list' });
  assert.throws(() => generated.decodeInstalledControlRequest({ protocolVersion: 1, method: 'session.append' }));
});
