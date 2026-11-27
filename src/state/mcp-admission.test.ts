import assert from 'node:assert/strict';
import test from 'node:test';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { hasInstalledMcpRecipe } from './mcp-admission.js';

// Inert manifest entry data only. This does not verify or create a bundle,
// installed selection, authorization, native image or executable capability.
const entry = (entryId: string, role: string, executable: boolean, relativePath = `entries/${entryId}`): RuntimeBundleManifest['entries'][number] =>
  ({ entryId, role, executable, relativePath, version: '1', digest: 'a'.repeat(64), byteCount: 1 });
const http = [entry('mcp-streamable-http-broker-v1', 'platform_helper', true, 'native/linux-x64/linux-mcp-http-broker.node'),
  entry('mcp-http-admin-probe-v1', 'platform_helper', false, 'helpers/mcp-http-admin-probe.mjs')];
const stdio = [entry('mcp-stdio-broker-v1', 'platform_helper', true, 'native/linux-x64/linux-mcp-stdio-broker.node'),
  entry('linux_worker_controller', 'platform_helper', true), entry('linux_worker_native', 'platform_helper', true),
  entry('linux_bubblewrap', 'platform_helper', true), entry('installed-empty-root', 'sandbox_root_profile', false)];

test('HTTP and stdio independently require their complete fixed recipe without borrowing the other transport', () => {
  assert.equal(hasInstalledMcpRecipe({ entries: http }, 'streamable_http'), true);
  assert.equal(hasInstalledMcpRecipe({ entries: http }, 'stdio'), false);
  assert.equal(hasInstalledMcpRecipe({ entries: stdio }, 'stdio'), true);
  assert.equal(hasInstalledMcpRecipe({ entries: stdio }, 'streamable_http'), false);
  for (const kind of ['streamable_http', 'stdio'] as const) {
    const own = kind === 'stdio' ? stdio : http, other = kind === 'stdio' ? http : stdio;
    for (let index = 0; index < own.length; index++) {
      assert.equal(hasInstalledMcpRecipe({ entries: [...own.slice(0, index), ...own.slice(index + 1), ...other] }, kind), false);
      assert.equal(hasInstalledMcpRecipe({ entries: [...own, own[index]!] }, kind), false);
      for (const changes of [{ role: 'mcp_server' }, { executable: !own[index]!.executable }, { version: '2' }]) {
        const entries = own.map((value, position) => position === index ? { ...value, ...changes } : value);
        assert.equal(hasInstalledMcpRecipe({ entries }, kind), false);
      }
    }
  }
});

test('a similarly named broker or helper at an alternate path is not the fixed installed recipe', () => {
  for (const [entries, kind, index] of [[http, 'streamable_http', 0], [http, 'streamable_http', 1], [stdio, 'stdio', 0]] as const) {
    assert.equal(hasInstalledMcpRecipe({ entries: entries.map((value, position) => position === index
      ? { ...value, relativePath: 'alternate/image' } : value) }, kind), false);
  }
});
