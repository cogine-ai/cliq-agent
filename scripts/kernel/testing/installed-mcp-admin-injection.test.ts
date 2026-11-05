// Actual ESM bundling and ordinary Node output only; no selected runtime,
// StateOwner, native factory, resource scope or qualification is constructed.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildSupervisorSeaApplication } from './supervisor-sea-builder.js';

test('the signed-application builder includes the fixed MCP observer alongside the original resource observer', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-mcp-observer-app-'));
  try {
    const entry = path.join(fixture, 'entry.ts');
    const diagnostic = fileURLToPath(new URL('../../../src/state/mcp-admin-diagnostics.ts', import.meta.url));
    await writeFile(entry, `import {noteMcpAdminLifecycle} from ${JSON.stringify(diagnostic)};
noteMcpAdminLifecycle('http','native_close','entered');\n`, { flag: 'wx', mode: 0o600 });
    const built = await buildSupervisorSeaApplication({ fixture, entryPoint: entry, variant: 'fixed-observer',
      resourceDiagnostics: true, mcpAdminDiagnostics: true });
    assert(built.sources.some(name => name.endsWith('/installed-resource-subscriber.ts')));
    assert(built.sources.some(name => name.endsWith('/installed-mcp-admin-subscriber.ts')));
    const observed = spawnSync(process.execPath, [built.file], { env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8',
      timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 4096 });
    assert.equal(observed.error, undefined); assert.equal(observed.signal, null); assert.equal(observed.status, 0);
    assert.equal(observed.stdout, '');
    assert.equal(observed.stderr, 'CLIQ_MCP_ADMIN_LIFECYCLE_V1:http:native_close:entered:-:-\n');
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
