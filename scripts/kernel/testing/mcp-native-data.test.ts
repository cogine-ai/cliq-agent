// Actual compiled Linux C regressions. These private fixtures exercise data
// parsers and screens; they never create a native owner, StateOwner, Run,
// credential, connection, dispatch receipt or physical retirement authority.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const linux = process.platform === 'linux' && process.arch === 'x64';
const repository = fileURLToPath(new URL('../../..', import.meta.url));
const environment = { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' };

function compile(args: string[]): void {
  const result = spawnSync('/usr/bin/cc', args, { cwd: repository, env: environment,
    encoding: 'utf8', timeout: 60_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
  assert.equal(result.error, undefined, 'the original sixty-second compiler must actually join');
  assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr);
}

test('actual C Admin lifecycle data rejects truncated, foreign and substituted binary chains', { skip: !linux }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-mcp-admin-data-'));
  try {
    const binary = path.join(directory, 'admin-protocol');
    compile(['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      'native/linux/mcp-http-admin-protocol-fixture.c', '-o', binary]);
    await chmod(binary, 0o500);
    const result = spawnSync(binary, [], { env: environment, encoding: 'utf8', timeout: 10_000, maxBuffer: 65_536 });
    assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('actual C MCP screens preserve depth, byte and NoEcho boundaries through cancelled received-data screening', { skip: !linux }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-mcp-screen-data-'));
  try {
    const dependencies = spawnSync('/usr/bin/pkg-config', ['--cflags', '--libs', 'gio-2.0', 'openssl'],
      { env: environment, encoding: 'utf8', timeout: 10_000, maxBuffer: 8192 });
    assert.equal(dependencies.error, undefined); assert.equal(dependencies.signal, null);
    assert.equal(dependencies.status, 0, dependencies.stderr);
    const binary = path.join(directory, 'mcp-parser.node');
    const headers = path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node');
    // The selected broker already requires this exact unused-function flag:
    // platform and credential mechanisms share one private compilation unit.
    compile(['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
      '-shared', '-fPIC', '-pthread', '-I', headers, 'native/linux/mcp-http-native-fixture.c',
      '-o', binary, ...dependencies.stdout.trim().split(/\s+/u)]);
    await chmod(binary, 0o500);
    const binding = createRequire(import.meta.url)(binary) as {
      interfaceVersion: number; runMcpNativeFixture(): { checks: number };
    };
    assert.equal(binding.interfaceVersion, 1);
    // No prepareAdminHttp/prepareRunHttp production factory is invoked.
    assert.deepEqual(binding.runMcpNativeFixture(), { checks: 22 });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
