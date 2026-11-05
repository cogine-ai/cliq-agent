// Real compiled Linux data checks and a plain owned fixture process. No
// prepare factory, native scope, StateOwner, SQL, dispatch or retirement
// authority is used. The fixture never attests an earlier effect execution.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { identityHash } from '../../../src/kernel/identity.js';
import { compileInputSchema } from '../../../src/tools/input-schema.js';

const linux = process.platform === 'linux' && process.arch === 'x64';
const repository = fileURLToPath(new URL('../../..', import.meta.url));
const environment = { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' };

test('actual C stdio fixed recipe, JSON lines and cancelled received-data NoEcho remain bounded', { skip: !linux }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-mcp-stdio-data-'));
  try {
    const dependencies = spawnSync('/usr/bin/pkg-config', ['--cflags', '--libs', 'gio-2.0', 'openssl'],
      { env: environment, encoding: 'utf8', timeout: 10_000, maxBuffer: 8192 });
    assert.equal(dependencies.error, undefined); assert.equal(dependencies.signal, null);
    assert.equal(dependencies.status, 0, dependencies.stderr);
    const binary = path.join(directory, 'mcp-stdio-data.node');
    const headers = path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node');
    const compiled = spawnSync('/usr/bin/cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
      '-shared', '-fPIC', '-pthread', '-I', headers, 'native/linux/mcp-stdio-native-fixture.c',
      '-o', binary, ...dependencies.stdout.trim().split(/\s+/u)], { cwd: repository, env: environment,
      encoding: 'utf8', timeout: 60_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
    assert.equal(compiled.error, undefined); assert.equal(compiled.signal, null); assert.equal(compiled.status, 0, compiled.stderr);
    await chmod(binary, 0o500);
    const binding = createRequire(import.meta.url)(binary) as {
      interfaceVersion: number;
      runMcpStdioDataFixture(): { checks: number; factoryExecuted: false; authorityExecuted: false };
      runMcpStdioRecoveryDataFixture(): { checks: number; factoryExecuted: false; authorityExecuted: false };
    };
    assert.equal(binding.interfaceVersion, 1);
    assert.deepEqual(binding.runMcpStdioDataFixture(), { checks: 41, factoryExecuted: false, authorityExecuted: false });
    assert.deepEqual(binding.runMcpStdioRecoveryDataFixture(), { checks: 22, factoryExecuted: false, authorityExecuted: false });
    const server = path.join(directory, 'mcp-static-server');
    const serverBuild = spawnSync('/usr/bin/musl-gcc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
      '-fno-ident', '-ffile-prefix-map=' + repository + '=.', '-Wl,--build-id=none', '-s',
      'native/linux/mcp-stdio-server-fixture.c', '-o', server], { cwd: repository, env: environment,
      encoding: 'utf8', timeout: 60_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
    assert.equal(serverBuild.error, undefined); assert.equal(serverBuild.signal, null); assert.equal(serverBuild.status, 0, serverBuild.stderr);
    await chmod(server, 0o500);
    const key = identityHash('cliq-mcp-tool-idempotency-v1', 'run', 'operation', 'a'.repeat(64), 'effect');
    const invalidKeys = ['b'.repeat(64), key.slice(1), key + '=', 'A'.repeat(42) + 'B'];
    for (const mode of ['immutable_noop_profile', '--immutable-noop-effect-no-reply', '--immutable-noop-effect-exit-no-reply',
      '--immutable-noop-effect-and-status-no-reply'])
      for (const operation of ['stdio_noop_effect', 'stdio_noop_status']) for (const candidate of [key, ...invalidKeys]) {
      const omitReply = mode === '--immutable-noop-effect-and-status-no-reply' ||
        (mode !== 'immutable_noop_profile' && operation === 'stdio_noop_effect');
      const responsivePing = omitReply && mode !== '--immutable-noop-effect-exit-no-reply';
      let input = [
        { id: 1, jsonrpc: '2.0', method: 'initialize' },
        { jsonrpc: '2.0', method: 'notifications/initialized' },
        { id: 2, jsonrpc: '2.0', method: 'tools/list' },
        { id: 3, jsonrpc: '2.0', method: 'tools/call', params: { arguments: { idempotencyKey: candidate }, name: operation } }
      ].map(value => JSON.stringify(value)).join('\n') + '\n';
      if (candidate === key && responsivePing)
        input += JSON.stringify({ id: 'fixture-noop-ping', jsonrpc: '2.0', method: 'ping' }) + '\n';
      const child = spawnSync(server, [mode], { env: environment, input,
        encoding: 'utf8', timeout: 10_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
      assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.stderr, '');
      assert.equal(child.status, candidate === key ? 0 : 65);
      const replies = child.stdout.trimEnd().split('\n').map(line => JSON.parse(line));
      const selected = replies[1].result.tools.filter((tool: { name: string }) => tool.name === operation);
      assert.equal(selected.length, 1);
      const validate = compileInputSchema(selected[0].inputSchema);
      assert.equal(validate({ idempotencyKey: candidate }) !== undefined, candidate === key);
      assert.equal(replies.length, candidate === key && (!omitReply || responsivePing) ? 3 : 2);
      if (candidate === key && responsivePing) {
        assert.deepEqual(replies.map(reply => reply.id), [1, 2, 'fixture-noop-ping']);
        assert.deepEqual(replies[2], { id: 'fixture-noop-ping', jsonrpc: '2.0', result: {} });
      } else if (candidate === key && !omitReply) assert.deepEqual(replies[2].result.structuredContent, {
        originalExecutionObserved: false, profileClass: 'immutable_preexisting_noop_target', targetState: 'preexisting_noop'
      });
    }
    const unknownMode = spawnSync(server, ['--unknown-noop-mode'], { env: environment, input: '',
      encoding: 'utf8', timeout: 10_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
    assert.equal(unknownMode.error, undefined); assert.equal(unknownMode.signal, null);
    assert.equal(unknownMode.status, 64); assert.equal(unknownMode.stdout, ''); assert.equal(unknownMode.stderr, '');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

