import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { duplicateClientStdio, loadNativeStateOwner } from '../state/native-owner.js';
import { openClientStdio } from './stdio.js';

test('stdio factory preserves ordinary caller streams without reading a numeric descriptor', async () => {
  const native = await loadNativeStateOwner(), output = new PassThrough(), diagnostic = new PassThrough(), input = new PassThrough();
  for (const stream of [output, diagnostic]) Object.defineProperty(stream, 'fd', { get() { throw new Error('caller fd must not be inspected'); } });
  const owned = await openClientStdio(native, { input, output, diagnostic, workspacePath: '/workspace' });
  assert.equal(owned.io.output, output); assert.equal(owned.io.diagnostic, diagnostic);
  await owned.close(); await owned.close();
  assert.equal(output.destroyed, false); assert.equal(diagnostic.destroyed, false); assert.equal(input.destroyed, false);
  assert.throws(() => duplicateClientStdio({ ...native }, 'stdout'), /lacks owned client stdio/u);
  output.destroy(); diagnostic.destroy(); input.destroy();
});

test('actual pipe and socket duplicates preserve original flags, CLOEXEC and the original writer after close', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-client-stdio-'));
  try {
    const executable = path.join(directory, 'component');
    const source = fileURLToPath(new URL('../../native/state-owner/client-stdio-component.c', import.meta.url));
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-o', executable], { timeout: 30000, maxBuffer: 65536 });
    assert.equal(compiled.error, undefined); assert.equal(compiled.signal, null); assert.equal(compiled.status, 0, compiled.stderr.toString());
    const result = spawnSync(executable, [], { timeout: 10000, maxBuffer: 65536 });
    assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr.toString());
    assert.equal(result.stderr.length, 0);
    assert.equal(result.stdout.toString(), 'actual pipe/socket dup, flags, CLOEXEC, close, original-writer and child joins: 4 passed\n');
  } finally { await rm(directory, { recursive: true }); }
});
