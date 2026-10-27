import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import * as builder from './supervisor-sea-builder.js';

test('the complete real installed application preserves ESM and Ink within one Node-only embedded asset', async () => {
  const compile = (builder as Record<string, unknown>).buildSupervisorSeaApplication;
  assert.equal(typeof compile, 'function');
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-sea-app-'));
  try {
    const result = await (compile as (input: {fixture: string; entryPoint: string; variant: string}) =>
      Promise<{file: string; bytes: number; imports: readonly string[]; sources: readonly string[]}>)(
      { fixture, entryPoint: fileURLToPath(new URL('../../../src/state/installed-entry.ts', import.meta.url)), variant: 'actual' });
    assert.equal(result.file, path.join(fixture, 'actual.mjs'));
    assert(result.bytes > 0 && result.bytes <= 64 * 1024 * 1024);
    assert(result.imports.length > 0 && result.imports.every(name => name.startsWith('node:')));
    const source = await readFile(result.file, 'utf8');
    assert(result.sources.some(name => name.endsWith('yoga-layout/dist/src/index.js')));
    assert(result.sources.some(name => name.endsWith('ink/build/reconciler.js')));
    assert.match(source, /await /u, 'the complete asynchronous application remains ESM');
    assert(!result.sources.some(name => name.endsWith('ink/build/devtools.js')),
      'the existing pinned production-only Ink closure excludes the optional devtools module');
    assert.match(source, /cliqSeaCreateRequire\(process\.execPath\)/u);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
