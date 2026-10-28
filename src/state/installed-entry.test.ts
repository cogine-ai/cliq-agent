import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

test('the hidden installed entry refuses ordinary Node before reading roots or creating authority', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-entry-'));
  try {
    const entry = fileURLToPath(new URL('./installed-entry.ts', import.meta.url));
    const loader = fileURLToPath(import.meta.resolve('tsx'));
    const roles = ['keeper', 'supervisor'].flatMap(role => [[`--bootstrap-${role}`], [`--installed-${role}`,
      path.join(fixture, 'state'), 'a'.repeat(64), `0:1:${process.geteuid!()}`]]);
    roles.push(['--installed-client', path.join(fixture, 'state'), 'supervisor', 'status', '--json']);
    roles.push(['--upgrade-source-control', path.join(fixture, 'state'), 'a'.repeat(64)]);
    for (const args of roles) {
        const result = spawnSync(process.execPath, ['--import', loader, entry, ...args], {
          cwd: fixture, env: { PATH: process.env.PATH }, encoding: 'utf8',
          timeout: 30_000, maxBuffer: 128 * 1024,
        });
        assert.equal(result.error, undefined);
        assert.equal(result.status, 1);
        assert.equal(result.signal, null);
        const diagnostics = result.stderr.trim().split('\n').filter(line => line.startsWith('{')).map(line => JSON.parse(line));
        assert(diagnostics.some(value => value.scope === 'installed-read-startup' && value.message === 'expected the installed Linux SEA'));
        assert.deepEqual(await readdir(fixture), [], 'untrusted role locators must not create even an installation or StateRoot');
    }
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
