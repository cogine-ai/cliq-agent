import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { CREDENTIAL_PHASE_DIAGNOSTIC_BANNER, prepareSupervisorSeaCarrier, SUPERVISOR_SEA_NODE_VERSION } from './supervisor-sea-builder.js';

test('carrier preparation refuses an existing extraction directory without adopting or changing it', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-existing-carrier-'));
  try {
    const name = `node-v${SUPERVISOR_SEA_NODE_VERSION}-${process.platform}-${process.arch}`;
    const nodeRoot = path.join(fixture, name);
    await mkdir(nodeRoot, { mode: 0o700 });
    const sentinel = path.join(nodeRoot, 'existing-data');
    await writeFile(sentinel, 'existing carrier directory must remain untouched\n', { flag: 'wx', mode: 0o400 });
    const rootBefore = await lstat(nodeRoot, { bigint: true });
    const fileBefore = await lstat(sentinel, { bigint: true });
    // Existing local source is deliberately not an archive. The fresh-root
    // precondition must refuse before reading it, downloading, or extracting.
    await assert.rejects(prepareSupervisorSeaCarrier(fixture, fileURLToPath(import.meta.url)),
      /carrier extraction directory must not already exist/);
    assert.deepEqual(await lstat(nodeRoot, { bigint: true }), rootBefore);
    assert.deepEqual(await lstat(sentinel, { bigint: true }), fileBefore);
    assert.equal(await readFile(sentinel, 'utf8'), 'existing carrier directory must remain untouched\n');
    assert.deepEqual(await readdir(fixture), [name]);
    assert.deepEqual(await readdir(nodeRoot), ['existing-data']);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

// Actual diagnostic code generation and Node channel execution only. This does
// not replace the installed image's credential, manager or native qualification.
test('the fixed fixture banner writes only known credential phase markers and contains its own output errors', async () => {
  for (const closeStderr of [false, true]) {
    const bundled = await build({ stdin: { contents: `
      import { channel } from 'node:diagnostics_channel';
      import { closeSync } from 'node:fs';
      import { INSTALLED_CREDENTIAL_PHASE_CHANNEL, INSTALLED_CREDENTIAL_PHASES, noteInstalledCredentialPhase }
        from './src/state/installed-diagnostics.ts';
      if (${closeStderr}) closeSync(2);
      for (const phase of INSTALLED_CREDENTIAL_PHASES) noteInstalledCredentialPhase(phase);
      channel(INSTALLED_CREDENTIAL_PHASE_CHANNEL).publish('untrusted-private-value');
      channel(INSTALLED_CREDENTIAL_PHASE_CHANNEL).publish(Object.defineProperty({}, 'phase', {
        get() { throw new Error('must not inspect untrusted properties'); }
      }));
      process.stdout.write('diagnostic-only-complete');
    `, resolveDir: fileURLToPath(new URL('../../..', import.meta.url)) },
    bundle: true, write: false, platform: 'node', format: 'cjs', banner: { js: CREDENTIAL_PHASE_DIAGNOSTIC_BANNER } });
    const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, 'diagnostic-only-complete');
    assert.equal(child.stderr, closeStderr ? '' : ['open_selected', 'history', 'first_supervisor', 'secret_input',
      'second_supervisor', 'platform_store', 'finalize', 'retire'].map(phase => `CLIQ_CREDENTIAL_PHASE_V1:${phase}\n`).join(''));
  }
});
