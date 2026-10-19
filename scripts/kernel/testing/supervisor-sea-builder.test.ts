import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { CREDENTIAL_PHASE_DIAGNOSTIC_BANNER, INSTALLED_WORK_DIAGNOSTIC_BANNER,
  prepareSupervisorSeaCarrier, SUPERVISOR_SEA_NODE_VERSION } from './supervisor-sea-builder.js';

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

test('the work banner emits only bounded fixed counters and catches its own closed-pipe errors', async () => {
  for (const closeStderr of [false, true]) {
    const bundled = await build({ stdin: { contents: `
      import { channel } from 'node:diagnostics_channel';
      import { closeSync } from 'node:fs';
      import { INSTALLED_WORK_CHANNEL, observeInstalledWork, noteInstalledWorkRead }
        from './src/state/installed-work-diagnostics.ts';
      if (${closeStderr}) closeSync(2);
      const work = channel(INSTALLED_WORK_CHANNEL);
      work.publish('private-unrecognized-content');
      work.publish(Object.defineProperty({}, 'package', {get(){throw new Error('must not call getters')}}));
      (async()=>{ await observeInstalledWork('package', async()=>{noteInstalledWorkRead(7)});
        process.stdout.write('diagnostic-only-complete') })();
    `, resolveDir: fileURLToPath(new URL('../../..', import.meta.url)) },
    bundle: true, write: false, platform: 'node', format: 'cjs', banner: { js: INSTALLED_WORK_DIAGNOSTIC_BANNER } });
    const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text, '--', 'fixed-image', '--installed-credential'],
      { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, 'diagnostic-only-complete');
    if (closeStderr) assert.equal(child.stderr, '');
    else {
      const rows = child.stderr.trim().split('\n'); assert.equal(rows.length, 2);
      assert(rows.every(row => row.length < 256 && /^CLIQ_INSTALLED_WORK_V1:credential:(?:0|[1-9][0-9]*)(?::(?:0|[1-9][0-9]*)){11}$/u.test(row)));
      const final = rows.at(-1)!.split(':').slice(2).map(Number);
      assert.deepEqual(final.slice(0, 3), [1, 1, 7]); assert.deepEqual(final.slice(4), Array(8).fill(0));
      assert(!child.stderr.includes('private-unrecognized-content'));
    }
  }
});

test('the trusted work subscriber caps output and explicitly reports truncation instead of rounding or emitting arbitrary data', async () => {
  const bundled = await build({ stdin: { contents: `
    import { channel } from 'node:diagnostics_channel';
    import { INSTALLED_WORK_CHANNEL, observeInstalledWork } from './src/state/installed-work-diagnostics.ts';
    const diagnostic = channel(INSTALLED_WORK_CHANNEL);
    const zero = {started:0,completed:0,bytesRead:0,spanElapsedMs:0};
    for (const row of [{...zero,started:NaN},{...zero,started:-1},{...zero,completed:1},
      {...zero,bytesRead:Number.MAX_SAFE_INTEGER+1}])
      diagnostic.publish({package:row,revalidate:zero,createCompare:zero});
    diagnostic.publish({package:zero,revalidate:zero,createCompare:{...zero,bytesRead:1}});
    (async()=>{for(let i=0;i<140;i++)await observeInstalledWork('revalidate',async()=>{});
      process.stdout.write('original-work-complete')})();
  `, resolveDir: fileURLToPath(new URL('../../..', import.meta.url)) },
  bundle: true, write: false, platform: 'node', format: 'cjs', banner: { js: INSTALLED_WORK_DIAGNOSTIC_BANNER } });
  const child = spawnSync(process.execPath, ['-e', bundled.outputFiles[0]!.text, '--', 'fixed-image', '--bootstrap-credential'],
    { encoding: 'utf8', timeout: 5000 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, 'original-work-complete');
  const lines = child.stderr.trim().split('\n'); assert.equal(lines.length, 257);
  assert.equal(lines.at(-1), 'CLIQ_INSTALLED_WORK_V1:bootstrap:truncated');
  assert(lines.every(line => line.length < 256));
});
