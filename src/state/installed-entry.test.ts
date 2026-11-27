import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';
import { runInNewContext } from 'node:vm';

test('both installed service roles cancel startup before joining and closing its resources', async () => {
  const source = await readFile(new URL('./installed-entry.ts', import.meta.url), 'utf8');
  const start = source.indexOf("  process.once('SIGTERM', () => {");
  const end = source.indexOf('\n  if (credentialRole)', start);
  assert(start >= 0 && end > start);
  const handler = source.slice(start, end);
  for (const mode of ['--installed-keeper', '--installed-supervisor']) {
    const process = new EventEmitter(), events: string[] = [], stop = new AbortController();
    let finish!: () => void;
    const starting = new Promise<void>(resolve => { finish = resolve; });
    const closed = new Promise<void>(resolve => {
      stop.signal.addEventListener('abort', () => events.push('cancel'));
      runInNewContext(handler, { mode, process, starting, serviceStopRequested: false, serviceStartupStop: stop,
        store: undefined, close() { events.push('close'); resolve(); }, report() { assert.fail('unexpected close failure'); } });
    });
    process.emit('SIGTERM');
    assert(stop.signal.aborted); assert.deepEqual(events, ['cancel']);
    events.push('producer-joined'); finish(); await closed;
    assert.deepEqual(events, ['cancel', 'producer-joined', 'close']);
  }
});

test('normal model setup retains real OS termination outside its separately owned prompt', async () => {
  // Execute the entry's actual signal-selection block in a plain child. No
  // installed root, credential action, terminal identity or native role exists.
  const source = await readFile(new URL('./installed-entry.ts', import.meta.url), 'utf8');
  const start = source.indexOf('    const stop = new AbortController(), stopping = () => stop.abort();');
  const end = source.indexOf('\n    try {', start);
  assert(start >= 0 && end > start);
  const setup = source.slice(start, end);
  const cases = [
    { args: ['models', 'add', 'remote', '--profile', 'example'], cancels: false },
    { args: ['models', 'list'], cancels: true },
    { args: ['models', 'add', 'local', '--manifest', '/test/model-manifest.json'], cancels: true },
    { args: ['help'], cancels: false },
    { args: ['run'], cancels: true }
  ];
  for (const { args, cancels } of cases) for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    const child = spawn(process.execPath, ['--input-type=module', '-e', `
      const mode = process.argv[1];
      process.argv.splice(1, 0, 'fixed-image');
      ${setup}
      stop.signal.addEventListener('abort', () => process.stdout.write('aborted\\n', () => process.exit(0)));
      process.stdout.write('ready\\n'); setInterval(() => {}, 1000);
    `, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', error = '', sent = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    try {
      const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
        child.once('error', reject);
        child.stdout.on('data', bytes => {
          output += bytes.toString(); if (output.length > 64) { child.kill('SIGKILL'); return; }
          if (!sent && output.includes('ready\n')) { sent = true; child.kill(signal); }
        });
        child.stderr.on('data', bytes => { error += bytes.toString(); if (error.length > 4096) child.kill('SIGKILL'); });
        child.once('close', (code, signal) => resolve({ code, signal }));
      });
      assert.equal(error, ''); assert.equal(sent, true);
      assert.deepEqual(exit, cancels ? { code: 0, signal: null } : { code: null, signal });
      assert.equal(output, cancels ? 'ready\naborted\n' : 'ready\n');
    } finally { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
  }
});

test('the hidden installed entry refuses ordinary Node before reading roots or creating authority', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-entry-'));
  try {
    const entry = fileURLToPath(new URL('./installed-entry.ts', import.meta.url));
    const loader = fileURLToPath(import.meta.resolve('tsx'));
    const roles = ['keeper', 'supervisor'].flatMap(role => [[`--bootstrap-${role}`], [`--installed-${role}`,
      path.join(fixture, 'state'), 'a'.repeat(64), `0:1:${process.geteuid!()}`]]);
    roles.push(['--installed-client', path.join(fixture, 'state'), 'supervisor', 'status', '--json']);
    roles.push(['--upgrade-source-control', path.join(fixture, 'state'), 'a'.repeat(64)]);
    roles.push(['--installed-models', path.join(fixture, 'state'), 'a'.repeat(64), '0:1:0', 'e30']);
    roles.push([], ['--installed-invalid-role']);
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
