import assert from 'node:assert/strict';
import { channel } from 'node:diagnostics_channel';
import fs from 'node:fs';
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { INSTALLED_INSTALL_PHASE_CHANNEL, INSTALLED_INSTALL_PHASES, noteInstalledInstallPhase,
  noteInstalledWorkRead, observeInstalledWork } from '../../../src/state/installed-work-diagnostics.js';
import { decodeInstalledInstallerDiagnostics, encodeInstalledInstallerDiagnostic, observeInstalledInstallerDiagnostics } from './installed-install-diagnostics.js';

const prefix = 'CLIQ_INSTALLED_INSTALL_V1:';
function frame(values: readonly number[]) { return prefix + values.join(':') + '\n'; }
const good = [1, 0, 0, 1, 0, 1024, 0];

test('fixed installer journal uses real returned read bytes and never exposes file bytes or paths', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-install-work-'));
  const filename = path.join(root, 'private-path-must-not-escape'), data = Buffer.from('private-byte-values-must-not-escape');
  let raw = ''; const write = fs.writeSync;
  const mock = t.mock.method(fs, 'writeSync', ((fd: number, value: string) => {
    if (fd === 2 && value.startsWith(prefix)) { raw += value; return Buffer.byteLength(value); }
    return write(fd, value);
  }) as typeof fs.writeSync); syncBuiltinESMExports();
  const stop = observeInstalledInstallerDiagnostics();
  try {
    await writeFile(filename, data, { mode: 0o600 });
    noteInstalledInstallPhase('source_verify');
    await observeInstalledWork('package', async () => {
      const handle = await open(filename, 'r');
      try { const bytes = Buffer.alloc(data.length); const read = await handle.read(bytes, 0, bytes.length, 0); noteInstalledWorkRead(read.bytesRead); }
      finally { await handle.close(); }
    });
    for (const phase of INSTALLED_INSTALL_PHASES.slice(1)) noteInstalledInstallPhase(phase);
    const rows = decodeInstalledInstallerDiagnostics(Buffer.from(raw));
    assert(rows.length >= 16); assert.equal(rows[0]!.phase, 1); assert.equal(rows.at(-1)!.phase, 16);
    assert(rows.at(-1)!.packageBytesRead >= data.length); assert.equal(rows.at(-1)!.packageStarted, rows.at(-1)!.packageSettled);
    assert(!raw.includes(filename)); assert(!raw.includes(data.toString())); assert(!raw.includes('qualified'));
    assert(rows.every(row => Object.isFrozen(row) && Object.values(row).every(value => Number.isSafeInteger(value) && value >= 0)));
  } finally { stop(); mock.mock.restore(); syncBuiltinESMExports(); await rm(root, { recursive: true, force: true }); }
});

for (const kind of ['write_error', 'partial_write', 'clock_error', 'malformed_observation'] as const)
  test(`optional ${kind} is contained within the fixed diagnostic callbacks`, async t => {
    let writes = 0, getters = 0;
    const mock = t.mock.method(fs, 'writeSync', (() => {
      writes++;
      if (kind === 'write_error') throw new Error('private output failure');
      return kind === 'partial_write' ? 1 : 0;
    }) as typeof fs.writeSync); syncBuiltinESMExports();
    const clock = kind === 'clock_error' ? t.mock.method(performance, 'now', () => { throw new Error('private clock failure'); }) : undefined;
    let stop: (() => void) | undefined;
    try {
      stop = observeInstalledInstallerDiagnostics();
      if (kind === 'malformed_observation') channel(INSTALLED_INSTALL_PHASE_CHANNEL).publish(Object.defineProperty({}, 'phase', {
        enumerable: true, get() { getters++; throw new Error('private getter'); } }));
      noteInstalledInstallPhase('source_verify');
      const result = await Promise.resolve('original-result');
      assert.equal(result, 'original-result'); assert.equal(getters, 0);
      if (kind === 'clock_error' || kind === 'malformed_observation') assert.equal(writes, 0);
    } finally { stop?.(); clock?.mock.restore(); mock.mock.restore(); syncBuiltinESMExports(); }
  });

test('no trusted install subscriber means no clock or output work', t => {
  const mock = t.mock.method(performance, 'now', () => { throw new Error('clock must not run'); });
  try { assert.equal(channel(INSTALLED_INSTALL_PHASE_CHANNEL).hasSubscribers, false); noteInstalledInstallPhase('source_verify'); }
  finally { mock.mock.restore(); }
});

test('closed parser accepts only bounded monotonic numeric frames and never returns unrelated stderr', () => {
  const rows = decodeInstalledInstallerDiagnostics(Buffer.from('unrelated private stderr\n' + frame(good) + frame([2, 0, 30031, 1, 1, 2048, 50])));
  assert.equal(rows.length, 2); assert.equal(rows[1]!.elapsedMs, 30031, 'measurement does not change the original 30000ms command deadline');
  assert(!JSON.stringify(rows).includes('unrelated')); assert(Object.isFrozen(rows));
  const bad = [
    frame([0, 0, 0, 0, 0, 0, 0]), frame([17, 0, 0, 0, 0, 0, 0]), frame([1, 1_048_577, 0, 0, 0, 0, 0]),
    frame([1, 0, 0, 1, 2, 0, 0]), frame([1, 0, 0, 1, 0, Number.MAX_SAFE_INTEGER + 1, 0]),
    prefix + '01:0:0:1:0:1:0\n', prefix + '1:0:0:1:0:1:0:private\n', prefix + '1:0:0:1:0:1:private\n',
    frame([2, 1, 3, 1, 1, 10, 2]) + frame([1, 1, 4, 1, 1, 10, 2]),
    frame([2, 1, 3, 1, 1, 10, 2]) + frame([2, 0, 4, 1, 1, 10, 2]),
    frame([2, 1, 3, 1, 1, 10, 2]) + frame([2, 1, 2, 1, 1, 10, 2]),
    frame(good) + prefix + 'truncated\n', frame(good).repeat(257), frame(good).trimEnd(),
  ];
  for (const bytes of bad) assert.deepEqual(decodeInstalledInstallerDiagnostics(Buffer.from(bytes)), []);
  assert.deepEqual(decodeInstalledInstallerDiagnostics(Buffer.alloc(2 * 1024 * 1024 + 1)), []);
});

test('the actual parent scans both original output buffers before any fixed projection and preserves original timeout/assertions', async () => {
  const source = await import('node:fs/promises').then(module => module.readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8'));
  const start = source.indexOf('  const command = (executable: string'), end = source.indexOf('  const success =', start);
  const command = source.slice(start, end);
  assert(start >= 0 && end > start); assert(command.includes('timeout = 30000'));
  const scan = command.indexOf('scanBytes(result.stdout); scanBytes(result.stderr);'), decode = command.indexOf('decodeInstalledInstallerDiagnostics(result.stderr)'), refuse = command.indexOf('assert.equal(result.error, undefined');
  assert(scan >= 0 && decode > scan && refuse > decode);
  const originalFailure = command.indexOf('fixtureCommandJoinDiagnostic(result, timeout, started)');
  assert(originalFailure > scan && originalFailure < decode, 'original elapsed/failure capture precedes diagnostic formatting');
  assert(command.includes('executable === process.execPath && args.length === 4 && args[0] === recipe.installerEntry'));
  assert(command.includes('console.log(encodeInstalledInstallerDiagnostic(diagnostic))'));
  assert(!command.includes('console.log(result.stderr'));
});


test('parent forwarding reproduces only the exact already-scanned frame, including a key-name needle', async () => {
  const { createCredentialSecretScanner } = await import('./credential-secret-scan.js');
  const needle = Buffer.from('packageStarted');
  const scanner = createCredentialSecretScanner([needle], { maxBytes: 65536, maxStreams: 8 });
  try {
    const stdout = Buffer.from('{}\n'), stderr = Buffer.from(frame(good));
    for (const bytes of [stdout, stderr]) {
      const stream = scanner.openStream(); try { stream.scan(bytes); } finally { stream.close(); }
    }
    const projected = decodeInstalledInstallerDiagnostics(stderr);
    assert.equal(projected.length, 1);
    const replay = Buffer.from(encodeInstalledInstallerDiagnostic(projected[0]!) + '\n');
    assert.deepEqual(replay, stderr, 'the actual formatter emits no byte that was absent from the original scanned frame');
    assert.equal(replay.includes(needle), false); assert.equal(scanner.stats().streamsOpened, 2);
    assert.equal(scanner.stats().streamsClosed, 2); assert.equal(scanner.stats().matched, false);
    const poisoned = Object.defineProperty({}, 'phase', { enumerable: true, get() { throw new Error('must not execute'); } });
    assert.throws(() => encodeInstalledInstallerDiagnostic(poisoned as never));
  } finally { scanner.close(); needle.fill(0); }
});
