// Pure diagnostic projection only; these bytes are not guest/native evidence.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { readGuestVerifierBoundaryFailure, readGuestVerifierOutputFailure, recordGuestVerifierBoundaryFailure } from './guest-verifier-diagnostics.js';

test('a failed boundary assertion retains only its last fixed stdout stage and actual outcome', () => {
  const failure = new Error('unretained TAP and arbitrary diagnostic text');
  const stdout = Buffer.from('TAP version 13\n# CLIQ_GUEST_BOUNDARY_V1:runtime_identity\n'
    + '# CLIQ_GUEST_BOUNDARY_V1:source_read\nnot ok 1 - unretained test text\n');
  recordGuestVerifierBoundaryFailure(failure, 'assertion_failed', stdout);
  assert.deepEqual(readGuestVerifierBoundaryFailure(failure), { stage: 'source_read', outcome: 'assertion_failed' });
  assert.equal(readGuestVerifierBoundaryFailure(new Error('unrelated')), undefined);
  assert.equal(readGuestVerifierBoundaryFailure({ stage: 'source_read', outcome: 'assertion_failed' }), undefined);
});

test('the fixed projection consumes actual Node test-runner stdout without retaining TAP', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-guest-boundary-diagnostic-'));
  try {
    const filename = path.join(root, 'boundary.test.mjs');
    await writeFile(filename, `import test from 'node:test'; import assert from 'node:assert/strict'; import fs from 'node:fs';
test('unretained diagnostic fixture', () => { fs.writeSync(1, 'CLIQ_GUEST_BOUNDARY_V1:runtime_identity\\n'); assert.equal(1, 2); });`);
    // A nested host test must not inherit the outer runner's private IPC mode.
    const childEnv = { ...process.env }; delete childEnv.NODE_TEST_CONTEXT;
    const actual = spawnSync(process.execPath, ['--test', '--test-reporter=tap', filename],
      { env: childEnv, timeout: 5000, maxBuffer: 65_536 });
    assert.equal(actual.error, undefined); assert.equal(actual.status, 1);
    const error = new Error('the original outcome assertion');
    recordGuestVerifierBoundaryFailure(error, 'assertion_failed', actual.stdout);
    assert.deepEqual(readGuestVerifierBoundaryFailure(error), { stage: 'runtime_identity', outcome: 'assertion_failed' });
    const bootstrap = path.join(root, 'bootstrap.test.mjs');
    await writeFile(bootstrap, "import './absent-owned-bootstrap.mjs';\n");
    const refused = spawnSync(process.execPath, ['--test', '--test-reporter=tap', bootstrap],
      { env: childEnv, timeout: 5000, maxBuffer: 65_536 });
    assert.equal(refused.error, undefined); assert.equal(refused.status, 1);
    const original = new Error('original bootstrap outcome assertion');
    recordGuestVerifierBoundaryFailure(original, 'assertion_failed', refused.stdout, refused.stderr);
    assert.equal(readGuestVerifierBoundaryFailure(original), undefined);
    const diagnostic = readGuestVerifierOutputFailure(original);
    assert.equal(diagnostic?.markerStatus, 'absent');
    assert.ok(diagnostic.reportedErrorCodes.includes('ERR_MODULE_NOT_FOUND'));
    assert.equal(diagnostic.stdoutBytes, refused.stdout.length); assert.equal(diagnostic.stderrBytes, refused.stderr.length);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('a real Node test-runner pre-body spawn failure projects only the fixed executable category', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-guest-spawn-diagnostic-'));
  try {
    const filename = path.join(root, 'never-started.test.mjs');
    await writeFile(filename, "import fs from 'node:fs'; fs.writeSync(1, 'CLIQ_GUEST_BOUNDARY_V1:runtime_identity\\n');\n");
    const childEnv = { ...process.env }; delete childEnv.NODE_TEST_CONTEXT;
    // This deliberately missing test-only alias makes the actual --test
    // runner fail its child spawn, before reading the test body. It changes
    // no production guest argv, native recipe, executable or authority.
    const preload = path.join(root, 'missing-executable.cjs');
    await writeFile(preload, "process.execPath = '/usr/bin/node (deleted)';\n");
    const actual = spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--require', preload, filename],
      { env: childEnv, timeout: 5000, maxBuffer: 65_536 });
    assert.equal(actual.error, undefined); assert.equal(actual.status, 1);
    assert.equal(actual.stdout.includes('CLIQ_GUEST_BOUNDARY_V1:'), false);
    assert.equal(actual.stderr.length, 0);
    assert.match(actual.stdout.toString('utf8'), /\bENOENT\b/u);
    assert.equal(/^ +error: 'spawn \/usr\/bin\/node \(deleted\) ENOENT'\r?$/mu.test(actual.stdout.toString('utf8')), true,
      'the real TAP contains its exact reported spawn error');
    assert.equal(/^ +code: 'ENOENT'\r?$/mu.test(actual.stdout.toString('utf8')), true,
      'the real TAP contains the failed spawn code');
    const original = new Error('original outcome assertion');
    recordGuestVerifierBoundaryFailure(original, 'assertion_failed', actual.stdout, actual.stderr);
    assert.equal(readGuestVerifierBoundaryFailure(original), undefined);
    assert.deepEqual(readGuestVerifierOutputFailure(original), { outcome: 'assertion_failed', stdoutBytes: actual.stdout.length,
      stderrBytes: 0, markerStatus: 'absent', reportedErrorCodes: ['ENOENT'],
      spawnSyscall: 'spawn', spawnTarget: 'deleted_canonical_node' });
    assert.equal(original.message, 'original outcome assertion');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('spawn diagnostics recognize only complete fixed Node TAP targets without retaining a pathname', () => {
  for (const [target, spawnTarget] of [['/usr/bin/node', 'canonical_node'],
    ['/usr/bin/node (deleted)', 'deleted_canonical_node'], ['/bindfileAB12cd (deleted)', 'deleted_bindfile']] as const) {
    const error = new Error('original outcome assertion');
    const stdout = Buffer.from(`  ---\n  error: 'spawn ${target} ENOENT'\n  code: 'ENOENT'\n  ...\n`);
    recordGuestVerifierBoundaryFailure(error, 'assertion_failed', stdout, Buffer.alloc(0));
    assert.deepEqual(readGuestVerifierOutputFailure(error), { outcome: 'assertion_failed', stdoutBytes: stdout.length,
      stderrBytes: 0, markerStatus: 'absent', reportedErrorCodes: ['ENOENT'], spawnSyscall: 'spawn', spawnTarget });
    assert.equal(JSON.stringify(readGuestVerifierOutputFailure(error)).includes(target), false);
  }
});

test('unknown, malicious, conflicting and partial TAP cannot become a fixed spawn target', () => {
  const known = "  ---\n  error: 'spawn /usr/bin/node (deleted) ENOENT'\n  code: 'ENOENT'\n  ...\n";
  const foreign = "  ---\n  error: 'spawn /unretained-private-path ENOENT'\n  code: 'ENOENT'\n  ...\n";
  for (const stdout of [foreign, known + foreign, known + known, known.replace("  code: 'ENOENT'", "  code: 'EPERM'"),
    known.replace("  code: 'ENOENT'", "  code: 'ENOENT'\n  code: 'ENOENT'"),
    known.replace(' (deleted)', ' (deleted)/unexpected'), known.replace(' (deleted)', String.raw`\x20(deleted)`),
    known.replace('  ...\n', '  ...'), known.replace('  ...\n', ''),
    known.replace(/^/gmu, '# '), "Error: spawn /usr/bin/node (deleted) ENOENT\n",
    known.replace('/usr/bin/node (deleted)', '/bindfileAB12cd (deleted)/unexpected'),
    known.replace('/usr/bin/node (deleted)', '/bindfileTOO_LONG (deleted)'),
    known.replace('/usr/bin/node (deleted)', '/' + 'x'.repeat(256)), known + known.replace('  ...\n', ''),
    known.replace('  ---\n', '---\n'), known.replace("  error:", "    error:"),
    known.replace('  ---\n', '  ---\n    ---\n')]) {
    const original = new Error('original outcome assertion');
    recordGuestVerifierBoundaryFailure(original, 'assertion_failed', Buffer.from(stdout), Buffer.alloc(0));
    const result = readGuestVerifierOutputFailure(original);
    assert.equal(result?.spawnSyscall, 'other_or_absent'); assert.equal(result?.spawnTarget, 'other_or_absent');
    assert.equal(JSON.stringify(result).includes('/unretained-private-path'), false);
    assert.equal(original.message, 'original outcome assertion');
  }
  for (const [stdout, stderr] of [[Buffer.concat([Buffer.from(known), Buffer.from([0xff])]), Buffer.alloc(0)],
    [Buffer.from(known), Buffer.from([0xff])]] as const) {
    const original = new Error('original outcome assertion');
    recordGuestVerifierBoundaryFailure(original, 'assertion_failed', stdout, stderr);
    assert.equal(readGuestVerifierOutputFailure(original)?.spawnSyscall, 'other_or_absent');
    assert.equal(readGuestVerifierOutputFailure(original)?.spawnTarget, 'other_or_absent');
  }
  const oversized = new Error('original oversized output');
  recordGuestVerifierBoundaryFailure(oversized, 'assertion_failed', Buffer.from(known), Buffer.alloc(65_536));
  assert.equal(readGuestVerifierOutputFailure(oversized), undefined);
});

test('unknown, incomplete, duplicated, skipped and reordered markers cannot become a stage', () => {
  for (const stdout of [
    '', 'TAP version 13\nnot ok 1\n', 'CLIQ_GUEST_BOUNDARY_V1:runtime_identity',
    'CLIQ_GUEST_BOUNDARY_V1:runtime_identity\n# CLIQ_GUEST_BOUNDARY_V1:source_read',
    'CLIQ_GUEST_BOUNDARY_V1:untrusted_text\n', 'CLIQ_GUEST_BOUNDARY_V1:source_read\n',
    'CLIQ_GUEST_BOUNDARY_V1:runtime_identity\nCLIQ_GUEST_BOUNDARY_V1:runtime_identity\n',
    'CLIQ_GUEST_BOUNDARY_V1:runtime_identity\nCLIQ_GUEST_BOUNDARY_V1:environment\n',
    'CLIQ_GUEST_BOUNDARY_V1:runtime_identity\nCLIQ_GUEST_BOUNDARY_V1:source_read\nCLIQ_GUEST_BOUNDARY_V1:runtime_identity\n',
  ]) {
    const error = new Error('unretained');
    recordGuestVerifierBoundaryFailure(error, 'infra_failed', Buffer.from(stdout));
    assert.equal(readGuestVerifierBoundaryFailure(error), undefined);
  }
  for (const stdout of [Buffer.concat([Buffer.from('CLIQ_GUEST_BOUNDARY_V1:runtime_identity\n'), Buffer.from([0xff])]),
    Buffer.concat([Buffer.from('CLIQ_GUEST_BOUNDARY_V1:runtime_identity\n'), Buffer.alloc(65_536)])]) {
    const error = new Error('unretained');
    recordGuestVerifierBoundaryFailure(error, 'infra_failed', stdout);
    assert.equal(readGuestVerifierBoundaryFailure(error), undefined);
  }
});

test('a real closed stdout descriptor cannot let the guest marker replace assertion execution', async () => {
  const source = await readFile(new URL('./guest-verifier-native.ts', import.meta.url), 'utf8');
  const literal = /const successfulScript = (`[\s\S]*?`);/u.exec(source)?.[1];
  assert.ok(literal);
  const script = runInNewContext(literal) as string;
  const boundary = script.split('\n').find(line => line.startsWith('  const boundary ='));
  assert.ok(boundary);
  const child = spawnSync(process.execPath, ['--input-type=module', '--eval', `import fs from 'node:fs';
${boundary}
fs.closeSync(1);
try { fs.fstatSync(1); process.exit(4); } catch (error) { if (error.code !== 'EBADF') throw error; }
boundary('runtime_identity');
const original = new Error('source-owned original assertion');
try { throw original; } catch (error) { if (error !== original) process.exit(3); }
fs.writeSync(2, 'assertion_reached');`], { timeout: 5000, maxBuffer: 65_536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0);
  assert.equal(child.stdout.length, 0); assert.equal(child.stderr.toString('utf8'), 'assertion_reached');
});

test('a failure before the callback retains only bounded counts, marker status and finite error codes', () => {
  const error = new Error('original outcome assertion');
  const stdout = Buffer.from('unretained path and test name\n');
  const stderr = Buffer.from("Error [ERR_MODULE_NOT_FOUND]: unretained module/path and secret-like text\ncode: 'ENOENT'\n");
  recordGuestVerifierBoundaryFailure(error, 'assertion_failed', stdout, stderr);
  assert.equal(readGuestVerifierBoundaryFailure(error), undefined);
  assert.deepEqual(readGuestVerifierOutputFailure(error), { outcome: 'assertion_failed', stdoutBytes: stdout.length,
    stderrBytes: stderr.length, markerStatus: 'absent', reportedErrorCodes: ['ERR_MODULE_NOT_FOUND', 'ENOENT'],
    spawnSyscall: 'other_or_absent', spawnTarget: 'other_or_absent' });
  assert.equal(readGuestVerifierOutputFailure(new Error('unrelated')), undefined);
  assert.equal(readGuestVerifierOutputFailure({ outputFailure: readGuestVerifierOutputFailure(error) }), undefined);
});

test('malformed markers, UTF-8 and oversized output do not become a valid boundary or arbitrary diagnostic', () => {
  for (const [stdout, markerStatus] of [
    [Buffer.from('CLIQ_GUEST_BOUNDARY_V1:source_read\n'), 'invalid_sequence'],
    [Buffer.from([0xff]), 'invalid_utf8'],
    [Buffer.from('CLIQ_GUEST_BOUNDARY_V1:runtime_identity\n'), 'ordered'],
  ] as const) {
    const error = new Error('original');
    recordGuestVerifierBoundaryFailure(error, 'infra_failed', stdout, Buffer.from('code: UNLISTED_NATIVE_TEXT'));
    assert.deepEqual(readGuestVerifierOutputFailure(error), { outcome: 'infra_failed', stdoutBytes: stdout.length,
      stderrBytes: 26, markerStatus, reportedErrorCodes: [], spawnSyscall: 'other_or_absent', spawnTarget: 'other_or_absent' });
  }
  const error = new Error('oversized');
  recordGuestVerifierBoundaryFailure(error, 'infra_failed', Buffer.alloc(65_536), Buffer.from('x'));
  assert.equal(readGuestVerifierOutputFailure(error), undefined);
});
