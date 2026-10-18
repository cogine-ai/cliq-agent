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
    stderrBytes: stderr.length, markerStatus: 'absent', reportedErrorCodes: ['ERR_MODULE_NOT_FOUND', 'ENOENT'] });
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
      stderrBytes: 26, markerStatus, reportedErrorCodes: [] });
  }
  const error = new Error('oversized');
  recordGuestVerifierBoundaryFailure(error, 'infra_failed', Buffer.alloc(65_536), Buffer.from('x'));
  assert.equal(readGuestVerifierOutputFailure(error), undefined);
});
