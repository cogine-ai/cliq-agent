// Pure diagnostic projection only; these bytes are not guest/native evidence.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { readGuestVerifierBoundaryFailure, recordGuestVerifierBoundaryFailure } from './guest-verifier-diagnostics.js';

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
