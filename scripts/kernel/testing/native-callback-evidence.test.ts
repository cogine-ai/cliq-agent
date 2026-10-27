// Inert parser/serialization inputs only. No native module is built or loaded.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { CALLBACK_CASES, CALLBACK_IDLE_MARKER, CALLBACK_OTHER_MARKER, readNativeCallbackEvidence } from './native-callback-evidence.js';

function fixture(mode: 'baseline' | 'candidate') {
  const baseline = mode === 'baseline';
  const stdout = Buffer.from('TAP version 13\n' + CALLBACK_CASES.map((name, index) => {
    const passed = !baseline || index === 0;
    return `${passed ? 'ok' : 'not ok'} ${index + 1} - ${name}\n` + (passed ? '' : `  ---\n  error: |-\n    ${CALLBACK_IDLE_MARKER}\n  ...\n`);
  }).join('') + '# ' + JSON.stringify({ diagnosticOnly: true, actualInspectionEntered: true, cancelJoinedWithin1500ms: true,
    actualInspectionConnectionRetired: true, childrenJoined: true, installedI1Qualified: false }) + '\n# ' +
    JSON.stringify({ diagnosticOnly: true, actualPreparationEntered: true, closeJoinedWithin1500ms: true,
      actualPreparationConnectionRetired: true, childrenJoined: true, installedI1Qualified: false }) +
    `\n1..4\n# tests 4\n# pass ${baseline ? 1 : 4}\n# fail ${baseline ? 3 : 0}\n# cancelled 0\n# skipped 0\n`);
  return { mode, stdout, stderr: Buffer.alloc(0), code: baseline ? 1 : 0, signal: null, joined: true };
}
test('closed callback evidence requires every original case and both actual-join report shapes', () => {
  for (const mode of ['baseline', 'candidate'] as const) {
    const result = readNativeCallbackEvidence(fixture(mode));
    assert.equal(result.mode, mode); assert.equal(result.installedI1Qualified, false);
    assert.equal(result.idleDeliveryRefusals, mode === 'baseline' ? 3 : 0);
  }
});
test('unknown failure, missing proof, altered counters and unjoined collectors never become expected RED or GREEN', () => {
  const baseline = fixture('baseline'), candidate = fixture('candidate');
  for (const input of [
    { ...baseline, stdout: Buffer.from(baseline.stdout.toString().replace(CALLBACK_IDLE_MARKER, CALLBACK_OTHER_MARKER)) },
    { ...baseline, stdout: Buffer.from(baseline.stdout.toString().replace(CALLBACK_IDLE_MARKER, 'async-hook label absent')) },
    { ...baseline, stdout: Buffer.from(baseline.stdout.toString().replace('"childrenJoined":true', '"childrenJoined":false')) },
    { ...baseline, stdout: Buffer.from(baseline.stdout.toString().replace('"actualPreparationEntered":true', '"actualPreparationEntered":false')) },
    { ...baseline, stdout: Buffer.from(baseline.stdout.toString().replace('"actualInspectionConnectionRetired":true', '"actualInspectionConnectionRetired":false')) },
    { ...baseline, stdout: Buffer.from(baseline.stdout.toString().replace('"closeJoinedWithin1500ms":true', '"closeJoinedWithin1500ms":false')) },
    { ...baseline, stdout: Buffer.from(baseline.stdout.toString().replace('# fail 3', '# fail 2')) },
    { ...baseline, stdout: Buffer.from(baseline.stdout.toString().replace(CALLBACK_CASES[0], 'other case')) },
    { ...baseline, stdout: Buffer.from(baseline.stdout.toString().replace('"diagnosticOnly":true', '"diagnosticOnly":true,"extra":true')) },
    { ...baseline, code: 0 }, { ...baseline, signal: 'SIGKILL' }, { ...baseline, joined: false },
    { ...candidate, code: 1 }, { ...candidate, stderr: Buffer.from('unexpected original bytes') },
    { ...candidate, stdout: Buffer.alloc(2 * 1024 * 1024 + 1) },
  ]) assert.throws(() => readNativeCallbackEvidence(input));
});
test('the actual Node TAP serializer retains the fixed sentinel as one exact diagnostic line', async () => {
  // This tiny complete program tests Node formatting only. It is not an
  // extracted production function, original native RED or qualification input.
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-callback-tap-'));
  try {
    const source = path.join(root, 'format.test.mjs');
    await writeFile(source, `import assert from 'node:assert/strict';import test from 'node:test';
      test('fixed format only',()=>assert.equal(1,0,${JSON.stringify(CALLBACK_IDLE_MARKER + '\n')}));`, { flag: 'wx', mode: 0o600 });
    // A nested test must not inherit the parent's private V8 reporter pipe.
    const environment = { ...process.env }; delete environment.NODE_TEST_CONTEXT;
    const child = spawnSync(process.execPath, ['--test', '--test-reporter=tap', source], { env: environment, timeout: 10000, maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 1); assert.equal(child.stderr.length, 0);
    assert.equal(child.stdout.toString().split('\n').filter(line => line.trim() === CALLBACK_IDLE_MARKER).length, 1);
  } finally { await rm(root, { recursive: true, force: true }); }
});
