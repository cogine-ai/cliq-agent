// Closed interpretation of original test-runner output only. This module
// cannot manufacture a source view, native result, retirement or authority.
import assert from 'node:assert/strict';
import { parseJsonStrict } from '../../../src/kernel/json.js';

export const CALLBACK_IDLE_MARKER = 'CLIQ_NATIVE_CALLBACK_FAILURE_V1:idle_delivery';
export const CALLBACK_OTHER_MARKER = 'CLIQ_NATIVE_CALLBACK_FAILURE_V1:other';
export const CALLBACK_CASES = Object.freeze([
  'a queued credential platform request expires while the shared native workers remain blocked',
  'an executing credential platform timeout retires its connection and permits a healthy subsequent operation',
  'caller cancellation joins an executing credential inspection and cannot revoke its next native job',
  'native preparation close joins promptly and its retained original no-release mutex cannot be forged or reused',
] as const);
export function readNativeCallbackEvidence(input: Readonly<{ mode: 'baseline' | 'candidate'; stdout: Buffer;
  stderr: Buffer; code: number | null; signal: string | null; joined: boolean }>) {
  assert(input.mode === 'baseline' || input.mode === 'candidate');
  assert(input.joined && input.signal === null && input.code === (input.mode === 'baseline' ? 1 : 0));
  assert(input.stdout.length <= 2 * 1024 * 1024 && input.stderr.length === 0);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(input.stdout);
  assert(!text.includes('\0') && !text.includes(CALLBACK_OTHER_MARKER));
  const lines = text.split('\n'), cases: Array<{ name: string; passed: boolean; at: number }> = [];
  for (const [at, line] of lines.entries()) {
    const match = /^(ok|not ok) [1-9][0-9]* - (.+)$/u.exec(line);
    if (match) cases.push({ name: match[2]!, passed: match[1] === 'ok', at });
  }
  assert.equal(cases.length, 4);
  assert.equal(new Set(cases.map(row => row.name)).size, 4);
  assert(CALLBACK_CASES.every(name => cases.some(row => row.name === name)));
  const baseline = input.mode === 'baseline';
  for (const [index, row] of cases.entries()) {
    const expected = !baseline || row.name === CALLBACK_CASES[0];
    assert.equal(row.passed, expected);
    const block = lines.slice(row.at + 1, cases[index + 1]?.at ?? lines.length);
    const idle = block.filter(line => line.trim() === CALLBACK_IDLE_MARKER).length;
    assert.equal(idle, expected ? 0 : 1, 'RED requires the actual private idle-delivery sentinel for every refusal');
  }
  assert.equal(lines.filter(line => line.trim() === CALLBACK_IDLE_MARKER).length, baseline ? 3 : 0);
  for (const [name, count] of [['tests', 4], ['pass', baseline ? 1 : 4], ['fail', baseline ? 3 : 0],
    ['cancelled', 0], ['skipped', 0]] as const) assert.equal(lines.filter(line => line === `# ${name} ${count}`).length, 1);
  const reports = lines.filter(line => line.startsWith('# {')).map(line => parseJsonStrict(line.slice(2))) as Record<string, unknown>[];
  const required = [
    ['actualInspectionEntered', 'actualInspectionConnectionRetired', 'cancelJoinedWithin1500ms'],
    ['actualPreparationEntered', 'actualPreparationConnectionRetired', 'closeJoinedWithin1500ms'],
  ] as const;
  for (const [entered, retired, timely] of required) {
    const selected = reports.filter(row => Object.hasOwn(row, entered)); assert.equal(selected.length, 1);
    const row = selected[0]!;
    assert.deepEqual(Object.keys(row).sort(), ['diagnosticOnly', entered, timely, retired, 'childrenJoined', 'installedI1Qualified'].sort());
    assert.equal(row.diagnosticOnly, true); assert.equal(row[entered], true); assert.equal(row[retired], true);
    assert.equal(row[timely], true); assert.equal(row.childrenJoined, true); assert.equal(row.installedI1Qualified, false);
  }
  return Object.freeze({ diagnosticOnly: true, mode: input.mode, cases: 4, passed: baseline ? 1 : 4,
    idleDeliveryRefusals: baseline ? 3 : 0, originalInspectionEnteredAndRetired: true,
    originalPreparationEnteredAndRetired: true, originalFixtureChildrenJoined: true, installedI1Qualified: false });
}
