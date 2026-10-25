// Pure manager-data projection and the actual source-owned assertion block.
// No live manager, unit operation, process death or installed proof is created.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';
import { projectInstalledUnitStopObservation } from './installed-unit-stop-observation.js';

function raw(pid: string, changes: Record<string, unknown> = {}) {
  return { Id: 'not-retained.service', ActiveState: 'active', SubState: 'running', MainPID: pid, ExecMainPID: pid,
    InvocationID: 'a'.repeat(32), ControlGroup: '/not-retained', Result: 'success', ExecMainCode: '0', ExecMainStatus: '0', ...changes };
}
const unavailable = { diagnosticOnly: true, kind: 'unavailable', reason: 'fixed_unit_projection_refused' };

test('unit-stop diagnosis copies only the two fixed roles, finite states, bounded exit values and actual before/after relations', () => {
  const before = [raw('17'), raw('18')], after = [raw('0', { ActiveState: 'failed', SubState: 'failed', Result: 'exit-code',
    ExecMainPID: '17', ExecMainCode: '1', ExecMainStatus: '7' }), raw('18')];
  const observed = projectInstalledUnitStopObservation(before, after); assert.equal(observed.kind, 'observed');
  assert(observed.kind === 'observed');
  const active = { activeState: 'active', subState: 'running', result: 'success', mainPidZero: false,
    execMainPidZero: false, mainPidMatchesExec: true, execMainCode: 0, execMainStatus: 0 };
  assert.deepEqual(observed, { diagnosticOnly: true, kind: 'observed', units: [
    { role: 'supervisor', before: active, after: { activeState: 'failed', subState: 'failed', result: 'exit-code', mainPidZero: true,
      execMainPidZero: false, mainPidMatchesExec: false, execMainCode: 1, execMainStatus: 7 }, sameNonzeroMainPid: false, sameNonemptyInvocation: true },
    { role: 'keeper', before: active, after: active, sameNonzeroMainPid: true, sameNonemptyInvocation: true }
  ] });
  assert(Object.isFrozen(observed) && Object.isFrozen(observed.units) && observed.units.every(unit =>
    Object.isFrozen(unit) && Object.isFrozen(unit.before) && Object.isFrozen(unit.after)));
  after[0]!.ExecMainStatus = '0'; before[0]!.ActiveState = 'inactive';
  assert.equal(observed.units[0].before.activeState, 'active'); assert.equal(observed.units[0].after.execMainStatus, 7);
  assert(!JSON.stringify(observed).includes('not-retained'));
  assert(!Object.hasOwn(observed, 'qualified') && !Object.hasOwn(observed, 'joined'));
});

test('unknown states map only to a fixed literal and zero PIDs or empty invocations never claim an original identity', () => {
  const observed = projectInstalledUnitStopObservation([raw('0', { InvocationID: '' }), raw('17')],
    [raw('0', { InvocationID: '', ActiveState: 'private unknown', SubState: 'private unknown', Result: 'private unknown' }),
      raw('19', { InvocationID: 'b'.repeat(32) })]);
  assert(observed.kind === 'observed');
  assert.equal(observed.units[0].after.activeState, 'unclassified'); assert.equal(observed.units[0].after.subState, 'unclassified');
  assert.equal(observed.units[0].after.result, 'unclassified'); assert.equal(observed.units[0].sameNonzeroMainPid, false);
  assert.equal(observed.units[0].sameNonemptyInvocation, false); assert.equal(observed.units[1].sameNonemptyInvocation, false);
  assert.equal(observed.units[1].sameNonzeroMainPid, false); assert(!JSON.stringify(observed).includes('private unknown'));
});

test('malformed manager observations yield only the closed unavailable variant without invoking accessors or proxies', () => {
  let traps = 0; const good = [raw('17'), raw('18')];
  const getter = Object.defineProperty(raw('17'), 'ActiveState', { enumerable: true, get() { traps++; throw 0; } });
  const arrayGetter = Object.defineProperty([raw('17'), raw('18')], '0', { enumerable: true, get() { traps++; throw 0; } });
  const proxy = new Proxy(raw('17'), { get() { traps++; throw 0; }, ownKeys() { traps++; throw 0; }, getOwnPropertyDescriptor() { traps++; throw 0; } });
  const arrayProxy = new Proxy(good, { get() { traps++; throw 0; }, ownKeys() { traps++; throw 0; } });
  const extra = [...good]; Object.defineProperty(extra, 'unexpected', { value: 'not retained' });
  for (const before of [null, [], [good[0]], [...good, good[0]], Array(2), extra, arrayGetter, arrayProxy, [proxy, good[1]], [getter, good[1]],
    [raw('2147483648'), good[1]], [raw('01'), good[1]], [raw('17', { InvocationID: 'bad' }), good[1]],
    [raw('17', { ExecMainCode: '-1' }), good[1]], [raw('17', { ExecMainStatus: '65536' }), good[1]],
    [raw('17', { Result: { toString() { traps++; throw 0; } } }), good[1]], [raw('17', { SubState: 'x'.repeat(129) }), good[1]]]) {
    assert.deepEqual(projectInstalledUnitStopObservation(before, good), unavailable);
    assert.deepEqual(projectInstalledUnitStopObservation(good, before), unavailable);
  }
  const ignored = Object.defineProperty(raw('17'), 'rawMessage', { enumerable: true, get() { traps++; throw 0; } });
  assert.equal(projectInstalledUnitStopObservation([ignored, good[1]], good).kind, 'observed');
  assert.equal(traps, 0);
});

test('the real journey stop assertion still fails after the already-observed finite unit facts are recorded', async () => {
  const source = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  const start = source.indexOf('            const after = units.map(unit => show(unit));');
  const end = source.indexOf('            // The original service stop, terminal status', start);
  assert(start > 0 && end > start);
  const body = source.slice(start, end);
  assert(body.indexOf('report.unitStopObservation =') < body.indexOf("assert.equal(stopped.ActiveState, 'inactive')"));
  assert(!body.includes('delay(') && !body.includes('Date.') && !body.includes('setTimeout(') && !body.includes('command('));
  const code = ts.transpileModule(`return (async()=>{${body}})();`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const invoke = new Function('units', 'show', 'report', 'projectInstalledUnitStopObservation', 'assert', 'before', 'lstat', code);
  const units = ['first-fixed-unit', 'second-fixed-unit'], before = [raw('17'), raw('18')], after =
    [raw('0', { ActiveState: 'failed', SubState: 'failed', Result: 'exit-code', ExecMainCode: '1', ExecMainStatus: '7' }), raw('18')];
  const report: Record<string, unknown> = {}; let shows = 0;
  await assert.rejects(invoke(units, (unit: string) => { assert.equal(unit, units[shows]); return after[shows++]; }, report,
    projectInstalledUnitStopObservation, assert, before, () => assert.fail('failed original state assertion precedes process I/O')),
  error => error instanceof assert.AssertionError && error.actual === 'failed' && error.expected === 'inactive');
  assert.equal(shows, 2);
  assert.deepEqual(report.unitStopObservation, projectInstalledUnitStopObservation(before, after));
  const malformed: Record<string, unknown> = {};
  await assert.rejects(invoke(units, () => ({ ActiveState: 'failed' }), malformed, projectInstalledUnitStopObservation, assert, before,
    () => assert.fail('original state assertion still fails before process I/O')), assert.AssertionError);
  assert.deepEqual(malformed.unitStopObservation, unavailable, 'capture refusal neither hides nor replaces the original assertion');
});
