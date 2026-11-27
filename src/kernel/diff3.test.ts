import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mergeTextDiff3V1, type Diff3LineEditV1 } from './diff3.js';

test('cliq-diff3-v1 preserves disjoint changes and every original line terminator', async () => {
  const result = await mergeTextDiff3V1('one\r\ntwo\nthree', 'ONE\r\ntwo\nthree', 'one\r\ntwo\nTHREE');
  assert.equal(result.kind, 'merged');
  if (result.kind !== 'merged') assert.fail('disjoint edits must merge');
  assert.equal(result.text, 'ONE\r\ntwo\nTHREE');
  assert.deepEqual(result.currentEdits, [{ baseStart: 0, baseEnd: 1, replacement: 'ONE\r\n' }]);
  assert.deepEqual(result.desiredEdits, [{ baseStart: 2, baseEnd: 3, replacement: 'THREE' }]);
});

// Independent quadratic oracle: production uses Myers plus banded crossing
// reconstruction, not this full matrix. Lowest edit index means D, I, E ties.
function oracle(base: readonly string[], target: readonly string[]) {
  const costs = Array.from({ length: base.length + 1 }, () => Array<number>(target.length + 1).fill(Infinity));
  for (let i = base.length; i >= 0; i--) for (let j = target.length; j >= 0; j--) {
    if (i === base.length) costs[i][j] = target.length - j;
    else if (j === target.length) costs[i][j] = base.length - i;
    else costs[i][j] = Math.min(costs[i + 1][j] + 1, costs[i][j + 1] + 1,
      base[i] === target[j] ? costs[i + 1][j + 1] : Infinity);
  }
  const edits: Diff3LineEditV1[] = [];
  let i = 0, j = 0, pending: Diff3LineEditV1 | undefined;
  while (i < base.length || j < target.length) {
    if (i < base.length && costs[i][j] === costs[i + 1][j] + 1) {
      pending ??= { baseStart: i, baseEnd: i, replacement: '' };
      pending.baseEnd = ++i;
    } else if (j < target.length && costs[i][j] === costs[i][j + 1] + 1) {
      pending ??= { baseStart: i, baseEnd: i, replacement: '' };
      pending.replacement += target[j++];
    } else {
      if (pending) edits.push(pending);
      pending = undefined; i++; j++;
    }
  }
  if (pending) edits.push(pending);
  return { edits, distance: costs[0][0] };
}

function apply(base: readonly string[], edits: readonly Diff3LineEditV1[]): string {
  let result = '', cursor = 0;
  for (const edit of edits) {
    assert.ok(edit.baseStart >= cursor && edit.baseEnd >= edit.baseStart && edit.baseEnd <= base.length);
    result += base.slice(cursor, edit.baseStart).join('') + edit.replacement;
    cursor = edit.baseEnd;
  }
  return result + base.slice(cursor).join('');
}

test('canonical shortest scripts agree with an independent exhaustive oracle and round-trip all 16,129 small pairs', async () => {
  const words: string[][] = [[]];
  for (let length = 1; length <= 6; length++) for (let bits = 0; bits < 2 ** length; bits++)
    words.push(Array.from({ length }, (_, index) => bits & (1 << index) ? 'A\n' : 'B\n'));
  let pairs = 0;
  for (const base of words) for (const target of words) {
    const result = await mergeTextDiff3V1(base.join(''), target.join(''), base.join(''));
    assert.equal(result.kind, 'merged');
    if (result.kind !== 'merged') assert.fail('one-sided text must merge');
    const expected = oracle(base, target);
    assert.deepEqual(result.currentEdits, expected.edits, JSON.stringify({ base, target }));
    assert.equal(result.currentEdits.reduce((sum, edit) => sum + edit.baseEnd - edit.baseStart
      + edit.replacement.split('\n').length - 1, 0), expected.distance);
    assert.equal(apply(base, result.currentEdits), target.join(''));
    assert.equal(result.text, target.join(''));
    assert.deepEqual(result.desiredEdits, []);
    pairs++;
  }
  assert.equal(pairs, 16_129);
});

test('overlap conflicts retain every intersecting edit and never manufacture conflict markers', async () => {
  const result = await mergeTextDiff3V1('A\nB\nC\nD\n', 'X\n', 'A\nY\nC\nZ\n');
  assert.equal(result.kind, 'conflict');
  if (result.kind !== 'conflict') assert.fail('the wide replacement conflicts twice');
  assert.deepEqual(result.conflicts, [
    { current: { baseStart: 0, baseEnd: 4, replacement: 'X\n' }, desired: { baseStart: 1, baseEnd: 2, replacement: 'Y\n' } },
    { current: { baseStart: 0, baseEnd: 4, replacement: 'X\n' }, desired: { baseStart: 3, baseEnd: 4, replacement: 'Z\n' } },
  ]);
  assert.equal(Object.hasOwn(result, 'text'), false);
});

test('zero-width boundaries preserve insertion order while same-position and interior differences conflict', async () => {
  const merged = [
    ['', '', '', ''],
    ['', 'new\n', 'new\n', 'new\n'],
    ['x\n', 'a\n', 'y\nx\n', 'y\na\n'],
    ['x\n', 'a\n', 'x\nz\n', 'a\nz\n'],
    ['A\nB\n', 'A\n', 'A\nI\nB\n', 'A\nI\n'],
    ['A\nB\n', 'A\n', 'A\nB\nI\n', 'A\nI\n'],
    ['A\nB\n', 'A\nI\nB\n', 'A\nI\nB\n', 'A\nI\nB\n'],
    ['A\nB\n', 'X\nB\n', 'X\nB\n', 'X\nB\n'],
  ];
  for (const [base, current, desired, expected] of merged) {
    const result = await mergeTextDiff3V1(base, current, desired);
    assert.equal(result.kind, 'merged', JSON.stringify({ base, current, desired }));
    if (result.kind === 'merged') assert.equal(result.text, expected);
    const reversed = await mergeTextDiff3V1(base, desired, current);
    assert.equal(reversed.kind, 'merged');
    if (reversed.kind === 'merged') assert.equal(reversed.text, expected);
  }
  for (const [base, current, desired] of [
    ['', 'A\n', 'B\n'],
    ['A\nB\n', 'A\nI\nB\n', 'A\nJ\nB\n'],
    ['A\nB\nC\n', 'A\n', 'A\nB\nI\nC\n'],
    ['A\nB\n', 'X\n', 'A\nY\n'],
  ]) {
    const result = await mergeTextDiff3V1(base, current, desired);
    assert.equal(result.kind, 'conflict', JSON.stringify({ base, current, desired }));
    assert.equal(Object.hasOwn(result, 'text'), false);
  }
});

test('canonical repeated-line ties choose the earliest edit, deletion first, not a greedy prefix or suffix', async () => {
  for (const [base, desired, expected] of [
    ['x\nx\n', 'x\n', [{ baseStart: 0, baseEnd: 1, replacement: '' }]],
    ['A\nB\n', 'A\nA\n', [{ baseStart: 0, baseEnd: 0, replacement: 'A\n' }, { baseStart: 1, baseEnd: 2, replacement: '' }]],
    ['A\nB\n', 'B\nA\n', [{ baseStart: 0, baseEnd: 1, replacement: '' }, { baseStart: 2, baseEnd: 2, replacement: 'A\n' }]],
  ] as const) {
    const result = await mergeTextDiff3V1(base, desired, base);
    assert.equal(result.kind, 'merged');
    assert.deepEqual(result.currentEdits, expected);
  }
});

test('Unicode, bare CR, mixed CRLF and missing final newline are never normalized', async () => {
  const base = '🙂\r\n原\r样\n最后';
  const result = await mergeTextDiff3V1(base, '🙂\r\n改\r样\n最后', '🙂\r\n原\r样\n末尾🙂');
  assert.equal(result.kind, 'merged');
  if (result.kind === 'merged') assert.equal(result.text, '🙂\r\n改\r样\n末尾🙂');
  assert.deepEqual(result.currentEdits, [{ baseStart: 1, baseEnd: 2, replacement: '改\r样\n' }]);
  const newlineChange = await mergeTextDiff3V1('no newline', 'no newline\n', 'no newline\n');
  assert.equal(newlineChange.kind, 'merged');
  if (newlineChange.kind === 'merged') assert.equal(newlineChange.text, 'no newline\n');
});

test('cancellation and owner resource failures are errors, never text conflicts or partial merges', async () => {
  const before = new AbortController(), cancellation = new Error('owner cancelled');
  before.abort(cancellation);
  await assert.rejects(mergeTextDiff3V1('a', 'b', 'c', { signal: before.signal }), error => error === cancellation);
  const resource = new Error('owner work budget exhausted');
  await assert.rejects(mergeTextDiff3V1('x\n'.repeat(10_000), 'y\n', 'z\n', {
    onWork: ({ totalWork }) => { if (totalWork >= 4096) throw resource; },
  }), error => error === resource);
  const during = new AbortController();
  await assert.rejects(mergeTextDiff3V1('x'.repeat(100_000), 'y', 'z', {
    signal: during.signal,
    onWork: ({ totalWork }) => { if (totalWork >= 4096) setImmediate(() => during.abort(cancellation)); },
  }), error => error === cancellation);
});

test('output assembly yields to its owner even when alternating edits cover every base line', async () => {
  const base: string[] = [], current: string[] = [], desired: string[] = [];
  for (let i = 0; i < 4_200; i++) {
    base.push(`${i}\n`); current.push(i % 2 ? `c${i}\n` : `${i}\n`); desired.push(i % 2 ? `${i}\n` : `d${i}\n`);
  }
  const controller = new AbortController(), cancellation = new Error('cancel output');
  let reachedOutput = false;
  await assert.rejects(mergeTextDiff3V1(base.join(''), current.join(''), desired.join(''), {
    signal: controller.signal,
    onWork: ({ phase }) => {
      if (phase === 'output' && !reachedOutput) {
        reachedOutput = true; setImmediate(() => controller.abort(cancellation));
      }
    },
  }), error => error === cancellation);
  assert.equal(reachedOutput, true);
});

test('off-grid Myers diagonals cannot evade an owner work budget', async () => {
  const resource = new Error('distance work exhausted');
  let distanceObservations = 0;
  await assert.rejects(mergeTextDiff3V1('A\n'.repeat(2500), 'A\n'.repeat(1250), 'A\n'.repeat(2500), {
    onWork: ({ phase }) => { if (phase === 'distance' && ++distanceObservations === 2) throw resource; },
  }), error => error === resource);
  assert.equal(distanceObservations, 2);
});

test('large small-D unique and repeated inputs use linear observed work, not per-line suffix replays', async () => {
  for (const repeated of [false, true]) {
    const measurements: number[] = [];
    for (const count of [2000, 4000]) {
      const lines = Array.from({ length: count }, (_, index) => repeated ? 'x\n' : `${index}\n`);
      const base = lines.join(''), changed = [...lines];
      if (repeated) changed.pop(); else changed[Math.floor(count / 2)] = 'changed\n';
      let work = 0;
      const result = await mergeTextDiff3V1(base, changed.join(''), base, { onWork: value => { work = value.totalWork; } });
      assert.equal(result.kind, 'merged');
      if (result.kind === 'merged') assert.equal(result.text, changed.join(''));
      assert.ok(work < 40 * base.length + 40 * count, JSON.stringify({ count, repeated, work }));
      measurements.push(work);
    }
    assert.ok(measurements[1] < 2.2 * measurements[0], JSON.stringify({ repeated, measurements }));
  }
  let work = 0;
  const skewed = await mergeTextDiff3V1('A\n', 'B\n'.repeat(10_000), 'A\n', { onWork: value => { work = value.totalWork; } });
  assert.equal(skewed.kind, 'merged');
  if (skewed.kind === 'merged') assert.equal(skewed.text, 'B\n'.repeat(10_000));
  assert.ok(work < 150_000, `highly unequal grids must be clipped: ${work}`);
});

test('long byte-identical replacements are compared cooperatively, not as an unobserved merge step', async () => {
  let mergeObservations = 0;
  const replacement = '🙂'.repeat(50_000);
  const result = await mergeTextDiff3V1('base', replacement, replacement, {
    onWork: ({ phase }) => { if (phase === 'merge') mergeObservations++; },
  });
  assert.equal(result.kind, 'merged');
  if (result.kind === 'merged') assert.equal(result.text, replacement);
  assert.ok(mergeObservations >= 20, `long equality work must be visible: ${mergeObservations}`);
});

test('all 3,375 tiny three-way combinations match an independent all-pairs overlap oracle symmetrically', async () => {
  const words: string[][] = [[]];
  for (let length = 1; length <= 3; length++) for (let bits = 0; bits < 2 ** length; bits++)
    words.push(Array.from({ length }, (_, index) => bits & (1 << index) ? 'A\n' : 'B\n'));
  const identical = (a: Diff3LineEditV1, b: Diff3LineEditV1) => a.baseStart === b.baseStart
    && a.baseEnd === b.baseEnd && a.replacement === b.replacement;
  const touch = (a: Diff3LineEditV1, b: Diff3LineEditV1) => {
    if (a.baseStart === a.baseEnd && b.baseStart === b.baseEnd) return a.baseStart === b.baseStart;
    if (a.baseStart === a.baseEnd) return a.baseStart > b.baseStart && a.baseStart < b.baseEnd;
    if (b.baseStart === b.baseEnd) return b.baseStart > a.baseStart && b.baseStart < a.baseEnd;
    return Math.max(a.baseStart, b.baseStart) < Math.min(a.baseEnd, b.baseEnd);
  };
  let triples = 0;
  for (const base of words) for (const current of words) for (const desired of words) {
    const currentEdits = oracle(base, current).edits, desiredEdits = oracle(base, desired).edits;
    const conflicts = currentEdits.flatMap(c => desiredEdits.filter(d => touch(c, d) && !identical(c, d))
      .map(d => ({ current: c, desired: d })));
    const result = await mergeTextDiff3V1(base.join(''), current.join(''), desired.join(''));
    const reversed = await mergeTextDiff3V1(base.join(''), desired.join(''), current.join(''));
    assert.equal(result.kind, conflicts.length ? 'conflict' : 'merged');
    assert.equal(reversed.kind, result.kind);
    if (result.kind === 'conflict') {
      assert.deepEqual(result.conflicts.map(value => JSON.stringify(value)).sort(), conflicts.map(value => JSON.stringify(value)).sort());
    } else {
      const accepted = [...currentEdits, ...desiredEdits.filter(d => !currentEdits.some(c => identical(c, d)))];
      accepted.sort((a, b) => a.baseStart - b.baseStart || a.baseEnd - b.baseEnd);
      const expected = apply(base, accepted);
      assert.equal(result.text, expected);
      if (reversed.kind === 'merged') assert.equal(reversed.text, expected);
    }
    triples++;
  }
  assert.equal(triples, 3375);
});
