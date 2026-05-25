import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildHelpText, completeSlash, matchSlash, parseSlash } from './slash.js';

test('parseSlash maps /exit and /quit to exit', () => {
  assert.deepEqual(parseSlash('/exit'), { kind: 'exit' });
  assert.deepEqual(parseSlash('/quit'), { kind: 'exit' });
  assert.deepEqual(parseSlash('  /exit  '), { kind: 'exit' });
});

test('parseSlash maps /reset and /help', () => {
  assert.deepEqual(parseSlash('/reset'), { kind: 'reset' });
  assert.deepEqual(parseSlash('/help'), { kind: 'help' });
});

test('parseSlash maps skill commands', () => {
  assert.deepEqual(parseSlash('/skills'), { kind: 'skills' });
  assert.deepEqual(parseSlash('/skill reviewer'), { kind: 'skill', name: 'reviewer' });
  const noArg = parseSlash('/skill');
  assert.equal(noArg.kind, 'invalid');
  if (noArg.kind === 'invalid') assert.match(noArg.reason, /requires a skill name/);
});

test('parseSlash /policy requires a known mode argument', () => {
  assert.deepEqual(parseSlash('/policy default'), { kind: 'policy', mode: 'default' });
  assert.deepEqual(parseSlash('/policy accept-edits'), { kind: 'policy', mode: 'accept-edits' });
  assert.deepEqual(parseSlash('/policy plan'), { kind: 'policy', mode: 'plan' });
  assert.deepEqual(parseSlash('/policy yolo'), { kind: 'policy', mode: 'yolo' });

  const noArg = parseSlash('/policy');
  assert.equal(noArg.kind, 'invalid');
  if (noArg.kind === 'invalid') {
    assert.match(noArg.reason, /requires a mode argument/);
    assert.match(noArg.reason, /Default \(default\)/);
    assert.match(noArg.reason, /Plan \(plan\)/);
    assert.match(noArg.reason, /! YOLO \(yolo\)/);
  }

  const bad = parseSlash('/policy frobnicate');
  assert.equal(bad.kind, 'invalid');
  if (bad.kind === 'invalid') {
    assert.match(bad.reason, /unknown policy mode/);
    assert.match(bad.reason, /Default \(default\)/);
    assert.match(bad.reason, /Plan \(plan\)/);
  }

  const old = parseSlash('/policy read-only');
  assert.equal(old.kind, 'invalid');
  if (old.kind === 'invalid') {
    assert.match(old.reason, /read-only has been replaced by plan/);
  }
});

test('parseSlash flags unknown commands without throwing', () => {
  const r = parseSlash('/banana');
  assert.equal(r.kind, 'unknown');
  if (r.kind === 'unknown') assert.equal(r.head, '/banana');
});

test('matchSlash returns prefix-matching commands', () => {
  assert.deepEqual(
    matchSlash('/').map((c) => c.name).sort(),
    ['/exit', '/help', '/policy', '/quit', '/reset', '/skill', '/skills']
  );
  assert.deepEqual(
    matchSlash('/p').map((c) => c.name),
    ['/policy']
  );
  assert.deepEqual(matchSlash('/zz'), []);
});

test('completeSlash returns the single match name (with trailing space when arg expected)', () => {
  assert.equal(completeSlash('/p'), '/policy ');
  assert.equal(completeSlash('/r'), '/reset');
  assert.equal(completeSlash('/'), null); // multiple matches
  assert.equal(completeSlash('/policy '), null); // already past the head
  assert.equal(completeSlash('not slash'), null);
  assert.equal(completeSlash('/zz'), null);
});

test('buildHelpText lists every command with its description', () => {
  const text = buildHelpText();
  assert.match(text, /\/exit/);
  assert.match(text, /\/quit/);
  assert.match(text, /\/reset/);
  assert.match(text, /\/help/);
  assert.match(text, /\/policy <mode>/);
  assert.match(text, /\/skills/);
  assert.match(text, /\/skill <name>/);
  assert.match(text, /Modes:/);
  assert.match(text, /Default \(default\)/);
  assert.match(text, /Accept Edits \(accept-edits\)/);
  assert.match(text, /Plan \(plan\)/);
  assert.match(text, /! YOLO \(yolo\)/);
  assert.match(text, /Shortcuts:/);
  assert.match(text, /Shift\+Tab\s+Rotate mode/);
  assert.match(text, /Ctrl\+O\s+Expand\/collapse the most recent tool output/);
  assert.match(text, /Ctrl\+C\s+Cancel an active turn or clear input/);
});
