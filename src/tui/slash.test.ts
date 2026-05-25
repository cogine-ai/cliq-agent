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
  assert.deepEqual(parseSlash('/policy auto'), { kind: 'policy', mode: 'auto' });
  assert.deepEqual(parseSlash('/policy read-only'), { kind: 'policy', mode: 'read-only' });
  assert.deepEqual(parseSlash('/policy confirm-write'), { kind: 'policy', mode: 'confirm-write' });

  const noArg = parseSlash('/policy');
  assert.equal(noArg.kind, 'invalid');
  if (noArg.kind === 'invalid') {
    assert.match(noArg.reason, /requires a mode argument/);
    assert.match(noArg.reason, /! YOLO Run \(auto\)/);
    assert.match(noArg.reason, /Read Only \(read-only\)/);
  }

  const bad = parseSlash('/policy frobnicate');
  assert.equal(bad.kind, 'invalid');
  if (bad.kind === 'invalid') {
    assert.match(bad.reason, /unknown policy mode/);
    assert.match(bad.reason, /! YOLO Run \(auto\)/);
    assert.match(bad.reason, /Read Only \(read-only\)/);
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
  assert.match(text, /! YOLO Run \(auto\)/);
  assert.match(text, /Read Only \(read-only\)/);
  assert.match(text, /Shortcuts:/);
  assert.match(text, /Shift\+Tab\s+Rotate mode/);
  assert.match(text, /Ctrl\+O\s+Expand\/collapse the most recent tool output/);
  assert.match(text, /Ctrl\+C\s+Cancel an active turn or clear input/);
});
