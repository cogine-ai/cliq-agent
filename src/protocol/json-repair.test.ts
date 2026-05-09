import test from 'node:test';
import assert from 'node:assert/strict';

import { repairJsonStrings } from './json-repair.js';

function repairAndParse(raw: string): unknown {
  return JSON.parse(repairJsonStrings(raw));
}

test('preserves valid short escapes', () => {
  const raw = '{"s":"\\"\\\\\\/\\b\\f\\n\\r\\t"}';
  assert.equal(repairJsonStrings(raw), raw);
  assert.deepEqual(JSON.parse(raw), { s: '"\\/\b\f\n\r\t' });
});

test('preserves valid \\uXXXX escapes', () => {
  const raw = '{"s":"\\u0041\\u00e9"}';
  assert.equal(repairJsonStrings(raw), raw);
  assert.deepEqual(repairAndParse(raw), { s: 'Aé' });
});

test('repairs invalid escape \\; (issue example)', () => {
  const raw = '{"bash":"find .git/worktrees/ -type f -name \'HEAD\' -mtime +30 -exec dirname {} \\;"}';
  assert.deepEqual(repairAndParse(raw), {
    bash: "find .git/worktrees/ -type f -name 'HEAD' -mtime +30 -exec dirname {} \\;"
  });
});

test('repairs invalid escape \\x by escaping the backslash only', () => {
  const raw = '{"s":"a\\xb"}';
  assert.equal(repairJsonStrings(raw), '{"s":"a\\\\xb"}');
  assert.deepEqual(repairAndParse(raw), { s: 'a\\xb' });
});

test('repairs \\u with fewer than four hex digits', () => {
  const raw = '{"s":"\\u12"}';
  assert.equal(repairJsonStrings(raw), '{"s":"\\\\u12"}');
  assert.deepEqual(repairAndParse(raw), { s: '\\u12' });
});

test('repairs \\u with non-hex following digits', () => {
  const raw = '{"s":"\\uZZZZ"}';
  assert.equal(repairJsonStrings(raw), '{"s":"\\\\uZZZZ"}');
  assert.deepEqual(repairAndParse(raw), { s: '\\uZZZZ' });
});

test('escapes raw newline inside a string', () => {
  const raw = '{"s":"a\nb"}';
  assert.equal(repairJsonStrings(raw), '{"s":"a\\nb"}');
  assert.deepEqual(repairAndParse(raw), { s: 'a\nb' });
});

test('escapes raw tab and carriage return inside a string', () => {
  const raw = '{"s":"a\tb\rc"}';
  assert.equal(repairJsonStrings(raw), '{"s":"a\\tb\\rc"}');
});

test('escapes other control characters as \\u00XX', () => {
  const raw = `{"s":"a${String.fromCharCode(0x01)}b"}`;
  assert.equal(repairJsonStrings(raw), '{"s":"a\\u0001b"}');
  assert.deepEqual(repairAndParse(raw), { s: `a${String.fromCharCode(0x01)}b` });
});

test('repairs trailing isolated backslash inside a string', () => {
  const raw = '{"s":"abc\\';
  assert.equal(repairJsonStrings(raw), '{"s":"abc\\\\');
});

test('does not touch backslashes outside string literals', () => {
  const raw = '{"a":1}\\';
  assert.equal(repairJsonStrings(raw), '{"a":1}\\');
});

test('does not insert missing quotes or braces (non-goal)', () => {
  const raw = '{"bash":"pwd"';
  assert.equal(repairJsonStrings(raw), raw);
  assert.throws(() => JSON.parse(repairJsonStrings(raw)));
});

test('does not extract JSON from code fences (non-goal)', () => {
  const raw = '```json\n{"bash":"pwd"}\n```';
  assert.equal(repairJsonStrings(raw), raw);
  assert.throws(() => JSON.parse(repairJsonStrings(raw)));
});

test('does not modify field names or repair structural commas (non-goal)', () => {
  const raw = '{"bash":"a" "message":"b"}';
  assert.equal(repairJsonStrings(raw), raw);
  assert.throws(() => JSON.parse(repairJsonStrings(raw)));
});

test('strict valid JSON is returned unchanged', () => {
  const raw = '{"edit":{"path":"src/x.ts","old_text":"a","new_text":"b"}}';
  assert.equal(repairJsonStrings(raw), raw);
});
