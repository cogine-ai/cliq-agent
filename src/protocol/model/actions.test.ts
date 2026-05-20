import test from 'node:test';
import assert from 'node:assert/strict';

import { parseModelAction } from './actions.js';

test('parses bash action', () => {
  assert.deepEqual(parseModelAction('{"bash":"npm test"}'), { bash: 'npm test' });
});

test('parses edit action', () => {
  assert.deepEqual(parseModelAction('{"edit":{"path":"src/index.ts","old_text":"foo","new_text":"bar"}}'), {
    edit: { path: 'src/index.ts', old_text: 'foo', new_text: 'bar' }
  });
});

test('parses read action', () => {
  assert.deepEqual(parseModelAction('{"read":{"path":"src/index.ts","start_line":1,"end_line":20}}'), {
    read: { path: 'src/index.ts', start_line: 1, end_line: 20 }
  });
});

test('parses ls action', () => {
  assert.deepEqual(parseModelAction('{"ls":{"path":"src"}}'), { ls: { path: 'src' } });
});

test('parses find action', () => {
  assert.deepEqual(parseModelAction('{"find":{"path":"src","name":"runner"}}'), {
    find: { path: 'src', name: 'runner' }
  });
});

test('parses grep action', () => {
  assert.deepEqual(parseModelAction('{"grep":{"path":"src","pattern":"runTurn"}}'), {
    grep: { path: 'src', pattern: 'runTurn' }
  });
});

test('parses skill activation action', () => {
  assert.deepEqual(parseModelAction('{"skill":{"name":"reviewer"}}'), {
    skill: { name: 'reviewer' }
  });
});

test('parses skill resource read and list actions', () => {
  assert.deepEqual(parseModelAction('{"skillResource":{"skill":"reviewer","path":"references/rubric.md"}}'), {
    skillResource: { skill: 'reviewer', path: 'references/rubric.md' }
  });
  assert.deepEqual(parseModelAction('{"skillResource":{"skill":"reviewer","mode":"list"}}'), {
    skillResource: { skill: 'reviewer', mode: 'list' }
  });
});

test('rejects invalid skill activation payloads', () => {
  assert.throws(() => parseModelAction('{"skill":{"name":123}}'), /unsupported action/i);
});

test('rejects invalid skill resource payloads', () => {
  assert.throws(() => parseModelAction('{"skillResource":{"skill":"reviewer","mode":"write"}}'), /unsupported action/i);
  assert.throws(() => parseModelAction('{"skillResource":{"skill":123,"path":"x"}}'), /unsupported action/i);
  assert.throws(() => parseModelAction('{"skillResource":{"path":"x"}}'), /unsupported action/i);
  assert.throws(() => parseModelAction('{"skillResource":{"skill":"reviewer","path":123}}'), /unsupported action/i);
});

test('parses final message action', () => {
  assert.deepEqual(parseModelAction('{"message":"done"}'), { message: 'done' });
});

test('rejects multiple top-level keys', () => {
  assert.throws(() => parseModelAction('{"bash":"pwd","message":"done"}'), /exactly one top-level key/i);
});

test('rejects unknown top-level keys', () => {
  assert.throws(() => parseModelAction('{"unknown":"value"}'), /unknown top-level key/i);
});

test('rejects malformed json', () => {
  assert.throws(() => parseModelAction('{"bash":"pwd"'), /invalid json|unexpected token/i);
});

test('repairs invalid \\; escape and parses as bash action', () => {
  const raw = '{"bash":"find .git/worktrees/ -type f -name \'HEAD\' -mtime +30 -exec dirname {} \\;"}';
  assert.deepEqual(parseModelAction(raw), {
    bash: "find .git/worktrees/ -type f -name 'HEAD' -mtime +30 -exec dirname {} \\;"
  });
});

test('repaired JSON still rejects multiple top-level keys', () => {
  assert.throws(
    () => parseModelAction('{"bash":"a\\;","message":"done"}'),
    /exactly one top-level key/i
  );
});

test('does not extract JSON from code fences', () => {
  assert.throws(
    () => parseModelAction('```json\n{"bash":"pwd"}\n```'),
    /invalid json|unexpected token/i
  );
});
