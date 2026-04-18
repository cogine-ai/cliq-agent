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
