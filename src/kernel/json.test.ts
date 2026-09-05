import assert from 'node:assert/strict';
import { test } from 'node:test';

import { assertBoundedJsonValue, parseJsonStrict, StrictJsonError } from './json.js';

test('parseJsonStrict decodes the complete JSON domain without object prototypes', () => {
  const value = parseJsonStrict('{"text":"ok\\n","number":-1.5e2,"array":[true,false,null]}') as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(value), null);
  assert.deepEqual({ ...value }, { text: 'ok\n', number: -150, array: [true, false, null] });
});

test('parseJsonStrict rejects duplicate keys including escape-equivalent spellings', () => {
  assert.throws(() => parseJsonStrict('{"a":1,"a":2}'), /duplicate JSON object key/);
  assert.throws(() => parseJsonStrict('{"a":1,"\\u0061":2}'), /duplicate JSON object key/);
});

test('parseJsonStrict rejects trailing data, commas, invalid numbers, and non-finite numbers', () => {
  assert.throws(() => parseJsonStrict('{} true'), /trailing JSON content/);
  assert.throws(() => parseJsonStrict('[1,]'), /trailing comma/);
  assert.throws(() => parseJsonStrict('{"a":1,}'), /trailing comma/);
  assert.throws(() => parseJsonStrict('01'), /invalid character after JSON number/);
  assert.throws(() => parseJsonStrict('1e9999'), /finite range/);
});

test('parseJsonStrict reports UTF-8 byte offsets', () => {
  assert.throws(
    () => parseJsonStrict('{"é":1,"é":2}'),
    (error: unknown) => error instanceof StrictJsonError && error.offset === Buffer.byteLength('{"é":1,', 'utf8')
  );
});

test('parseJsonStrict bounds nesting depth', () => {
  const source = '['.repeat(34) + ']'.repeat(34);
  assert.throws(() => parseJsonStrict(source), /nesting exceeds/);
});

test('parseJsonStrict bounds aggregate object members and array elements', () => {
  const source = `[${Array.from({ length: 10_001 }, () => '0').join(',')}]`;
  assert.throws(() => parseJsonStrict(source), /more than 10000 container entries/u);
});

test('assertBoundedJsonValue applies the same bounds to already-decoded values', () => {
  let nested: unknown = null;
  for (let index = 0; index < 33; index += 1) nested = [nested];
  assert.throws(() => assertBoundedJsonValue(nested), /exceeds JSON depth 32/u);
  assert.throws(() => assertBoundedJsonValue(Array.from({ length: 10_001 }, () => null)), /more than 10000/u);
});
