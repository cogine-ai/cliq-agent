import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { builtinToolInputBytes, decodeBuiltinToolInput, clipBuiltinText, builtinReadOutputBytes, decodeBuiltinReadOutput, BUILTIN_SCRIPT_ENVIRONMENTS, BUILTIN_SCRIPT_RECIPE } from './builtin-tool-data.js';
const limits = { maxSingleFileBytes: 268_435_456, maxInvocationOutputBytes: 67_108_864 };

test('the fixed program accepts only exact normalized original inputs and real resource ceilings', () => {
  for (const [tool, input] of [['read', { path: 'a', start_line: 1 }], ['ls', { path: '.' }],
    ['find', { path: '.', name: 'test' }], ['grep', { path: '.', pattern: 'literal.*' }], ['bash', { command: 'printf ok' }]] as const) {
    const actual = decodeBuiltinToolInput(builtinToolInputBytes(tool, input, limits));
    assert.equal(actual.tool, tool); assert.deepEqual(actual.input, input); assert(Object.isFrozen(actual.input));
  }
  assert.throws(() => builtinToolInputBytes('read', { path: '../outside' }, limits));
  assert.throws(() => builtinToolInputBytes('ls', {}, limits)); // normalization cannot substitute another granted input
  assert.throws(() => builtinToolInputBytes('read', { path: './a' }, limits));
  assert.throws(() => builtinToolInputBytes('bash', { command: 'x\0y' }, limits));
  assert.throws(() => builtinToolInputBytes('ls', { path: '.' }, { ...limits, maxSingleFileBytes: 268_435_457 }));
  assert.throws(() => builtinToolInputBytes('ls', { path: '.' }, { ...limits, maxInvocationOutputBytes: 67_108_865 }));
});

test('a sealed input frame cannot relabel control, repeat keys, append data or select another root', () => {
  const original = builtinToolInputBytes('ls', { path: '.' }, limits);
  for (const text of [original.toString().replace('"tool":"ls"', '"tool":"request_input"'),
    original.toString().replace('"tool":"ls"', '"tool":"ls","tool":"ls"'),
    `${original.toString()}\n`, original.toString().replace('"schemaVersion":1', '"root":"/host","schemaVersion":1')])
    assert.throws(() => decodeBuiltinToolInput(Buffer.from(text)));
});

test('actual byte limits preserve Unicode and mark an oversized match prefix incomplete', () => {
  assert.deepEqual(clipBuiltinText('a😀é', 4), { text: 'a', truncated: true });
  assert.deepEqual(clipBuiltinText('a😀é', 5), { text: 'a😀', truncated: true });
  assert.deepEqual(clipBuiltinText('a😀é', 7), { text: 'a😀é', truncated: false });
  const content = Array.from({ length: 200 }, (_, i) => ({ path: `a/${i}`, line: i + 1, text: '😀'.repeat(500) }));
  const bytes = builtinReadOutputBytes({ schemaVersion: 1, tool: 'grep', scope: 'private_generation_non_git', path: '.',
    complete: true, reasons: [], scannedEntries: 200, content }, 65_536);
  assert(bytes.length <= 65_536);
  const actual = JSON.parse(bytes.toString()); assert.equal(actual.complete, false);
  assert.deepEqual(actual.reasons, ['output_limit']); assert(actual.content.length > 0 && actual.content.length < content.length);
  assert.deepEqual(actual.content, content.slice(0, actual.content.length));
});


test('read outputs stay closed and tied to their original tool, path, match and completeness', () => {
  const capsule = decodeBuiltinToolInput(builtinToolInputBytes('grep', { path: 'sub', pattern: 'needle' }, limits));
  const output = { schemaVersion: 1, tool: 'grep', scope: 'private_generation_non_git', path: 'sub', complete: true,
    reasons: [], scannedEntries: 1, content: [{ path: 'sub/a', line: 1, text: 'needle' }] } as const;
  const encoded = builtinReadOutputBytes(output, limits.maxInvocationOutputBytes);
  assert.deepEqual(decodeBuiltinReadOutput(encoded, capsule), output);
  for (const mutation of [{ tool: 'ls' }, { path: '.' }, { complete: false }, { reasons: ['file_limit'] },
    { content: [{ path: '../outside', line: 1, text: 'needle' }] }, { content: [{ path: 'sub/a', line: 1, text: 'no' }] },
    { content: [{ path: 'sub/a', line: 1, text: 'needle', authority: true }] }]) {
    const changed = { ...output, ...mutation }; const bytes = canonicalJsonBytes(changed);
    assert.throws(() => decodeBuiltinReadOutput(bytes, capsule));
  }
});


test('read recipe stays Node-only while Bash carries the fixed existing-Git protection environment', () => {
  assert.deepEqual(BUILTIN_SCRIPT_ENVIRONMENTS.read.controlledPath, ['/usr/bin']);
  assert.deepEqual(BUILTIN_SCRIPT_ENVIRONMENTS.read.variables, []);
  assert.deepEqual(BUILTIN_SCRIPT_ENVIRONMENTS.bash.controlledPath, ['/usr/bin', '/bin']);
  assert.deepEqual(BUILTIN_SCRIPT_ENVIRONMENTS.bash.variables, [{ name: 'GIT_OPTIONAL_LOCKS', value: { kind: 'non_secret_literal', value: '0' } }]);
  assert.equal(BUILTIN_SCRIPT_RECIPE.privateGitProtection, 'existing_read_only');
  assert.equal(BUILTIN_SCRIPT_ENVIRONMENTS.bash.networkMode, 'none');
  assert.equal(BUILTIN_SCRIPT_ENVIRONMENTS.bash.inheritedHostEnvironment, false);
});
