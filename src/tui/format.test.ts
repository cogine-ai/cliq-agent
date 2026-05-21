import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  extractToolBody,
  formatToolResultSummary,
  previewFromAction,
  toolNameFromAction
} from './format.js';

test('toolNameFromAction maps each ModelAction variant to its registry name', () => {
  assert.equal(toolNameFromAction({ bash: 'ls' }), 'bash');
  assert.equal(toolNameFromAction({ edit: { path: 'a', old_text: '', new_text: '' } }), 'edit');
  assert.equal(toolNameFromAction({ read: { path: 'a' } }), 'read');
  assert.equal(toolNameFromAction({ ls: { path: '.' } }), 'ls');
  assert.equal(toolNameFromAction({ find: { name: '*.ts' } }), 'find');
  assert.equal(toolNameFromAction({ grep: { pattern: 'foo' } }), 'grep');
});

test('previewFromAction shows the most useful field per action kind', () => {
  assert.equal(previewFromAction({ bash: 'npm test' }), 'npm test');
  assert.equal(
    previewFromAction({ edit: { path: 'src/foo.ts', old_text: 'a', new_text: 'b' } }),
    'src/foo.ts'
  );
  assert.equal(previewFromAction({ read: { path: 'src/bar.ts' } }), 'src/bar.ts');
  assert.equal(
    previewFromAction({ read: { path: 'src/bar.ts', start_line: 10, end_line: 20 } }),
    'src/bar.ts:10-20'
  );
  assert.equal(previewFromAction({ ls: {} }), '.');
  assert.equal(previewFromAction({ ls: { path: 'src' } }), 'src');
  assert.equal(previewFromAction({ find: { name: '*.ts' } }), '*.ts');
  assert.equal(previewFromAction({ find: { name: '*.ts', path: 'src' } }), '*.ts in src');
  assert.equal(previewFromAction({ grep: { pattern: 'foo' } }), 'foo');
  assert.equal(previewFromAction({ grep: { pattern: 'foo', path: 'src' } }), 'foo in src');
});

test('formatToolResultSummary prefers target details; falls back to policy/error', () => {
  assert.equal(
    formatToolResultSummary({
      tool: 'read',
      status: 'ok',
      content: '...',
      meta: { path: 'src/foo.ts', start_line: 3, end_line: 8 }
    }),
    'src/foo.ts:3-8'
  );

  assert.equal(
    formatToolResultSummary({
      tool: 'grep',
      status: 'ok',
      content: '...',
      meta: { path: 'src', matches: 2 }
    }),
    'src — 2 matches'
  );

  assert.equal(
    formatToolResultSummary({
      tool: 'edit',
      status: 'error',
      content: '...',
      meta: { path: 'src/foo.ts', error: 'patch did not apply' }
    }),
    'src/foo.ts — patch did not apply'
  );

  assert.equal(
    formatToolResultSummary({
      tool: 'bash',
      status: 'error',
      content: '...',
      meta: { policy: 'confirm-bash', reason: 'user declined' }
    }),
    'policy=confirm-bash user declined'
  );

  assert.equal(
    formatToolResultSummary({
      tool: 'unknown',
      status: 'error',
      content: '...',
      meta: { error: 'something broke' }
    }),
    'something broke'
  );

  assert.equal(
    formatToolResultSummary({ tool: 'x', status: 'ok', content: '...', meta: {} }),
    '(no details)'
  );
});

test('formatToolResultSummary surfaces bash command and exit state', () => {
  assert.equal(
    formatToolResultSummary({
      tool: 'bash',
      status: 'ok',
      content: 'TOOL_RESULT bash OK\n$ npm test\n(exit=0 signal=none)\npass',
      meta: { exit: 0, signal: 'none', timed_out: false }
    }),
    'npm test — exit=0'
  );

  assert.equal(
    formatToolResultSummary({
      tool: 'bash',
      status: 'error',
      content: 'TOOL_RESULT bash ERROR\n$ npm test\n(exit=42 signal=none)\nfail',
      meta: { exit: 42, signal: 'none', timed_out: false }
    }),
    'npm test — exit=42'
  );

  assert.equal(
    formatToolResultSummary({
      tool: 'bash',
      status: 'error',
      content: 'TOOL_RESULT bash ERROR\n$ long command\n(exit=null signal=SIGTERM)\n[process timed out]',
      meta: { exit: null, signal: 'SIGTERM', timed_out: true }
    }),
    'long command — exit=null signal=SIGTERM timed out'
  );
});

test('extractToolBody strips the TOOL_RESULT header for bash and the file tools', () => {
  const bash = `TOOL_RESULT bash success
$ echo hi
(exit=0 signal=none)
hi
done`;
  assert.equal(extractToolBody({ tool: 'bash', status: 'ok', content: bash, meta: {} }), 'hi\ndone');

  // ls, read, find, grep all share the `TOOL_RESULT <tool>\npath=...` header.
  const ls = `TOOL_RESULT ls OK
path=.
a.txt
b.txt`;
  assert.equal(extractToolBody({ tool: 'ls', status: 'ok', content: ls, meta: {} }), 'a.txt\nb.txt');

  const read = `TOOL_RESULT read OK
path=src/foo.ts
line 1
line 2`;
  assert.equal(
    extractToolBody({ tool: 'read', status: 'ok', content: read, meta: {} }),
    'line 1\nline 2'
  );

  const empty = `TOOL_RESULT bash success
$ true
`;
  assert.equal(extractToolBody({ tool: 'bash', status: 'ok', content: empty, meta: {} }), undefined);

  // Content that has no body past the header returns undefined (not empty string).
  const headerOnly = `TOOL_RESULT ls OK
path=.`;
  assert.equal(
    extractToolBody({ tool: 'ls', status: 'ok', content: headerOnly, meta: {} }),
    undefined
  );
});
