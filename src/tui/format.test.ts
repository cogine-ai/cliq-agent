import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  extractBashBody,
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

test('formatToolResultSummary prefers path; falls back to policy/error', () => {
  assert.equal(
    formatToolResultSummary({
      tool: 'read',
      status: 'ok',
      content: '...',
      meta: { path: 'src/foo.ts' }
    }),
    'src/foo.ts'
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

test('extractBashBody strips the TOOL_RESULT header and skips empty bodies', () => {
  const sample = `TOOL_RESULT bash success
$ echo hi
hi
done`;
  assert.equal(extractBashBody({ tool: 'bash', status: 'ok', content: sample, meta: {} }), 'hi\ndone');

  const empty = `TOOL_RESULT bash success
$ true
`;
  assert.equal(extractBashBody({ tool: 'bash', status: 'ok', content: empty, meta: {} }), undefined);

  // Non-bash tools never produce a body.
  assert.equal(
    extractBashBody({ tool: 'read', status: 'ok', content: 'whatever', meta: {} }),
    undefined
  );
});
