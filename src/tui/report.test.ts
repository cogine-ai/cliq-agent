import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { reduce, createInitialState } from './store.js';
import { buildLocalReportMarkdown, redactReportText } from './report.js';

const baseState = () =>
  createInitialState({
    policy: 'plan',
    model: { provider: 'openai', model: 'gpt-4.1' },
    session: { id: 'ses_abcdef1234567890', cwd: '/Users/alice/Secret Project' }
  });

test('buildLocalReportMarkdown creates a local bug report with minimal diagnostics', async () => {
  const state = reduce(baseState(), {
    type: 'runtime-event',
    event: {
      type: 'error',
      stage: 'model',
      code: 'model-error',
      message:
        'request failed Authorization: Bearer sk-proj-abcdefghijklmnopqrstuvwxyz123456 OPENAI_API_KEY=sk-test-abcdefghijklmnopqrstuvwxyz123456 dGhpc2lzYXZlcnlzZWNyZXR0b2tlbjEyMzQ1Njc4OTA='
    }
  });

  const markdown = await buildLocalReportMarkdown(state, {
    kind: 'bug',
    cliqVersion: '1.2.3',
    cliqCommit: '1234567890abcdef1234567890abcdef12345678',
    env: {
      SHELL: '/bin/zsh',
      TERM: 'xterm-256color',
      TERM_PROGRAM: 'iTerm.app'
    },
    platform: 'darwin',
    arch: 'arm64',
    release: '25.1.0',
    nodeVersion: 'v24.0.0',
    isTTY: true,
    colorDepth: 24
  });

  assert.match(markdown, /^# Cliq Bug Report Draft/m);
  assert.match(markdown, /Local draft only/);
  assert.match(markdown, /Cliq has not submitted or uploaded this report/);
  assert.match(markdown, /Cliq version: 1\.2\.3/);
  assert.match(markdown, /Cliq commit: 1234567890ab/);
  assert.match(markdown, /OS\/platform: darwin arm64 25\.1\.0/);
  assert.match(markdown, /Terminal: iTerm\.app \(xterm-256color\)/);
  assert.match(markdown, /Shell: zsh/);
  assert.match(markdown, /Node\.js: v24\.0\.0/);
  assert.match(markdown, /TTY: true/);
  assert.match(markdown, /Color depth: 24/);
  assert.match(markdown, /Provider\/model: openai\/gpt-4\.1/);
  assert.match(markdown, /Policy\/mode: plan/);
  assert.match(markdown, /Short session id: ses_abcdef12/);
  assert.match(markdown, /Workspace: Secret Project/);
  assert.match(markdown, /- \[model:model-error\] request failed/);
  assert.doesNotMatch(markdown, /\/Users\/alice/);
  assert.doesNotMatch(markdown, /sk-proj-/);
  assert.doesNotMatch(markdown, /sk-test-/);
  assert.doesNotMatch(markdown, /dGhpc2lzYXZlcnlzZWNyZXR0b2tlbjEyMzQ1Njc4OTA=/);
  assert.match(markdown, /\[REDACTED\]/);
});

test('buildLocalReportMarkdown uses feedback wording and unknown for unavailable fields', async () => {
  const state = {
    ...baseState(),
    model: { provider: 'openai' as const, model: '' },
    session: { id: '', cwd: '' },
    errors: []
  };

  const markdown = await buildLocalReportMarkdown(state, {
    kind: 'feedback',
    cliqVersion: null,
    cliqCommit: null,
    env: {},
    platform: '',
    arch: '',
    release: '',
    nodeVersion: ''
  });

  assert.match(markdown, /^# Cliq Feedback Draft/m);
  assert.match(markdown, /## Feedback/);
  assert.match(markdown, /Cliq version: unknown/);
  assert.match(markdown, /Cliq commit: unknown/);
  assert.match(markdown, /Provider\/model: unknown/);
  assert.match(markdown, /Short session id: unknown/);
  assert.match(markdown, /Workspace: unknown/);
  assert.match(markdown, /Recent structured errors:\n- unknown/);
});

test('redactReportText covers common secret patterns', () => {
  const redacted = redactReportText(
    [
      'Authorization: Bearer sk-secretabcdefghijklmnopqrstuvwxyz123456',
      'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456',
      'github_pat_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart',
      'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwPQ=='
    ].join('\n')
  );

  assert.doesNotMatch(redacted, /sk-secret/);
  assert.doesNotMatch(redacted, /sk-ant-api03/);
  assert.doesNotMatch(redacted, /github_pat_/);
  assert.doesNotMatch(redacted, /eyJhbGci/);
  assert.doesNotMatch(redacted, /YWJjZGVm/);
  assert.equal((redacted.match(/\[REDACTED\]/g) ?? []).length, 5);
});
