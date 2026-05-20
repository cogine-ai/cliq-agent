import assert from 'node:assert/strict';
import test from 'node:test';

import { buildToolApprovalSubject, buildTxApplyApprovalSubject } from './subjects.js';
import type { TxReviewSnapshot } from '../workspace/transactions/inspect.js';

test('buildToolApprovalSubject creates a bash approval subject with command payload', () => {
  const subject = buildToolApprovalSubject({
    definition: { name: 'bash', access: 'exec' },
    action: { bash: 'npm test' }
  });

  assert.equal(subject.kind, 'tool');
  assert.equal(subject.toolName, 'bash');
  assert.equal(subject.access, 'exec');
  assert.deepEqual(subject.action, { bash: 'npm test' });
  assert.equal(subject.display.title, 'Allow bash command?');
  assert.equal(subject.display.command, 'npm test');
  if (subject.kind === 'tool') {
    assert.deepEqual(subject.channel, { kind: 'bash', commandHead: 'npm', compound: false });
  }
});

test('buildToolApprovalSubject extracts a clean command head for bash with env prefixes', () => {
  const subject = buildToolApprovalSubject({
    definition: { name: 'bash', access: 'exec' },
    action: { bash: 'NODE_ENV=production sudo -u deploy git push' }
  });

  if (subject.kind === 'tool') {
    assert.deepEqual(subject.channel, { kind: 'bash', commandHead: 'git', compound: false });
  }
});

test('buildToolApprovalSubject reports empty commandHead for unidentifiable bash lines', () => {
  const subject = buildToolApprovalSubject({
    definition: { name: 'bash', access: 'exec' },
    action: { bash: '&& ls' }
  });

  if (subject.kind === 'tool') {
    // Empty string is the explicit "no head" sentinel; allowlist matching
    // MUST fall through to ask/preset instead of guessing.
    assert.deepEqual(subject.channel, { kind: 'bash', commandHead: '', compound: false });
  }
});

test('buildToolApprovalSubject marks compound bash lines', () => {
  const subject = buildToolApprovalSubject({
    definition: { name: 'bash', access: 'exec' },
    action: { bash: 'git status && rm -rf /' }
  });

  if (subject.kind === 'tool') {
    assert.deepEqual(subject.channel, { kind: 'bash', commandHead: 'git', compound: true });
  }
});

test('buildToolApprovalSubject marks TX edits as staged and includes the path', () => {
  const subject = buildToolApprovalSubject({
    definition: { name: 'edit', access: 'write' },
    action: { edit: { path: 'src/index.ts', old_text: 'old', new_text: 'new' } },
    tx: { enabled: true, txId: 'tx_review', mode: 'edit' }
  });

  assert.equal(subject.kind, 'tool');
  assert.equal(subject.display.title, 'Allow staged edit?');
  assert.equal(subject.display.path, 'src/index.ts');
  if (subject.kind === 'tool') {
    assert.deepEqual(subject.channel, { kind: 'fs-write', path: 'src/index.ts', op: 'modify' });
    assert.deepEqual(subject.tx, { enabled: true, txId: 'tx_review', mode: 'edit' });
  }
});

test('buildToolApprovalSubject creates fallback display detail for other tools', () => {
  const subject = buildToolApprovalSubject({
    definition: { name: 'grep', access: 'read' },
    action: { grep: { path: 'src', pattern: 'createRunner' } }
  });

  assert.equal(subject.kind, 'tool');
  assert.equal(subject.display.title, 'Allow grep?');
  assert.equal(subject.display.detail, '{"grep":{"path":"src","pattern":"createRunner"}}');
  if (subject.kind === 'tool') {
    assert.deepEqual(subject.channel, { kind: 'fs-read', path: 'src' });
  }
});

test('buildToolApprovalSubject derives fs-read channel for read/ls/find with omitted path', () => {
  const ls = buildToolApprovalSubject({
    definition: { name: 'ls', access: 'read' },
    action: { ls: {} }
  });
  if (ls.kind === 'tool') {
    assert.deepEqual(ls.channel, { kind: 'fs-read', path: '' });
  }

  const find = buildToolApprovalSubject({
    definition: { name: 'find', access: 'read' },
    action: { find: { name: '*.ts' } }
  });
  if (find.kind === 'tool') {
    assert.deepEqual(find.channel, { kind: 'fs-read', path: '' });
  }

  const read = buildToolApprovalSubject({
    definition: { name: 'read', access: 'read' },
    action: { read: { path: 'docs/README.md' } }
  });
  if (read.kind === 'tool') {
    assert.deepEqual(read.channel, { kind: 'fs-read', path: 'docs/README.md' });
  }
});

test('buildToolApprovalSubject truncates long fallback display detail', () => {
  const subject = buildToolApprovalSubject({
    definition: { name: 'grep', access: 'read' },
    action: { grep: { path: 'src', pattern: 'x'.repeat(1000) } }
  });

  assert.equal(subject.kind, 'tool');
  assert.ok(subject.display.detail);
  assert.ok(subject.display.detail.length <= 300);
  assert.ok(subject.display.detail.startsWith('{"grep":{"path":"src","pattern":"'));
  assert.ok(subject.display.detail.endsWith('... (truncated)'));
});

test('buildTxApplyApprovalSubject copies transaction review fields', () => {
  const snapshot = {
    tx: {
      id: 'tx_apply',
      kind: 'edit',
      state: 'validated',
      workspaceId: 'ws',
      sessionId: 'sess',
      workspaceRealPath: '/tmp/ws',
      createdAt: '2026-05-12T00:00:00Z',
      updatedAt: '2026-05-12T00:00:01Z',
      diffSummary: {
        filesChanged: 1,
        additions: 2,
        deletions: 1,
        creates: [],
        modifies: ['src/index.ts'],
        deletes: []
      },
      validators: [{ name: 'tsc', severity: 'blocking', status: 'pass', durationMs: 12 }],
      blockingFailures: []
    },
    diff: null,
    audit: [],
    bashEffects: [],
    validatorResults: [],
    validatorArtifactResults: [],
    validatorArtifactErrors: [],
    artifactRef: 'tx/tx_apply/'
  } satisfies TxReviewSnapshot;

  const subject = buildTxApplyApprovalSubject(snapshot);

  assert.deepEqual(subject, {
    kind: 'tx-apply',
    txId: 'tx_apply',
    diffSummary: snapshot.tx.diffSummary,
    validators: snapshot.tx.validators,
    blockingFailures: [],
    artifactRef: 'tx/tx_apply/'
  });
});
