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
  assert.deepEqual(subject.tx, { enabled: true, txId: 'tx_review', mode: 'edit' });
});

test('buildToolApprovalSubject creates fallback display detail for other tools', () => {
  const subject = buildToolApprovalSubject({
    definition: { name: 'grep', access: 'read' },
    action: { grep: { path: 'src', pattern: 'createRunner' } }
  });

  assert.equal(subject.kind, 'tool');
  assert.equal(subject.display.title, 'Allow grep?');
  assert.equal(subject.display.detail, '{"grep":{"path":"src","pattern":"createRunner"}}');
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
