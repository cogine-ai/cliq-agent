import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { exportHandoff } from '../handoff/export.js';
import { createCheckpoint } from '../session/checkpoints.js';
import { createCompaction } from '../session/compaction.js';
import { createSession } from '../session/store.js';
import type { SessionRecord } from '../session/types.js';
import { getArtifactView, toSessionRecordView, toSessionView } from './artifacts.js';

const previousHome = process.env.CLIQ_HOME;
const cleanupDirs: string[] = [];

test.after(async () => {
  if (previousHome === undefined) {
    delete process.env.CLIQ_HOME;
  } else {
    process.env.CLIQ_HOME = previousHome;
  }
  await Promise.all(cleanupDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function setupWorkspace() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-artifacts-home-'));
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-artifacts-workspace-'));
  cleanupDirs.push(home, cwd);
  process.env.CLIQ_HOME = home;
  return { home, cwd };
}

test('toSessionView exposes stable records without raw assistant JSON', async () => {
  const { cwd } = await setupWorkspace();
  const session = createSession(cwd);
  session.records.push(
    { id: 'usr_1', ts: '2026-05-03T00:00:00.000Z', kind: 'user', role: 'user', content: 'hello' },
    {
      id: 'ast_1',
      ts: '2026-05-03T00:00:01.000Z',
      kind: 'assistant',
      role: 'assistant',
      content: '{"message":"done"}',
      action: { message: 'done' }
    },
    {
      id: 'tool_1',
      ts: '2026-05-03T00:00:02.000Z',
      kind: 'tool',
      role: 'user',
      tool: 'bash',
      status: 'ok',
      content: `TOOL_RESULT bash OK\n${'x'.repeat(500)}`,
      meta: { exit: 0 }
    }
  );

  const view = toSessionView(session);

  assert.equal(view.records[0]?.kind, 'user');
  assert.equal(view.records[1]?.kind, 'assistant');
  assert.deepEqual(view.records[1], {
    id: 'ast_1',
    ts: '2026-05-03T00:00:01.000Z',
    kind: 'assistant',
    role: 'assistant',
    actionType: 'message',
    message: 'done'
  });
  assert.equal(view.records[2]?.kind, 'tool');
  assert.equal('content' in view.records[2]!, false);
  assert.equal((view.records[2] as { contentPreview: string }).contentPreview.length <= 280, true);
});

test('getArtifactView resolves checkpoint, workspace checkpoint, compaction, and handoff views', async () => {
  const { cwd } = await setupWorkspace();
  const session = createSession(cwd);
  session.records.push(
    { id: 'usr_1', ts: '2026-05-03T00:00:00.000Z', kind: 'user', role: 'user', content: 'summarize' },
    {
      id: 'ast_1',
      ts: '2026-05-03T00:00:01.000Z',
      kind: 'assistant',
      role: 'assistant',
      content: '{"message":"ok"}',
      action: { message: 'ok' }
    }
  );

  const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual', name: 'manual' });
  const compaction = await createCompaction(cwd, session, {
    endIndexExclusive: 1,
    summaryMarkdown: 'summary'
  });
  const handoff = await exportHandoff(cwd, session, { checkpointId: checkpoint.id });

  assert.equal((await getArtifactView(session, checkpoint.id)).kind, 'checkpoint');
  assert.equal((await getArtifactView(session, checkpoint.workspaceCheckpointId!)).kind, 'workspace-checkpoint');
  assert.equal((await getArtifactView(session, compaction.id)).kind, 'compaction');
  const handoffView = await getArtifactView(session, handoff.id);
  assert.equal(handoffView.kind, 'handoff');
  assert.equal('json' in handoffView.handoff, false);
  assert.equal('paths' in handoffView.handoff, false);
  assert.match(handoffView.handoff.summaryMarkdown, /summary/);
  assert.match(handoffView.handoff.markdown, /# Handoff/);
  await assert.rejects(() => getArtifactView(session, 'missing'), /artifact not found/i);
  await assert.rejects(() => getArtifactView(session, 'wchk_missing'), /artifact not found/i);
  await assert.rejects(() => getArtifactView(session, 'handoff_missing'), /artifact not found/i);
  await assert.rejects(() => getArtifactView(session, 'handoff_../../../outside'), /artifact not found/i);

  session.checkpoints.push({
    id: 'chk_missing_workspace',
    kind: 'manual',
    createdAt: '2026-05-03T00:00:02.000Z',
    recordIndex: 1,
    turn: 1,
    workspaceCheckpointId: 'wchk_missing_for_checkpoint'
  });
  await assert.rejects(() => getArtifactView(session, 'chk_missing_workspace'), /artifact not found/i);
});

test('toSessionView renders tx-opened with txId, name, explicit:true', async () => {
  const { cwd } = await setupWorkspace();
  const session = createSession(cwd);
  session.records.push({
    id: 'txrec_open_tx_01H',
    ts: '2026-05-06T10:00:00.000Z',
    kind: 'tx-opened',
    role: 'user',
    content: 'Transaction tx_01H opened (explicit)',
    meta: { txId: 'tx_01H', txKind: 'edit', name: 'refactor', explicit: true }
  });

  const view = toSessionView(session);
  const opened = view.records[0];
  assert.equal(opened?.kind, 'tx-opened');
  assert.equal((opened as { txId: string }).txId, 'tx_01H');
  assert.equal((opened as { name?: string }).name, 'refactor');
  assert.equal((opened as { explicit: true }).explicit, true);
  assert.equal('text' in opened!, false);
  assert.equal('content' in opened!, false);
});

test('toSessionView renders tx-applied with structured diffSummary, validators, overrides, artifactRef', async () => {
  const { cwd } = await setupWorkspace();
  const session = createSession(cwd);
  session.records.push({
    id: 'txrec_apply_tx_02H',
    ts: '2026-05-06T10:01:00.000Z',
    kind: 'tx-applied',
    role: 'user',
    content: 'Transaction tx_02H applied: 4 files changed (+12 -3)',
    meta: {
      txId: 'tx_02H',
      txKind: 'edit',
      diffSummary: { filesChanged: 4, additions: 12, deletions: 3, creates: [], modifies: ['a.ts', 'b.ts', 'c.ts', 'd.ts'], deletes: [] },
      files: { creates: [], modifies: ['a.ts', 'b.ts', 'c.ts', 'd.ts'], deletes: [] },
      validators: { blocking: { pass: 2, fail: 0 }, advisory: { pass: 1, fail: 1, names: ['shell:tests'] } },
      overrides: [{ validatorName: 'shell:tsc', by: 'cli', ts: '2026-05-06T10:00:30.000Z' }],
      artifactRef: 'tx/tx_02H/',
      ghostSnapshotId: 'ws_chk_xyz'
    }
  });

  const view = toSessionView(session);
  const applied = view.records[0];
  assert.equal(applied?.kind, 'tx-applied');
  const a = applied as {
    txId: string;
    diffSummary: { filesChanged: number };
    validators: { advisory: { names: string[] } };
    overrides: Array<{ validatorName: string }>;
    artifactRef: string;
    ghostSnapshotId?: string;
  };
  assert.equal(a.txId, 'tx_02H');
  assert.equal(a.diffSummary.filesChanged, 4);
  assert.deepEqual(a.validators.advisory.names, ['shell:tests']);
  assert.equal(a.overrides[0].validatorName, 'shell:tsc');
  assert.equal(a.artifactRef, 'tx/tx_02H/');
  assert.equal(a.ghostSnapshotId, 'ws_chk_xyz');
  assert.equal('text' in applied!, false);
});

test('toSessionView renders tx-aborted with reason, artifactRef, optional appliedPartial', async () => {
  const { cwd } = await setupWorkspace();
  const session = createSession(cwd);
  session.records.push({
    id: 'txrec_abort_tx_03H',
    ts: '2026-05-06T10:02:00.000Z',
    kind: 'tx-aborted',
    role: 'user',
    content: 'Transaction tx_03H aborted: apply-failed-partial-kept',
    meta: {
      txId: 'tx_03H',
      txKind: 'edit',
      reason: 'apply-failed-partial-kept',
      files: { wouldHaveCreated: [], wouldHaveModified: ['x.ts', 'y.ts'], wouldHaveDeleted: [] },
      artifactRef: 'tx/tx_03H/',
      appliedPartial: { partialFiles: ['x.ts'], ghostSnapshotId: 'ws_chk_abc', restoreConfirmed: false }
    }
  });

  const view = toSessionView(session);
  const aborted = view.records[0];
  assert.equal(aborted?.kind, 'tx-aborted');
  const a = aborted as {
    txId: string;
    reason: string;
    artifactRef: string;
    appliedPartial?: { partialFiles: string[]; restoreConfirmed: boolean };
  };
  assert.equal(a.txId, 'tx_03H');
  assert.equal(a.reason, 'apply-failed-partial-kept');
  assert.equal(a.artifactRef, 'tx/tx_03H/');
  assert.deepEqual(a.appliedPartial?.partialFiles, ['x.ts']);
  assert.equal(a.appliedPartial?.restoreConfirmed, false);
  assert.equal('text' in aborted!, false);
});

test('toSessionRecordView renders tx-opened with txId, optional name, explicit:true', () => {
  const rec: SessionRecord = {
    id: 'txrec_open_tx_a',
    ts: 'x',
    kind: 'tx-opened',
    role: 'user',
    content: 'opened',
    meta: { txId: 'tx_a', txKind: 'edit', name: 'feature', explicit: true }
  };
  const view = toSessionRecordView(rec);
  assert.equal(view.kind, 'tx-opened');
  if (view.kind === 'tx-opened') {
    assert.equal(view.txId, 'tx_a');
    assert.equal(view.name, 'feature');
    assert.equal(view.explicit, true);
  }
});

test('toSessionRecordView renders tx-applied with diffSummary and artifactRef', () => {
  const rec: SessionRecord = {
    id: 'txrec_apply_tx_b',
    ts: 'x',
    kind: 'tx-applied',
    role: 'user',
    content: 'applied',
    meta: {
      txId: 'tx_b',
      txKind: 'edit',
      diffSummary: { filesChanged: 1, additions: 0, deletions: 0, creates: [], modifies: ['a.txt'], deletes: [] },
      files: { creates: [], modifies: ['a.txt'], deletes: [] },
      validators: { blocking: { pass: 1, fail: 0 }, advisory: { pass: 0, fail: 0, names: [] } },
      overrides: [],
      artifactRef: 'tx/tx_b/'
    }
  };
  const view = toSessionRecordView(rec);
  assert.equal(view.kind, 'tx-applied');
  if (view.kind === 'tx-applied') {
    assert.equal(view.txId, 'tx_b');
    assert.deepEqual(view.diffSummary.modifies, ['a.txt']);
  }
});

test('toSessionRecordView renders tx-aborted with reason and optional appliedPartial', () => {
  const rec: SessionRecord = {
    id: 'txrec_abort_tx_c',
    ts: 'x',
    kind: 'tx-aborted',
    role: 'user',
    content: 'aborted',
    meta: {
      txId: 'tx_c',
      txKind: 'edit',
      reason: 'apply-failed-partial-restored',
      files: { wouldHaveCreated: [], wouldHaveModified: ['a.txt'], wouldHaveDeleted: [] },
      artifactRef: 'tx/tx_c/',
      appliedPartial: { partialFiles: ['a.txt'], ghostSnapshotId: 'wchk_x', restoreConfirmed: true }
    }
  };
  const view = toSessionRecordView(rec);
  assert.equal(view.kind, 'tx-aborted');
  if (view.kind === 'tx-aborted') {
    assert.equal(view.txId, 'tx_c');
    assert.equal(view.appliedPartial?.restoreConfirmed, true);
  }
});
