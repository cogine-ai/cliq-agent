import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { exportHandoff } from '../handoff/export.js';
import { createCheckpoint } from '../session/checkpoints.js';
import { createCompaction } from '../session/compaction.js';
import {
  createSession,
  ensureSession,
  saveSession,
  sessionFilePath,
  workspaceStatePath
} from '../session/store.js';
import {
  ArtifactNotFoundError,
  getArtifactView,
  getArtifactViewForRequest,
  getSessionView,
  SessionNotFoundError,
  toSessionView
} from './artifacts.js';

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

async function setupSharedHomeWorkspaces() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-artifacts-home-'));
  const workspaceA = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-artifacts-workspace-a-'));
  const workspaceB = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-artifacts-workspace-b-'));
  cleanupDirs.push(home, workspaceA, workspaceB);
  process.env.CLIQ_HOME = home;
  return { home, workspaceA, workspaceB };
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
  await assert.rejects(() => getArtifactView(session, 'missing'), ArtifactNotFoundError);
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

test('getSessionView returns active and explicit session views for a workspace', async () => {
  const { cwd } = await setupWorkspace();
  const active = await ensureSession(cwd);
  active.records.push({
    id: 'usr_rpc_1',
    ts: '2026-05-06T00:00:00.000Z',
    kind: 'user',
    role: 'user',
    content: 'hello'
  });
  await saveSession(cwd, active);

  const activeView = await getSessionView(cwd);
  const explicitView = await getSessionView(cwd, active.id);

  assert.equal(activeView.id, active.id);
  assert.equal(explicitView.id, active.id);
  assert.equal(explicitView.records[0]?.kind, 'user');
});

test('getSessionView rejects unknown session ids without creating raw file contracts', async () => {
  const { cwd } = await setupWorkspace();
  await ensureSession(cwd);

  await assert.rejects(
    async () => await getSessionView(cwd, 'sess_missing'),
    SessionNotFoundError
  );
});

test('getSessionView does not create storage state when no active session exists', async () => {
  const { home, cwd } = await setupWorkspace();

  await assert.rejects(async () => await getSessionView(cwd), SessionNotFoundError);

  const homeEntries = (await readdir(home)).filter((entry) => !entry.startsWith('.'));
  assert.deepEqual(homeEntries, []);
});

test('getSessionView rejects explicit ids whose stored path belongs to another workspace', async () => {
  const { cwd: workspaceA } = await setupWorkspace();
  const workspaceB = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-artifacts-other-workspace-'));
  cleanupDirs.push(workspaceB);

  await ensureSession(workspaceA);
  const sessionB = await ensureSession(workspaceB);
  const statePathA = await workspaceStatePath(workspaceA);
  const stateA = JSON.parse(await readFile(statePathA, 'utf8')) as {
    recentSessions: Array<{
      id: string;
      path: string;
      createdAt: string;
      updatedAt: string;
    }>;
  };

  stateA.recentSessions = [
    {
      id: sessionB.id,
      path: sessionFilePath(sessionB),
      createdAt: sessionB.createdAt,
      updatedAt: sessionB.updatedAt
    },
    ...stateA.recentSessions.filter((entry) => entry.id !== sessionB.id)
  ];
  await writeFile(statePathA, JSON.stringify(stateA, null, 2), 'utf8');

  await assert.rejects(
    async () => await getSessionView(workspaceA, sessionB.id),
    (error: unknown) => error instanceof SessionNotFoundError && error.sessionId === sessionB.id
  );
});

test('getArtifactViewForRequest resolves artifacts through stable session lookup', async () => {
  const { cwd } = await setupWorkspace();
  const session = await ensureSession(cwd);
  session.records.push({
    id: 'usr_rpc_1',
    ts: '2026-05-06T00:00:00.000Z',
    kind: 'user',
    role: 'user',
    content: 'checkpoint me'
  });
  await saveSession(cwd, session);
  const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual', name: 'rpc-checkpoint' });

  const artifact = await getArtifactViewForRequest(cwd, checkpoint.id, session.id);

  assert.equal(artifact.kind, 'checkpoint');
  assert.equal(artifact.checkpoint.id, checkpoint.id);
});

test('getArtifactViewForRequest rejects workspace checkpoint and handoff artifacts from another session', async () => {
  const { workspaceA, workspaceB } = await setupSharedHomeWorkspaces();
  const sessionA = await ensureSession(workspaceA);
  sessionA.records.push({
    id: 'usr_a_1',
    ts: '2026-05-06T00:00:00.000Z',
    kind: 'user',
    role: 'user',
    content: 'session a'
  });
  await saveSession(workspaceA, sessionA);

  const sessionB = await ensureSession(workspaceB);
  sessionB.records.push({
    id: 'usr_b_1',
    ts: '2026-05-06T00:00:00.000Z',
    kind: 'user',
    role: 'user',
    content: 'session b'
  });
  const checkpointB = await createCheckpoint(workspaceB, sessionB, { kind: 'manual', name: 'session-b' });
  const handoffB = await exportHandoff(workspaceB, sessionB, { checkpointId: checkpointB.id });

  await assert.rejects(
    async () => await getArtifactViewForRequest(workspaceA, checkpointB.workspaceCheckpointId!, sessionA.id),
    (error: unknown) =>
      error instanceof ArtifactNotFoundError && error.artifactId === checkpointB.workspaceCheckpointId
  );
  await assert.rejects(
    async () => await getArtifactViewForRequest(workspaceA, handoffB.id, sessionA.id),
    (error: unknown) => error instanceof ArtifactNotFoundError && error.artifactId === handoffB.id
  );
});
