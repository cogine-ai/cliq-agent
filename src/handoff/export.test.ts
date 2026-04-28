import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { exportHandoff, handoffDirPath } from './export.js';
import { createSession } from '../session/store.js';

const originalCliqHome = process.env.CLIQ_HOME;
const handoffCliqHome = await mkdtemp(path.join(os.tmpdir(), 'cliq-handoff-home-'));
process.env.CLIQ_HOME = handoffCliqHome;

test.after(async () => {
  if (originalCliqHome === undefined) {
    delete process.env.CLIQ_HOME;
  } else {
    process.env.CLIQ_HOME = originalCliqHome;
  }
  await rm(handoffCliqHome, { recursive: true, force: true });
});

test('exportHandoff creates a handoff-only summary when no active compaction exists', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-handoff-workspace-'));
  try {
    const session = createSession(cwd);
    session.records.push({
      id: 'usr_1',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'user',
      role: 'user',
      content: 'Implement checkpoint restore'
    });

    const artifact = await exportHandoff(cwd, session);
    const dir = handoffDirPath(artifact.id);
    const json = JSON.parse(await readFile(path.join(dir, 'handoff.json'), 'utf8')) as typeof artifact;
    const markdown = await readFile(path.join(dir, 'HANDOFF.md'), 'utf8');

    assert.equal(artifact.sessionId, session.id);
    assert.equal(artifact.activeCompactionId, undefined);
    assert.equal(artifact.summarySource, 'handoff-only');
    assert.equal(session.compactions.length, 0);
    assert.equal(session.checkpoints.at(-1)?.kind, 'handoff');
    assert.equal(json.id, artifact.id);
    assert.match(markdown, /Implement checkpoint restore/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('exportHandoff reuses active compact summary without creating a new compaction', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-handoff-compact-'));
  try {
    const session = createSession(cwd);
    session.records.push(
      {
        id: 'usr_old',
        ts: '2026-04-29T00:00:00.000Z',
        kind: 'user',
        role: 'user',
        content: 'old detail'
      },
      {
        id: 'usr_tail',
        ts: '2026-04-29T00:00:01.000Z',
        kind: 'user',
        role: 'user',
        content: 'tail detail'
      }
    );
    session.compactions.push({
      id: 'cmp_1',
      status: 'active',
      createdAt: '2026-04-29T00:00:02.000Z',
      coveredRange: { startIndexInclusive: 0, endIndexExclusive: 1 },
      firstKeptRecordId: 'usr_tail',
      createdBy: { provider: 'ollama', model: 'qwen3:4b' },
      summaryMarkdown: '## Objective\nUse compact summary'
    });
    session.checkpoints.push({
      id: 'chk_existing',
      kind: 'manual',
      createdAt: '2026-04-29T00:00:03.000Z',
      recordIndex: 1,
      turn: 1
    });

    const artifact = await exportHandoff(cwd, session, { checkpointId: 'chk_existing' });

    assert.equal(artifact.activeCompactionId, 'cmp_1');
    assert.equal(artifact.checkpointId, 'chk_existing');
    assert.equal(artifact.summarySource, 'active-compaction');
    assert.match(artifact.summaryMarkdown, /Use compact summary/);
    assert.match(artifact.summaryMarkdown, /tail detail/);
    assert.equal(session.compactions.length, 1);
    assert.equal(session.checkpoints.length, 1);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
