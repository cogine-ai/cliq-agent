import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { forkSessionFromCheckpoint } from './fork.js';
import { createSession, ensureSession, saveSession } from './store.js';

let originalCliqHome: string | undefined;
let forkCliqHome: string | undefined;

test.beforeEach(async () => {
  originalCliqHome = process.env.CLIQ_HOME;
  forkCliqHome = await mkdtemp(path.join(os.tmpdir(), 'cliq-fork-home-'));
  process.env.CLIQ_HOME = forkCliqHome;
});

test.afterEach(async () => {
  if (originalCliqHome === undefined) {
    delete process.env.CLIQ_HOME;
  } else {
    process.env.CLIQ_HOME = originalCliqHome;
  }
  if (forkCliqHome) {
    await rm(forkCliqHome, { recursive: true, force: true });
  }
  originalCliqHome = undefined;
  forkCliqHome = undefined;
});

test('forkSessionFromCheckpoint creates a child session from the checkpoint prefix and makes it active', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-fork-workspace-'));
  try {
    const parent = createSession(cwd);
    parent.records.push(
      {
        id: 'usr_1',
        ts: '2026-04-29T00:00:00.000Z',
        kind: 'user',
        role: 'user',
        content: 'start task'
      },
      {
        id: 'ast_1',
        ts: '2026-04-29T00:00:01.000Z',
        kind: 'assistant',
        role: 'assistant',
        content: '{"message":"checkpoint ready"}',
        action: { message: 'checkpoint ready' }
      }
    );
    parent.checkpoints.push({
      id: 'chk_keep',
      kind: 'manual',
      name: 'safe point',
      createdAt: '2026-04-29T00:00:02.000Z',
      recordIndex: 2,
      turn: 1,
      workspaceCheckpointId: 'wchk_keep'
    });
    parent.records.push({
      id: 'usr_after',
      ts: '2026-04-29T00:00:03.000Z',
      kind: 'user',
      role: 'user',
      content: 'bad direction'
    });
    await saveSession(cwd, parent);

    const child = await forkSessionFromCheckpoint(cwd, parent, 'chk_keep', { name: 'alternate path' });
    const active = await ensureSession(cwd);

    assert.notEqual(child.id, parent.id);
    assert.equal(child.parentSessionId, parent.id);
    assert.equal(child.forkedFromCheckpointId, 'chk_keep');
    assert.equal(child.name, 'alternate path');
    assert.deepEqual(child.records.map((record) => record.id), ['usr_1', 'ast_1']);
    assert.deepEqual(child.checkpoints.map((checkpoint) => checkpoint.id), ['chk_keep']);
    assert.equal(active.id, child.id);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('forkSessionFromCheckpoint keeps checkpoints only through the exact fork point', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-fork-same-index-'));
  try {
    const parent = createSession(cwd);
    parent.records.push({
      id: 'usr_1',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'user',
      role: 'user',
      content: 'same boundary'
    });
    parent.checkpoints.push(
      {
        id: 'chk_target',
        kind: 'manual',
        createdAt: '2026-04-29T00:00:01.000Z',
        recordIndex: 1,
        turn: 1
      },
      {
        id: 'chk_later_same_boundary',
        kind: 'manual',
        createdAt: '2026-04-29T00:00:02.000Z',
        recordIndex: 1,
        turn: 1
      }
    );
    await saveSession(cwd, parent);

    const child = await forkSessionFromCheckpoint(cwd, parent, 'chk_target');

    assert.deepEqual(child.checkpoints.map((checkpoint) => checkpoint.id), ['chk_target']);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('forkSessionFromCheckpoint rejects unknown checkpoints without changing the active session', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-fork-missing-'));
  try {
    const parent = createSession(cwd);
    await saveSession(cwd, parent);

    await assert.rejects(
      () => forkSessionFromCheckpoint(cwd, parent, 'chk_missing'),
      /checkpoint not found/i
    );
    const active = await ensureSession(cwd);
    assert.equal(active.id, parent.id);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
