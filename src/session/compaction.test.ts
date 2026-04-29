import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createCompaction } from './compaction.js';
import { createSession, ensureSession } from './store.js';

async function withCliqHome(callback: () => Promise<void>) {
  const originalCliqHome = process.env.CLIQ_HOME;
  const compactionCliqHome = await mkdtemp(path.join(os.tmpdir(), 'cliq-compaction-home-'));

  try {
    process.env.CLIQ_HOME = compactionCliqHome;
    await callback();
  } finally {
    if (originalCliqHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = originalCliqHome;
    }
    await rm(compactionCliqHome, { recursive: true, force: true });
  }
}

function addUserRecords(session: ReturnType<typeof createSession>, count: number) {
  for (let index = 0; index < count; index += 1) {
    session.records.push({
      id: `usr_${index}`,
      ts: `2026-04-29T00:00:0${index}.000Z`,
      kind: 'user',
      role: 'user',
      content: `message ${index}`
    });
  }
}

test('createCompaction creates one active artifact and records the first kept tail record', async () => {
  await withCliqHome(async () => {
    const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-compaction-workspace-'));
    try {
      const session = createSession(cwd);
      addUserRecords(session, 4);

      const artifact = await createCompaction(cwd, session, {
        endIndexExclusive: 2,
        summaryMarkdown: '## Objective\nKeep going'
      });
      const persisted = await ensureSession(cwd);

      assert.equal(artifact.status, 'active');
      assert.deepEqual(artifact.coveredRange, { startIndexInclusive: 0, endIndexExclusive: 2 });
      assert.equal(artifact.firstKeptRecordId, 'usr_2');
      assert.equal(artifact.createdBy.provider, 'ollama');
      assert.equal(persisted.compactions.length, 1);
      assert.equal(persisted.compactions[0]?.id, artifact.id);
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });
});

test('createCompaction supersedes the previous active compaction and rejects non-advancing ranges', async () => {
  await withCliqHome(async () => {
    const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-compaction-supersede-'));
    try {
      const session = createSession(cwd);
      addUserRecords(session, 5);

      const first = await createCompaction(cwd, session, {
        endIndexExclusive: 2,
        summaryMarkdown: 'first summary'
      });
      await assert.rejects(
        () =>
          createCompaction(cwd, session, {
            endIndexExclusive: 2,
            summaryMarkdown: 'same range'
          }),
        /must advance/i
      );

      const second = await createCompaction(cwd, session, {
        endIndexExclusive: 3,
        summaryMarkdown: 'second summary'
      });

      assert.equal(session.compactions.find((artifact) => artifact.id === first.id)?.status, 'superseded');
      assert.equal(session.compactions.find((artifact) => artifact.id === second.id)?.status, 'active');
      assert.equal(session.compactions.filter((artifact) => artifact.status === 'active').length, 1);
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });
});

test('createCompaction rejects ranges that leave no raw tail', async () => {
  await withCliqHome(async () => {
    const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-compaction-tail-'));
    try {
      const session = createSession(cwd);
      addUserRecords(session, 2);

      await assert.rejects(
        () =>
          createCompaction(cwd, session, {
            endIndexExclusive: 2,
            summaryMarkdown: 'too much'
          }),
        /non-empty tail/i
      );
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });
});
