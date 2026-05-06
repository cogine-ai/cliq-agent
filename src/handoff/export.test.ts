import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { exportHandoff, handoffDirPath, readHandoffArtifact } from './export.js';
import { createSession } from '../session/store.js';

async function withCliqHome<T>(callback: (home: string) => Promise<T>) {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-handoff-home-'));
  const previousHome = process.env.CLIQ_HOME;
  try {
    process.env.CLIQ_HOME = home;
    return await callback(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(home, { recursive: true, force: true });
  }
}

test('exportHandoff creates a handoff-only summary when no active compaction exists', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-handoff-workspace-'));
  try {
    await withCliqHome(async () => {
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
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('exportHandoff reuses active compact summary without creating a new compaction', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-handoff-compact-'));
  try {
    await withCliqHome(async () => {
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
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('exportHandoff renders tx-opened/tx-applied/tx-aborted records in the markdown', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-handoff-tx-'));
  try {
    await withCliqHome(async () => {
      const session = createSession(cwd);
      session.records.push(
        {
          id: 'usr_1',
          ts: '2026-04-29T00:00:00.000Z',
          kind: 'user',
          role: 'user',
          content: 'kick off'
        },
        {
          id: 'txrec_open_tx_aa',
          ts: '2026-04-29T00:00:01.000Z',
          kind: 'tx-opened',
          role: 'user',
          content: 'Transaction tx_aa opened (explicit)',
          meta: { txId: 'tx_aa', txKind: 'edit', explicit: true, name: 'refactor foo' }
        },
        {
          id: 'txrec_apply_tx_aa',
          ts: '2026-04-29T00:00:02.000Z',
          kind: 'tx-applied',
          role: 'user',
          content: 'Transaction tx_aa applied',
          meta: {
            txId: 'tx_aa',
            txKind: 'edit',
            diffSummary: {
              filesChanged: 3,
              additions: 12,
              deletions: 4,
              creates: [],
              modifies: ['src/a.ts', 'src/b.ts', 'src/c.ts'],
              deletes: []
            },
            files: { creates: [], modifies: ['src/a.ts', 'src/b.ts', 'src/c.ts'], deletes: [] },
            validators: { blocking: { pass: 2, fail: 0 }, advisory: { pass: 0, fail: 0, names: [] } },
            overrides: [],
            artifactRef: '~/.cliq/transactions/tx_aa'
          }
        },
        {
          id: 'txrec_abort_tx_bb',
          ts: '2026-04-29T00:00:03.000Z',
          kind: 'tx-aborted',
          role: 'user',
          content: 'Transaction tx_bb aborted: validator-fail',
          meta: {
            txId: 'tx_bb',
            txKind: 'edit',
            reason: 'validator-fail',
            files: { wouldHaveCreated: [], wouldHaveModified: ['src/x.ts'], wouldHaveDeleted: [] },
            artifactRef: '~/.cliq/transactions/tx_bb'
          }
        }
      );

      const artifact = await exportHandoff(cwd, session);
      const markdown = await readFile(path.join(handoffDirPath(artifact.id), 'HANDOFF.md'), 'utf8');

      assert.match(markdown, /tx-opened "refactor foo" \(tx_aa\)/);
      assert.match(markdown, /tx-applied \(tx_aa\): 3 files changed/);
      assert.match(markdown, /tx-aborted \(tx_bb\): validator-fail/);
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('readHandoffArtifact rejects unsafe handoff ids before path access', async () => {
  await withCliqHome(async () => {
    await assert.rejects(() => readHandoffArtifact('../outside'), /invalid handoff id/i);
    await assert.rejects(() => readHandoffArtifact('handoff_../../outside'), /invalid handoff id/i);
    assert.throws(() => handoffDirPath('handoff_/outside'), /invalid handoff id/i);
  });
});
