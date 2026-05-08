import test from 'node:test';
import assert from 'node:assert/strict';

import { createSession } from '../session/store.js';
import { buildContextMessages } from './context.js';

test('buildContextMessages emits active compact summary plus raw tail records', () => {
  const session = createSession('/tmp/workspace');
  session.records.push(
    {
      id: 'usr_old',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'user',
      role: 'user',
      content: 'old raw detail'
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
    id: 'cmp_active',
    status: 'active',
    createdAt: '2026-04-29T00:00:02.000Z',
    coveredRange: { startIndexInclusive: 0, endIndexExclusive: 1 },
    firstKeptRecordId: 'usr_tail',
    createdBy: { provider: 'ollama', model: 'qwen3:4b' },
    summaryMarkdown: '## Objective\nSummarized old detail'
  });

  const messages = buildContextMessages(session, [
    { role: 'system', layer: 'core', source: 'base', content: 'BASE' }
  ]);

  assert.deepEqual(messages.map((message) => message.role), ['system', 'system', 'user']);
  assert.equal(messages[0]?.content, 'BASE');
  assert.match(messages[1]?.content ?? '', /Summarized old detail/);
  assert.equal(messages[2]?.content, 'tail detail');
  assert.equal(messages.some((message) => message.content === 'old raw detail'), false);
});

test('buildContextMessages falls back to full raw history without active compaction', () => {
  const session = createSession('/tmp/workspace');
  session.records.push({
    id: 'usr_1',
    ts: '2026-04-29T00:00:00.000Z',
    kind: 'user',
    role: 'user',
    content: 'raw detail'
  });

  const messages = buildContextMessages(session, [
    { role: 'system', layer: 'core', source: 'base', content: 'BASE' }
  ]);

  assert.deepEqual(messages.map((message) => message.content), ['BASE', 'raw detail']);
});

test('buildContextMessages emits tx-opened, tx-applied, tx-aborted as user messages', () => {
  const session = createSession('/tmp/workspace');
  session.records.push(
    {
      id: 'txrec_open_tx_aa',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'tx-opened',
      role: 'user',
      content: 'Transaction tx_aa opened (explicit)',
      meta: { txId: 'tx_aa', txKind: 'edit', explicit: true, name: 'refactor foo' }
    },
    {
      id: 'txrec_apply_tx_aa',
      ts: '2026-04-29T00:00:01.000Z',
      kind: 'tx-applied',
      role: 'user',
      content: 'Transaction tx_aa applied',
      meta: {
        txId: 'tx_aa',
        txKind: 'edit',
        diffSummary: {
          filesChanged: 1,
          additions: 5,
          deletions: 2,
          creates: [],
          modifies: ['src/foo.ts'],
          deletes: []
        },
        files: { creates: [], modifies: ['src/foo.ts'], deletes: [] },
        validators: { blocking: { pass: 1, fail: 0 }, advisory: { pass: 0, fail: 0, names: [] } },
        overrides: [],
        artifactRef: '~/.cliq/transactions/tx_aa'
      }
    },
    {
      id: 'txrec_abort_tx_bb',
      ts: '2026-04-29T00:00:02.000Z',
      kind: 'tx-aborted',
      role: 'user',
      content: 'Transaction tx_bb aborted: user-abort',
      meta: {
        txId: 'tx_bb',
        txKind: 'edit',
        reason: 'user-abort',
        files: { wouldHaveCreated: [], wouldHaveModified: ['src/bar.ts'], wouldHaveDeleted: [] },
        artifactRef: '~/.cliq/transactions/tx_bb'
      }
    }
  );

  const messages = buildContextMessages(session, [
    { role: 'system', layer: 'core', source: 'base', content: 'BASE' }
  ]);

  // Head (system) + 3 tx records all rendered as user messages with their content fields.
  assert.deepEqual(
    messages.map((m) => m.role),
    ['system', 'user', 'user', 'user']
  );
  assert.equal(messages[0]?.content, 'BASE');
  assert.equal(messages[1]?.content, 'Transaction tx_aa opened (explicit)');
  assert.equal(messages[2]?.content, 'Transaction tx_aa applied');
  assert.equal(messages[3]?.content, 'Transaction tx_bb aborted: user-abort');
});
