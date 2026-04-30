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
