import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from './store.js';
import {
  estimateMessagesTokens,
  estimateRecordTokens,
  maybeAutoCompact,
  selectAutoCompactRange,
  serializeRecordForSummary
} from './auto-compaction.js';

async function withTempSession(callback: (input: { cwd: string; session: ReturnType<typeof createSession> }) => Promise<void>) {
  const originalCliqHome = process.env.CLIQ_HOME;
  const cliqHome = await mkdtemp(path.join(os.tmpdir(), 'cliq-auto-compact-home-'));
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-auto-compact-workspace-'));
  try {
    process.env.CLIQ_HOME = cliqHome;
    await callback({ cwd, session: createSession(cwd) });
  } finally {
    if (originalCliqHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = originalCliqHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(cliqHome, { recursive: true, force: true });
  }
}

function user(id: string, content: string) {
  return { id, ts: '2026-04-30T00:00:00.000Z', kind: 'user' as const, role: 'user' as const, content };
}

function assistant(id: string, content: string, action: any = { message: content }) {
  return { id, ts: '2026-04-30T00:00:01.000Z', kind: 'assistant' as const, role: 'assistant' as const, content, action };
}

function tool(id: string, content: string) {
  return {
    id,
    ts: '2026-04-30T00:00:02.000Z',
    kind: 'tool' as const,
    role: 'user' as const,
    tool: 'bash',
    status: 'ok' as const,
    content,
    meta: { exit: 0 }
  };
}

test('estimateRecordTokens is deterministic', () => {
  assert.equal(estimateRecordTokens(user('u1', 'abcd')).tokens, 5);
  assert.equal(estimateMessagesTokens([{ role: 'user', content: 'abcd' }]).tokens, 5);
});

test('selectAutoCompactRange prefers a user-turn boundary and leaves a raw tail', () => {
  const session = createSession('/tmp/workspace');
  session.records.push(
    user('u1', 'old '.repeat(100)),
    assistant('a1', '{"message":"old answer"}'),
    user('u2', 'tail '.repeat(100)),
    assistant('a2', '{"message":"tail answer"}')
  );

  const range = selectAutoCompactRange({
    session,
    keepRecentTokens: 60,
    minNewTokens: 1
  });

  assert.equal(range?.endIndexExclusive, 2);
  assert.equal(range?.firstKeptRecordId, 'u2');
});

test('selectAutoCompactRange never keeps a tool record as the first tail record', () => {
  const session = createSession('/tmp/workspace');
  session.records.push(
    user('u1', 'run command'),
    assistant('a1', '{"bash":"printf ok"}', { bash: 'printf ok' }),
    tool('t1', 'TOOL_RESULT bash OK\nok'),
    assistant('a2', '{"message":"done"}')
  );

  const range = selectAutoCompactRange({
    session,
    keepRecentTokens: 1,
    minNewTokens: 1
  });

  assert.notEqual(session.records[range?.endIndexExclusive ?? -1]?.kind, 'tool');
});

test('serializeRecordForSummary includes tool metadata', () => {
  const serialized = serializeRecordForSummary(tool('t1', 'TOOL_RESULT bash OK\nok'), 10_000);

  assert.match(serialized, /tool=bash/);
  assert.match(serialized, /status=ok/);
  assert.match(serialized, /TOOL_RESULT bash OK/);
});

function fakeModel(outputs: string[]) {
  const calls: Array<{ role: string; content: string }[]> = [];
  return {
    calls,
    client: {
      async complete(messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>) {
        calls.push(messages);
        return {
          content: outputs.shift() ?? '## Objective\nGenerated summary',
          provider: 'openrouter' as const,
          model: 'test-model'
        };
      }
    }
  };
}

test('maybeAutoCompact writes an active artifact when threshold is exceeded', async () => {
  await withTempSession(async ({ cwd, session }) => {
    session.records.push(
      user('u1', 'old '.repeat(100)),
      assistant('a1', '{"message":"old"}'),
      user('u2', 'tail')
    );
    const model = fakeModel(['## Objective\nSummarized old context']);

    const result = await maybeAutoCompact({
      cwd,
      session,
      model: model.client,
      modelConfig: { provider: 'openrouter', model: 'test-model', baseUrl: 'https://example.test', streaming: 'off' },
      config: {
        enabled: 'on',
        contextWindowTokens: 400,
        thresholdRatio: 0.8,
        reserveTokens: 100,
        keepRecentTokens: 20,
        minNewTokens: 1,
        maxThresholdCompactionsPerTurn: 1,
        maxOverflowRetriesPerModelCall: 1,
        usableLimitTokens: 300,
        contextWindowSource: 'config'
      },
      instructions: [],
      phase: 'pre-model',
      trigger: 'threshold',
      state: { thresholdCompactionsThisTurn: 0, thresholdSuppressed: false },
      estimateOverrideTokens: 350
    });

    assert.equal(result.status, 'compacted');
    assert.equal(session.compactions[0]?.status, 'active');
    assert.match(session.compactions[0]?.summaryMarkdown ?? '', /Summarized old context/);
  });
});

test('maybeAutoCompact chunks summarizer input when selected records exceed summary budget', async () => {
  await withTempSession(async ({ cwd, session }) => {
    session.records.push(
      user('u1', 'old '.repeat(240)),
      user('u2', 'older '.repeat(240)),
      user('u3', 'tail')
    );
    const model = fakeModel(['## Objective\nChunk 1 summary', '## Objective\nChunk 2 summary']);

    const result = await maybeAutoCompact({
      cwd,
      session,
      model: model.client,
      modelConfig: { provider: 'openrouter', model: 'test-model', baseUrl: 'https://example.test', streaming: 'off' },
      config: {
        enabled: 'on',
        contextWindowTokens: 900,
        thresholdRatio: 0.8,
        reserveTokens: 300,
        keepRecentTokens: 1,
        minNewTokens: 1,
        maxThresholdCompactionsPerTurn: 1,
        maxOverflowRetriesPerModelCall: 1,
        usableLimitTokens: 600,
        contextWindowSource: 'config'
      },
      instructions: [],
      phase: 'pre-model',
      trigger: 'threshold',
      state: { thresholdCompactionsThisTurn: 0, thresholdSuppressed: false },
      estimateOverrideTokens: 800
    });

    assert.equal(result.status, 'compacted');
    assert.equal(model.calls.length > 1, true);
  });
});
