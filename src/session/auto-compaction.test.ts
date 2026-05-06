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

function txOpened(id: string, txId: string, name?: string) {
  return {
    id,
    ts: '2026-04-30T00:00:03.000Z',
    kind: 'tx-opened' as const,
    role: 'user' as const,
    content: `Transaction ${txId} opened (explicit)`,
    meta: { txId, txKind: 'edit' as const, explicit: true as const, ...(name !== undefined ? { name } : {}) }
  };
}

function txApplied(id: string, txId: string) {
  return {
    id,
    ts: '2026-04-30T00:00:04.000Z',
    kind: 'tx-applied' as const,
    role: 'user' as const,
    content: `Transaction ${txId} applied`,
    meta: {
      txId,
      txKind: 'edit' as const,
      diffSummary: {
        filesChanged: 1,
        additions: 5,
        deletions: 2,
        creates: [],
        modifies: ['src/foo.ts'],
        deletes: []
      },
      files: { creates: [], modifies: ['src/foo.ts'], deletes: [] },
      validators: {
        blocking: { pass: 1, fail: 0 },
        advisory: { pass: 0, fail: 0, names: [] }
      },
      overrides: [],
      artifactRef: `~/.cliq/transactions/${txId}`
    }
  };
}

function txAborted(id: string, txId: string, reason: 'user-abort' | 'validator-fail' | 'apply-error' = 'user-abort') {
  return {
    id,
    ts: '2026-04-30T00:00:05.000Z',
    kind: 'tx-aborted' as const,
    role: 'user' as const,
    content: `Transaction ${txId} aborted: ${reason}`,
    meta: {
      txId,
      txKind: 'edit' as const,
      reason,
      files: { wouldHaveCreated: [], wouldHaveModified: ['src/foo.ts'], wouldHaveDeleted: [] },
      artifactRef: `~/.cliq/transactions/${txId}`
    }
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

test('selectAutoCompactRange does not split between tx-opened and matching tx-applied', () => {
  const session = createSession('/tmp/workspace');
  // Span: open=1, close=3. assistant at index 2 is a safe-split candidate that would split the span.
  session.records.push(
    user('u1', 'lead'),
    txOpened('o1', 'tx_aa', 'refactor foo'),
    assistant('a1', '{"message":"working"}'),
    txApplied('p1', 'tx_aa'),
    user('u2', 'tail')
  );

  const range = selectAutoCompactRange({
    session,
    // keepRecentTokens larger than any tail makes selected fall back to candidates[0],
    // which is the assistant at index 2 — INSIDE the span. Adjust to openIndex=1.
    keepRecentTokens: 10_000,
    minNewTokens: 1
  });

  assert.equal(range?.endIndexExclusive, 1);
  assert.equal(range?.firstKeptRecordId, 'o1');
});

test('selectAutoCompactRange does not split between tx-opened and matching tx-aborted', () => {
  const session = createSession('/tmp/workspace');
  // Span: open=1, close=3. assistant at index 2 is a safe-split candidate that would split.
  session.records.push(
    user('u1', 'lead'),
    txOpened('o1', 'tx_bb'),
    assistant('a1', '{"message":"working"}'),
    txAborted('b1', 'tx_bb', 'user-abort'),
    user('u2', 'tail')
  );

  const range = selectAutoCompactRange({
    session,
    keepRecentTokens: 10_000,
    minNewTokens: 1
  });

  assert.equal(range?.endIndexExclusive, 1);
  assert.equal(range?.firstKeptRecordId, 'o1');
});

test('selectAutoCompactRange splits normally when tx-applied has no preceding tx-opened (implicit per-turn tx)', () => {
  const session = createSession('/tmp/workspace');
  // No tx-opened: tx-applied represents an implicit per-turn tx and is not a span boundary.
  session.records.push(
    user('u1', 'old '.repeat(100)),
    assistant('a1', '{"message":"old answer"}'),
    txApplied('p1', 'tx_cc'),
    user('u2', 'tail '.repeat(100)),
    assistant('a2', '{"message":"tail answer"}')
  );

  const range = selectAutoCompactRange({
    session,
    keepRecentTokens: 60,
    minNewTokens: 1
  });

  // user boundary at index 3 is selected normally (no span constraint).
  assert.equal(range?.endIndexExclusive, 3);
  assert.equal(range?.firstKeptRecordId, 'u2');
});

test('selectAutoCompactRange treats unmatched tx-opened as extending to records.length', () => {
  const session = createSession('/tmp/workspace');
  // tx-opened at index 3 with no matching apply/abort: span = [3, records.length=5].
  // assistant safe-split at index 4 would land INSIDE that still-open span; must move to 3.
  session.records.push(
    user('u1', 'old '.repeat(100)),
    assistant('a1', '{"message":"old answer"}'),
    user('u2', 'tail '.repeat(100)),
    txOpened('o1', 'tx_dd'),
    assistant('a2', '{"message":"tail answer"}')
  );

  const range = selectAutoCompactRange({
    session,
    keepRecentTokens: 1,
    minNewTokens: 1
  });

  // selected starts as the last candidate satisfying tail >= 1: assistant at index 4.
  // Adjustment: 4 is inside still-open span (3, 5) → moved to openIndex=3.
  assert.equal(range?.endIndexExclusive, 3);
  assert.equal(range?.firstKeptRecordId, 'o1');
});

test('serializeRecordForSummary surfaces meta.name and meta.txId for tx-opened records', () => {
  const serialized = serializeRecordForSummary(txOpened('o1', 'tx_aa', 'refactor foo'), 10_000);

  assert.match(serialized, /Transaction opened "refactor foo"/);
  assert.match(serialized, /tx_aa/);
  // Without a name, the rendering omits the quoted label.
  const noName = serializeRecordForSummary(txOpened('o2', 'tx_bb'), 10_000);
  assert.equal(/Transaction opened "/.test(noName), false);
  assert.match(noName, /Transaction opened \(tx_bb\)/);
});

test('serializeRecordForSummary surfaces meta.diffSummary for tx-applied records', () => {
  const serialized = serializeRecordForSummary(txApplied('p1', 'tx_aa'), 10_000);

  assert.match(serialized, /tx_aa/);
  assert.match(serialized, /1 files changed/);
  assert.match(serialized, /\+5 -2/);
  assert.match(serialized, /modifies: src\/foo\.ts/);
  assert.match(serialized, /1\/1 blocking pass/);
});

test('serializeRecordForSummary surfaces meta.appliedPartial for tx-aborted records when present', () => {
  const aborted = {
    id: 'b1',
    ts: '2026-04-30T00:00:05.000Z',
    kind: 'tx-aborted' as const,
    role: 'user' as const,
    content: 'Transaction tx_zz aborted: apply-error',
    meta: {
      txId: 'tx_zz',
      txKind: 'edit' as const,
      reason: 'apply-failed-partial-kept' as const,
      failedValidators: ['typecheck', 'lint'],
      files: { wouldHaveCreated: [], wouldHaveModified: ['src/a.ts', 'src/b.ts'], wouldHaveDeleted: [] },
      artifactRef: '~/.cliq/transactions/tx_zz',
      appliedPartial: {
        partialFiles: ['src/a.ts'],
        ghostSnapshotId: 'ghost_1',
        restoreConfirmed: false
      }
    }
  };
  const serialized = serializeRecordForSummary(aborted, 10_000);

  assert.match(serialized, /tx_zz/);
  assert.match(serialized, /apply-failed-partial-kept/);
  assert.match(serialized, /failedValidators: typecheck, lint/);
  assert.match(serialized, /partial: src\/a\.ts/);
  assert.match(serialized, /restoreConfirmed=false/);

  // Without appliedPartial / failedValidators, those segments are absent.
  const minimal = serializeRecordForSummary(txAborted('b2', 'tx_yy', 'user-abort'), 10_000);
  assert.match(minimal, /Transaction tx_yy aborted: user-abort/);
  assert.equal(/partial:/.test(minimal), false);
  assert.equal(/failedValidators:/.test(minimal), false);
});

test('selectAutoCompactRange respects multiple non-overlapping explicit tx spans', () => {
  const session = createSession('/tmp/workspace');
  // Span A: indices 1..3 (open..apply); span B: indices 4..6 (open..apply, no user between).
  // Best candidate by keepRecentTokens lands at index 5 (assistant inside span B); must move to 4.
  // u_mid sits BEFORE span B (index 4) — at index 7 (after span B), but to land selection inside
  // span B, we need an assistant safe-split inside it.
  session.records.push(
    user('u1', 'old '.repeat(100)),
    txOpened('o1', 'tx_aa'),
    assistant('a1', '{"message":"a1"}'),
    txApplied('p1', 'tx_aa'),
    txOpened('o2', 'tx_bb'),
    assistant('a2', '{"message":"a2"}'),
    txApplied('p2', 'tx_bb'),
    user('u_tail', 'tail '.repeat(100))
  );

  const range = selectAutoCompactRange({
    session,
    keepRecentTokens: 60,
    minNewTokens: 1
  });

  // Candidates would include assistant safe-split inside span B at index 5 and user at index 7.
  // Both 5 (inside span B 4..6) and possibly 2 (inside span A 1..3) get moved.
  // Best by tail-tokens is index 7 (user); 7 > 6 closeIndex of B, so 7 is OUTSIDE span B → no adjustment.
  // Verify the cut respects both spans (it should land at 7, all spans on the compact side).
  assert.equal(range?.endIndexExclusive, 7);
  assert.equal(range?.firstKeptRecordId, 'u_tail');

  // Now force a cut that WOULD split span B: shrink keepRecentTokens so the assistant inside span B
  // becomes the chosen candidate. Use a session where index 5 is the only candidate keeping enough tail.
  // Actually, easier: assert directly via the helper behavior — when cut would land inside span B,
  // it gets moved to span B's openIndex. We test this via the unmatched-tx case above and the
  // primary tx-opened/tx-applied test above. Here we additionally verify span A is not split:
  // build a session whose best candidate lands inside span A.
  const sessionB = createSession('/tmp/workspace');
  sessionB.records.push(
    user('u1', 'lead'),
    txOpened('o1', 'tx_aa'),
    assistant('a1', '{"message":"a1"}'),
    txApplied('p1', 'tx_aa'),
    txOpened('o2', 'tx_bb'),
    assistant('a2', '{"message":"a2"}'),
    txApplied('p2', 'tx_bb'),
    user('u_tail', 'tail '.repeat(200))
  );
  const rangeB = selectAutoCompactRange({
    session: sessionB,
    // Force tail to be very large so candidates near the front are preferred.
    // selected becomes the LAST candidate satisfying tailTokens >= keepRecentTokens.
    keepRecentTokens: 10_000,
    minNewTokens: 1
  });
  // No candidate has a tail >= 10000 tokens, so selected falls back to candidates[0].
  // candidates[0] is the smallest safe split. Index 2 (assistant inside span A) is safe.
  // Adjusted from 2 → 1 (span A's openIndex). previousEnd is 0, so 1 > 0 is fine.
  assert.equal(rangeB?.endIndexExclusive, 1);
  assert.equal(rangeB?.firstKeptRecordId, 'o1');
});

function fakeModel(outputs: string[]) {
  const calls: Array<{ role: string; content: string }[]> = [];
  const signals: Array<AbortSignal | undefined> = [];
  return {
    calls,
    signals,
    client: {
      async complete(
        messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>,
        options?: { signal?: AbortSignal }
      ) {
        calls.push(messages);
        signals.push(options?.signal);
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
    const controller = new AbortController();

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
      signal: controller.signal,
      estimateOverrideTokens: 800
    });

    assert.equal(result.status, 'compacted');
    assert.equal(model.calls.length > 1, true);
    assert.equal(model.signals.length, model.calls.length);
    assert.equal(model.signals.every((signal) => signal === controller.signal), true);
  });
});

test('maybeAutoCompact stops after summarizer returns if cancellation was requested', async () => {
  await withTempSession(async ({ cwd, session }) => {
    session.records.push(user('u1', 'old '.repeat(100)), assistant('a1', '{"message":"old"}'), user('u2', 'tail'));
    const controller = new AbortController();
    const model = {
      client: {
        async complete() {
          controller.abort();
          return {
            content: '## Objective\nShould not persist',
            provider: 'openrouter' as const,
            model: 'test-model'
          };
        }
      }
    };

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
      signal: controller.signal,
      estimateOverrideTokens: 350
    });

    assert.equal(result.status, 'error');
    assert.equal(result.status === 'error' ? result.error.name : '', 'AbortError');
    assert.equal(session.compactions.length, 0);
  });
});

test('maybeAutoCompact rejects summaries that exceed the summarizer budget', async () => {
  await withTempSession(async ({ cwd, session }) => {
    session.records.push(user('u1', 'old '.repeat(100)), assistant('a1', '{"message":"old"}'), user('u2', 'tail'));
    const model = fakeModel(['oversized summary '.repeat(1000)]);

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

    assert.equal(result.status, 'error');
    assert.match(result.status === 'error' ? result.error.message : '', /summarizer.*budget/i);
    assert.equal(session.compactions.length, 0);
  });
});
