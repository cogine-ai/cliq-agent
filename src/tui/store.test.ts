import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  createInitialState,
  createUiStore,
  reduce,
  type PendingApproval,
  type UiState,
} from './store.js';

const baseInit = (): UiState =>
  createInitialState({
    policy: 'auto',
    model: { provider: 'ollama', model: 'qwen3:4b' },
    session: { id: 'ses_test', cwd: '/repo' },
  });

test('createInitialState seeds an empty state with counter at 1', () => {
  const s = baseInit();
  assert.equal(s.transcript.length, 0);
  assert.equal(s.activeTurn, null);
  assert.equal(s.pendingApproval, null);
  assert.equal(s.policy, 'auto');
  assert.equal(s.errors.length, 0);
  assert.equal(s.versionUpdate, null);
  assert.equal(s.nextEntryId, 1);
});

test('user-input appends a user transcript entry with monotonic id', () => {
  let s = baseInit();
  s = reduce(s, { type: 'user-input', text: 'hello' });
  assert.equal(s.transcript.length, 1);
  assert.deepEqual(s.transcript[0], { kind: 'user', id: 'u1', text: 'hello' });

  s = reduce(s, { type: 'user-input', text: 'again' });
  assert.equal(s.transcript.length, 2);
  assert.equal(s.transcript[1]!.id, 'u2');
});

test('runtime-event model-start opens activeTurn with zeroed counters', () => {
  const s = reduce(baseInit(), {
    type: 'runtime-event',
    event: { type: 'model-start', provider: 'ollama', model: 'qwen3:4b', streaming: false },
  });
  assert.deepEqual(s.activeTurn, { modelChunks: 0, modelChars: 0 });
});

test('runtime-event model-progress updates counters within active turn', () => {
  let s = reduce(baseInit(), {
    type: 'runtime-event',
    event: { type: 'model-start', provider: 'ollama', model: 'qwen3:4b', streaming: false },
  });
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'model-progress', chunks: 3, chars: 120 },
  });
  assert.deepEqual(s.activeTurn, { modelChunks: 3, modelChars: 120 });
});

test('runtime-event model-progress without an active turn is a no-op', () => {
  const s = reduce(baseInit(), {
    type: 'runtime-event',
    event: { type: 'model-progress', chunks: 1, chars: 10 },
  });
  assert.equal(s.activeTurn, null);
});

test('runtime-event final appends assistant entry and clears activeTurn', () => {
  let s = reduce(baseInit(), {
    type: 'runtime-event',
    event: { type: 'model-start', provider: 'ollama', model: 'qwen3:4b', streaming: false },
  });
  s = reduce(s, { type: 'runtime-event', event: { type: 'final', message: 'done' } });
  assert.equal(s.activeTurn, null);
  assert.equal(s.transcript.length, 1);
  assert.deepEqual(s.transcript[0], { kind: 'assistant', id: 'a1', text: 'done' });
});

test('runtime-event error records entry, caps history at 20, clears activeTurn', () => {
  let s = reduce(baseInit(), {
    type: 'runtime-event',
    event: { type: 'model-start', provider: 'ollama', model: 'qwen3:4b', streaming: false },
  });
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'error', stage: 'model', message: 'oops', code: 'model-error' },
  });
  assert.equal(s.activeTurn, null);
  assert.equal(s.errors.length, 1);
  assert.equal(s.errors[0]!.message, 'oops');
  assert.equal(s.errors[0]!.code, 'model-error');

  let cur = s;
  for (let i = 0; i < 25; i += 1) {
    cur = reduce(cur, {
      type: 'runtime-event',
      event: { type: 'error', stage: 'protocol', message: `e${i}` },
    });
  }
  assert.equal(cur.errors.length, 20);
  // oldest entries dropped — last entry is the latest one pushed
  assert.equal(cur.errors[cur.errors.length - 1]!.message, 'e24');
});

test('session-reset clears transcript/turn/approval/errors/tokens but preserves identity fields', () => {
  let s = baseInit();
  s = reduce(s, { type: 'user-input', text: 'a' });
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'model-start', provider: 'ollama', model: 'qwen3:4b', streaming: false },
  });
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'error', stage: 'model', message: 'x' },
  });
  s = reduce(s, { type: 'session-tokens-update', tokens: 4242 });
  s = reduce(s, { type: 'version-update', notice: { current: '0.9.0', latest: '0.10.0' } });

  const after = reduce(s, { type: 'session-reset' });
  assert.equal(after.transcript.length, 0);
  assert.equal(after.activeTurn, null);
  assert.equal(after.pendingApproval, null);
  assert.equal(after.errors.length, 0);
  // Token bar must hide after /reset so the new session is not labeled with
  // the previous session's running estimate.
  assert.equal(after.sessionTokens, null);
  assert.deepEqual(after.versionUpdate, { current: '0.9.0', latest: '0.10.0' });
  assert.equal(after.policy, 'auto');
  assert.equal(after.session.id, 'ses_test');
  assert.equal(after.model.model, 'qwen3:4b');
});

test('version-update stores and clears package update notice', () => {
  const notice = { current: '0.9.0', latest: '0.10.0' };
  const afterSet = reduce(baseInit(), { type: 'version-update', notice });
  assert.deepEqual(afterSet.versionUpdate, notice);

  const afterClear = reduce(afterSet, { type: 'version-update', notice: null });
  assert.equal(afterClear.versionUpdate, null);
});

test('policy-change updates the policy mode and leaves transcript intact', () => {
  let s = baseInit();
  s = reduce(s, { type: 'user-input', text: 'a' });
  const after = reduce(s, { type: 'policy-change', mode: 'read-only' });
  assert.equal(after.policy, 'read-only');
  assert.equal(after.transcript.length, 1);
});

test('approval-request sets pendingApproval; approval-resolve clears it by id', () => {
  const noop = reduce(baseInit(), { type: 'approval-resolve', id: 'pa_unknown' });
  assert.equal(noop.pendingApproval, null);

  let resolvedWith: string | null = null;
  const pending: PendingApproval = {
    id: 'pa_1',
    subject: {
      kind: 'tool',
      toolName: 'bash',
      access: 'exec',
      channel: { kind: 'bash', commandHead: 'ls', compound: false },
      action: { bash: 'ls' } as never,
      display: { title: 'Allow bash command?', command: 'ls' }
    },
    resolve: (d) => {
      resolvedWith = d;
    }
  };
  const requested = reduce(baseInit(), { type: 'approval-request', pending });
  assert.equal(requested.pendingApproval, pending);

  // Bridge calls resolve before dispatching the clear action — reducer must
  // not call it itself.
  pending.resolve('allow');
  const cleared = reduce(requested, { type: 'approval-resolve', id: pending.id });
  assert.equal(cleared.pendingApproval, null);
  assert.equal(resolvedWith, 'allow');
});

test('approval-resolve with a mismatched id leaves a newer pending intact', () => {
  const newer: PendingApproval = {
    id: 'pa_new',
    subject: {
      kind: 'tool',
      toolName: 'bash',
      access: 'exec',
      channel: { kind: 'bash', commandHead: 'ls', compound: false },
      action: { bash: 'ls' } as never,
      display: { title: 'Allow bash command?', command: 'ls' }
    },
    resolve: () => undefined
  };
  const withNewer = reduce(baseInit(), { type: 'approval-request', pending: newer });
  // A stale resolve for an older pending must not clobber the newer one.
  const stale = reduce(withNewer, { type: 'approval-resolve', id: 'pa_old' });
  assert.equal(stale.pendingApproval, newer);
});

test('reducer is pure: input state is not mutated', () => {
  const s = baseInit();
  const before = JSON.stringify(s);
  reduce(s, { type: 'user-input', text: 'hi' });
  reduce(s, {
    type: 'runtime-event',
    event: { type: 'final', message: 'x' },
  });
  assert.equal(JSON.stringify(s), before);
});

test('createUiStore notifies subscribers on dispatch and supports unsubscribe', () => {
  const store = createUiStore(baseInit());
  let calls = 0;
  let lastState: UiState | null = null;
  const unsubscribe = store.subscribe((s) => {
    calls += 1;
    lastState = s;
  });

  store.dispatch({ type: 'user-input', text: 'one' });
  assert.equal(calls, 1);
  assert.equal(lastState!.transcript.length, 1);

  store.dispatch({ type: 'user-input', text: 'two' });
  assert.equal(calls, 2);

  unsubscribe();
  store.dispatch({ type: 'user-input', text: 'three' });
  assert.equal(calls, 2); // listener removed
  assert.equal(store.getState().transcript.length, 3); // store still mutates
});

test('runtime-event tool-start opens a running tool entry; tool-end finalizes it', () => {
  let s = baseInit();
  s = reduce(s, { type: 'runtime-event', event: { type: 'tool-start', tool: 'bash', preview: 'ls' } });
  assert.equal(s.transcript.length, 1);
  const opened = s.transcript[0]!;
  assert.equal(opened.kind, 'tool');
  if (opened.kind !== 'tool') return;
  assert.equal(opened.tool, 'bash');
  assert.equal(opened.status, 'running');

  s = reduce(s, { type: 'runtime-event', event: { type: 'tool-end', tool: 'bash', status: 'ok' } });
  const closed = s.transcript[0]!;
  assert.equal(closed.kind, 'tool');
  if (closed.kind !== 'tool') return;
  assert.equal(closed.status, 'ok');
});

test('tool-hook-start enriches the running entry with the action preview', () => {
  let s = baseInit();
  s = reduce(s, { type: 'runtime-event', event: { type: 'tool-start', tool: 'edit', preview: '' } });
  s = reduce(s, {
    type: 'tool-hook-start',
    action: { edit: { path: 'src/foo.ts', old_text: 'a', new_text: 'b' } }
  });
  const entry = s.transcript[0]!;
  assert.equal(entry.kind, 'tool');
  if (entry.kind !== 'tool') return;
  assert.equal(entry.summary, 'src/foo.ts');
  assert.equal(entry.status, 'running');
});

test('tool-hook-end finalizes the entry with formatToolResultSummary and bash body', () => {
  let s = baseInit();
  s = reduce(s, { type: 'runtime-event', event: { type: 'tool-start', tool: 'bash', preview: '' } });
  s = reduce(s, { type: 'tool-hook-start', action: { bash: 'echo hi' } });
  s = reduce(s, {
    type: 'tool-hook-end',
    result: {
      tool: 'bash',
      status: 'ok',
      content: 'TOOL_RESULT bash success\n$ echo hi\nhi\n',
      meta: {}
    }
  });
  const entry = s.transcript[0]!;
  assert.equal(entry.kind, 'tool');
  if (entry.kind !== 'tool') return;
  assert.equal(entry.status, 'ok');
  assert.equal(entry.body, 'hi\n');
});

test('tool-hook-end with no prior running entry synthesizes a finalized entry', () => {
  // Covers the deny-then-after-tool path where tool-hook-start never fires.
  let s = baseInit();
  s = reduce(s, {
    type: 'tool-hook-end',
    result: {
      tool: 'edit',
      status: 'error',
      content: 'TOOL_RESULT edit ERROR\npolicy=read-only\nblocked',
      meta: { policy: 'read-only', reason: 'blocked' }
    }
  });
  assert.equal(s.transcript.length, 1);
  const entry = s.transcript[0]!;
  assert.equal(entry.kind, 'tool');
  if (entry.kind !== 'tool') return;
  assert.equal(entry.status, 'error');
  assert.equal(entry.summary, 'policy=read-only blocked');
});

test('tx-* events update state.tx through the staging → finalized → validated → null lifecycle', () => {
  let s = baseInit();
  assert.equal(s.tx, null);

  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'tx-staging-start', txId: 'tx_abc', trigger: 'auto-turn' }
  });
  assert.deepEqual(s.tx, { txId: 'tx_abc', state: 'staging' });

  s = reduce(s, {
    type: 'runtime-event',
    event: {
      type: 'tx-finalized',
      txId: 'tx_abc',
      diffSummary: {
        filesChanged: 1,
        additions: 1,
        deletions: 0,
        creates: [],
        modifies: ['x.ts'],
        deletes: []
      }
    }
  });
  assert.deepEqual(s.tx, { txId: 'tx_abc', state: 'finalized' });

  s = reduce(s, {
    type: 'runtime-event',
    event: {
      type: 'tx-validated',
      txId: 'tx_abc',
      validators: { blocking: { pass: 1, fail: 0 }, advisory: { pass: 0, fail: 0, names: [] } },
      blockingFailures: []
    }
  });
  assert.deepEqual(s.tx, { txId: 'tx_abc', state: 'validated' });

  s = reduce(s, {
    type: 'runtime-event',
    event: {
      type: 'tx-applied',
      txId: 'tx_abc',
      diffSummary: {
        filesChanged: 1,
        additions: 1,
        deletions: 0,
        creates: [],
        modifies: ['x.ts'],
        deletes: []
      },
      validators: { blocking: { pass: 1, fail: 0 }, advisory: { pass: 0, fail: 0, names: [] } },
      overrides: [],
      artifactRef: 'tx_abc'
    }
  });
  assert.equal(s.tx, null);
});

test('tx-aborted clears state.tx', () => {
  let s = baseInit();
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'tx-staging-start', txId: 'tx_x', trigger: 'auto-turn' }
  });
  assert.notEqual(s.tx, null);
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'tx-aborted', txId: 'tx_x', reason: 'user-abort', artifactRef: 'tx_x' }
  });
  assert.equal(s.tx, null);
});

test('tx-* events push system entries with diff and validator summaries', () => {
  let s = baseInit();
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'tx-staging-start', txId: 'tx_1', trigger: 'auto-turn' }
  });
  s = reduce(s, {
    type: 'runtime-event',
    event: {
      type: 'tx-finalized',
      txId: 'tx_1',
      diffSummary: {
        filesChanged: 3,
        additions: 10,
        deletions: 4,
        creates: [],
        modifies: [],
        deletes: []
      }
    }
  });
  s = reduce(s, {
    type: 'runtime-event',
    event: {
      type: 'tx-validated',
      txId: 'tx_1',
      validators: {
        blocking: { pass: 2, fail: 1 },
        advisory: { pass: 0, fail: 0, names: [] }
      },
      blockingFailures: ['tsc']
    }
  });
  s = reduce(s, {
    type: 'runtime-event',
    event: {
      type: 'tx-applied',
      txId: 'tx_1',
      diffSummary: {
        filesChanged: 3,
        additions: 10,
        deletions: 4,
        creates: [],
        modifies: [],
        deletes: []
      },
      validators: {
        blocking: { pass: 2, fail: 1 },
        advisory: { pass: 0, fail: 0, names: [] }
      },
      overrides: [],
      artifactRef: 'tx_1'
    }
  });
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'tx-aborted', txId: 'tx_2', reason: 'validator-fail', artifactRef: 'tx_2' }
  });

  const systemTexts = s.transcript
    .filter((e): e is Extract<typeof e, { kind: 'system' }> => e.kind === 'system')
    .map((e) => e.text);
  assert.equal(systemTexts.length, 5);
  assert.match(systemTexts[0]!, /tx_1 staging started/);
  assert.match(systemTexts[1]!, /tx_1 finalized: 3 files \(\+10\/-4\)/);
  assert.match(systemTexts[2]!, /tx_1 validated: blocking 2\/3, advisory 0\/0 — failures: tsc/);
  assert.match(systemTexts[3]!, /tx_1 applied: \+10\/-4 over 3 files/);
  assert.match(systemTexts[4]!, /tx_2 aborted: validator-fail/);
});

test('checkpoint-created / compact-start / compact-skip do not pollute the transcript', () => {
  let s = baseInit();
  s = reduce(s, {
    type: 'runtime-event',
    event: {
      type: 'checkpoint-created',
      checkpointId: 'cp_1',
      kind: 'manual',
      workspaceSnapshotStatus: 'available'
    }
  });
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'compact-start', trigger: 'threshold', phase: 'pre-model' }
  });
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'compact-skip', reason: 'too-small' }
  });
  // None of the bookkeeping events should leave a system entry — they fire
  // (almost) every turn and would drown actual conversation in noise.
  assert.equal(s.transcript.length, 0);
});

test('compact-end and compact-error still surface as system entries (state changes)', () => {
  let s = baseInit();
  s = reduce(s, {
    type: 'runtime-event',
    event: {
      type: 'compact-end',
      artifactId: 'a1',
      estimatedTokensBefore: 9000,
      estimatedTokensAfter: 3000
    }
  });
  s = reduce(s, {
    type: 'runtime-event',
    event: { type: 'compact-error', trigger: 'threshold', message: 'oom' }
  });
  const systemTexts = s.transcript
    .filter((e): e is Extract<typeof e, { kind: 'system' }> => e.kind === 'system')
    .map((e) => e.text);
  assert.equal(systemTexts.length, 2);
  assert.match(systemTexts[0]!, /compaction completed: 9000 → 3000 tokens/);
  assert.match(systemTexts[1]!, /compaction error \(threshold\): oom/);
});

test('session-tokens-update sets sessionTokens; null until first dispatch', () => {
  const initial = baseInit();
  assert.equal(initial.sessionTokens, null);
  const after = reduce(initial, { type: 'session-tokens-update', tokens: 1234 });
  assert.equal(after.sessionTokens, 1234);
  const refreshed = reduce(after, { type: 'session-tokens-update', tokens: 5678 });
  assert.equal(refreshed.sessionTokens, 5678);
});

test('toggle-tool-body flips expanded on the latest tool entry that has a body', () => {
  let s = baseInit();
  s = reduce(s, { type: 'runtime-event', event: { type: 'tool-start', tool: 'bash', preview: '' } });
  s = reduce(s, { type: 'tool-hook-start', action: { bash: 'echo hi' } });
  s = reduce(s, {
    type: 'tool-hook-end',
    result: {
      tool: 'bash',
      status: 'ok',
      content: 'TOOL_RESULT bash success\n$ echo hi\nhi\n',
      meta: {}
    }
  });
  // After toggle, expanded becomes true.
  s = reduce(s, { type: 'toggle-tool-body' });
  let entry = s.transcript[0]!;
  assert.equal(entry.kind, 'tool');
  if (entry.kind !== 'tool') return;
  assert.equal(entry.expanded, true);

  // Toggle again: expanded becomes false.
  s = reduce(s, { type: 'toggle-tool-body' });
  entry = s.transcript[0]!;
  if (entry.kind !== 'tool') return;
  assert.equal(entry.expanded, false);
});

test('toggle-tool-body is a no-op when no tool entry has a body', () => {
  let s = baseInit();
  s = reduce(s, { type: 'user-input', text: 'hi' });
  const before = s;
  const after = reduce(s, { type: 'toggle-tool-body' });
  assert.equal(after, before);
});

test('end-to-end: user input, thinking, final assistant message', () => {
  const store = createUiStore(baseInit());
  store.dispatch({ type: 'user-input', text: 'what time is it?' });
  store.dispatch({
    type: 'runtime-event',
    event: { type: 'model-start', provider: 'ollama', model: 'qwen3:4b', streaming: false },
  });
  store.dispatch({
    type: 'runtime-event',
    event: { type: 'model-progress', chunks: 1, chars: 4 },
  });
  store.dispatch({
    type: 'runtime-event',
    event: { type: 'final', message: '12:34' },
  });

  const s = store.getState();
  assert.equal(s.transcript.length, 2);
  assert.equal(s.transcript[0]!.kind, 'user');
  assert.equal(s.transcript[1]!.kind, 'assistant');
  assert.equal(s.activeTurn, null);
});
