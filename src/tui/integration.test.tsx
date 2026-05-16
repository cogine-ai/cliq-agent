import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import type { ApprovalSubject } from '../policy/types.js';
import type { RuntimeEvent } from '../protocol/runtime/events.js';
import { App } from './app.js';
import {
  createInitialState,
  createUiStore,
  type PendingApproval,
  type UiApprovalDecision,
  type UiStore
} from './store.js';

const flush = () => new Promise<void>((r) => setImmediate(r));

const makeStore = (): UiStore =>
  createUiStore(
    createInitialState({
      policy: 'confirm-bash',
      model: { provider: 'ollama', model: 'qwen3:4b' },
      session: { id: 'ses_smoke', cwd: '/tmp/smoke' }
    })
  );

function dispatchEvent(store: UiStore, event: RuntimeEvent) {
  store.dispatch({ type: 'runtime-event', event });
}

test('end-to-end: user prompt → approval modal → allow → tool result → final', async () => {
  const store = makeStore();
  const submitted: string[] = [];
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={(text) => {
        submitted.push(text);
      }}
    />
  );

  // 1) User prompt arrives.
  stdin.write('list files');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();
  assert.deepEqual(submitted, ['list files']);
  assert.match(lastFrame() ?? '', /list files/);

  // 2) Runner starts thinking.
  dispatchEvent(store, {
    type: 'model-start',
    provider: 'ollama',
    model: 'qwen3:4b',
    streaming: false
  });
  await flush();
  assert.match(lastFrame() ?? '', /thinking/);

  // 3) Tool approval surfaces — modal replaces the input bar.
  let resolved: UiApprovalDecision | null = null;
  const subject: ApprovalSubject = {
    kind: 'tool',
    toolName: 'bash',
    access: 'exec',
    channel: { kind: 'bash', commandHead: 'ls' },
    action: { bash: 'ls' } as never,
    display: { title: 'Allow bash command?', command: 'ls' }
  };
  const pending: PendingApproval = {
    id: 'pa_smoke_1',
    subject,
    resolve: (d) => {
      resolved = d;
    }
  };
  store.dispatch({ type: 'approval-request', pending });
  await flush();
  let frame = lastFrame() ?? '';
  assert.match(frame, /Approval required/);
  assert.match(frame, /Allow bash command\?/);
  // Modal also captures the keystrokes — input bar is hidden while pending.
  assert.doesNotMatch(frame, /^>\s*$/m);

  // 4) User presses 'y' — modal resolves the bridge promise.
  stdin.write('y');
  await flush();
  await flush();
  assert.equal(resolved, 'allow');
  assert.equal(store.getState().pendingApproval, null);

  // 5) Runner runs the tool (hook bridge).
  store.dispatch({ type: 'tool-hook-start', action: { bash: 'ls' } });
  store.dispatch({
    type: 'tool-hook-end',
    result: {
      tool: 'bash',
      status: 'ok',
      content: 'TOOL_RESULT bash success\n$ ls\nfile-a.txt\nfile-b.txt\n',
      meta: {}
    }
  });
  await flush();
  frame = lastFrame() ?? '';
  assert.match(frame, /tool: bash/);
  assert.match(frame, /file-a\.txt/);

  // 6) Runner returns the final answer.
  dispatchEvent(store, { type: 'final', message: 'two files: a, b' });
  await flush();
  frame = lastFrame() ?? '';
  assert.match(frame, /two files: a, b/);
  assert.doesNotMatch(frame, /thinking/);
  // Input bar comes back once the modal cleared and turn ended.
  assert.match(frame, />/);
});

test('user denies an approval — resolve fires with deny and modal clears', async () => {
  const store = makeStore();
  const { stdin } = render(<App store={store} onSubmit={() => {}} />);
  let resolved: UiApprovalDecision | null = null;
  const pending: PendingApproval = {
    id: 'pa_deny',
    subject: {
      kind: 'tool',
      toolName: 'bash',
      access: 'exec',
      channel: { kind: 'bash', commandHead: 'rm' },
      action: { bash: 'rm -rf /' } as never,
      display: { title: 'Allow bash command?', command: 'rm -rf /' }
    },
    resolve: (d) => {
      resolved = d;
    }
  };
  store.dispatch({ type: 'approval-request', pending });
  await flush();

  stdin.write('n');
  await flush();
  await flush();

  assert.equal(resolved, 'deny');
  assert.equal(store.getState().pendingApproval, null);
});

test('tx-apply approval surfaces with diff/validator summary and allows', async () => {
  const store = makeStore();
  const { stdin, lastFrame } = render(<App store={store} onSubmit={() => {}} />);
  let resolved: UiApprovalDecision | null = null;
  const pending: PendingApproval = {
    id: 'pa_tx',
    subject: {
      kind: 'tx-apply',
      txId: 'tx_smoke',
      diffSummary: {
        filesChanged: 1,
        additions: 5,
        deletions: 2,
        creates: [],
        modifies: ['a.ts'],
        deletes: []
      },
      validators: [{ name: 'tsc', severity: 'blocking', status: 'pass', durationMs: 12 }],
      blockingFailures: [],
      artifactRef: 'tx_smoke'
    },
    resolve: (d) => {
      resolved = d;
    }
  };
  store.dispatch({ type: 'approval-request', pending });
  await flush();
  const frame = lastFrame() ?? '';
  assert.match(frame, /Apply transaction tx_smoke\?/);
  assert.match(frame, /1 changed \(\+5\/-2\)/);
  // tx-apply doesn't expose the [a]llow this turn shortcut.
  assert.doesNotMatch(frame, /\[a\]llow this turn/);

  stdin.write('y');
  await flush();
  await flush();
  assert.equal(resolved, 'allow');
});
