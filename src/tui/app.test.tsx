import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import type { ApprovalSubject } from '../policy/types.js';
import { App } from './app.js';
import {
  createInitialState,
  createUiStore,
  type PendingApproval,
  type UiApprovalDecision
} from './store.js';

const flush = () => new Promise<void>((r) => setImmediate(r));

// createInitialState preserves the policy passed by the caller; this store uses
// yolo intentionally so App tests can assert explicit UI policy rendering
// without depending on production default fallback behavior.
const makeStore = () =>
  createUiStore(
    createInitialState({
      policy: 'yolo',
      model: { provider: 'ollama', model: 'qwen3:4b' },
      session: { id: 'ses_smoke', cwd: '/tmp/smoke' }
    })
  );

const approvalSubject: ApprovalSubject = {
  kind: 'tool',
  toolName: 'bash',
  access: 'exec',
  channel: { kind: 'bash', commandHead: 'ls', unsafeForAllow: false },
  action: { bash: 'ls' } as never,
  display: { title: 'Allow bash command?', command: 'ls' }
};

test('mounts and renders status bar segments', () => {
  const store = makeStore();
  const { lastFrame } = render(<App store={store} onSubmit={() => {}} />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /ollama\/qwen3:4b/);
  assert.match(frame, /! YOLO/);
});

test('end-to-end: dispatches reach the rendered transcript', async () => {
  const store = makeStore();
  const { lastFrame } = render(<App store={store} onSubmit={() => {}} />);

  store.dispatch({ type: 'user-input', text: 'ping' });
  await flush();
  assert.match(lastFrame() ?? '', /ping/);

  store.dispatch({
    type: 'runtime-event',
    event: { type: 'model-start', provider: 'ollama', model: 'qwen3:4b', streaming: false }
  });
  await flush();
  assert.match(lastFrame() ?? '', /thinking/);

  store.dispatch({ type: 'runtime-event', event: { type: 'final', message: 'pong' } });
  await flush();
  const finalFrame = lastFrame() ?? '';
  assert.match(finalFrame, /pong/);
  assert.doesNotMatch(finalFrame, /thinking/);
});

test('typing /help and submitting renders the help block in the transcript', async () => {
  const store = makeStore();
  const { stdin, lastFrame } = render(<App store={store} onSubmit={() => {}} />);
  stdin.write('/help');
  await flush();
  // Palette is visible while typing.
  assert.match(lastFrame() ?? '', /\/help/);

  stdin.write('\r');
  await flush();
  const frame = lastFrame() ?? '';
  assert.match(frame, /Available slash commands/);
  assert.match(frame, /\/policy <mode>/);
});

test('typing an unknown slash command pushes an "unknown command" notice', async () => {
  const store = makeStore();
  const { stdin, lastFrame } = render(<App store={store} onSubmit={() => {}} />);
  stdin.write('/banana');
  await flush();
  stdin.write('\r');
  await flush();
  assert.match(lastFrame() ?? '', /unknown command: \/banana/);
});

test('/policy without a mode argument surfaces an inline error', async () => {
  const store = makeStore();
  const { stdin, lastFrame } = render(<App store={store} onSubmit={() => {}} />);
  stdin.write('/policy');
  await flush();
  stdin.write('\r');
  await flush();
  assert.match(lastFrame() ?? '', /requires a mode argument/);
});

test('/policy <mode> calls onPolicyChange and dispatches policy-change', async () => {
  const store = makeStore();
  const captured: string[] = [];
  const { stdin } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onPolicyChange={(mode) => {
        captured.push(mode);
      }}
    />
  );
  stdin.write('/policy plan');
  await flush();
  stdin.write('\r');
  await flush();
  await flush(); // extra tick for the awaited onPolicyChange chain
  assert.deepEqual(captured, ['plan']);
  assert.equal(store.getState().policy, 'plan');
});

test('/skills calls onSkillsList and renders the result', async () => {
  const store = makeStore();
  let calls = 0;
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onSkillsList={() => {
        calls += 1;
        return 'Skills:\n* reviewer [project/available] review instructions';
      }}
    />
  );

  stdin.write('/skills');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();

  assert.equal(calls, 1);
  assert.match(lastFrame() ?? '', /reviewer/);
});

test('/skill <name> calls onSkillActivate and renders the result', async () => {
  const store = makeStore();
  const activated: string[] = [];
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onSkillActivate={(name) => {
        activated.push(name);
        return `skill ${name} activated`;
      }}
    />
  );

  stdin.write('/skill reviewer');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();

  assert.deepEqual(activated, ['reviewer']);
  assert.match(lastFrame() ?? '', /skill reviewer activated/);
});

test('/reset awaits onReset and clears the transcript via session-reset', async () => {
  const store = makeStore();
  store.dispatch({ type: 'user-input', text: 'before reset' });
  store.dispatch({ type: 'runtime-event', event: { type: 'final', message: 'ready' } });
  let onResetCalls = 0;
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onReset={async () => {
        onResetCalls += 1;
      }}
    />
  );
  await flush();
  assert.match(lastFrame() ?? '', /before reset/);

  stdin.write('/reset');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();

  assert.equal(onResetCalls, 1);
  // session-reset clears the user line; system-message "session reset" remains.
  assert.doesNotMatch(lastFrame() ?? '', /before reset/);
  assert.match(lastFrame() ?? '', /session reset/);
});

test('Ctrl+C clears the input buffer when no turn is active', async () => {
  const store = makeStore();
  const { stdin, lastFrame } = render(<App store={store} onSubmit={() => {}} />);
  stdin.write('partial');
  await flush();
  assert.match(lastFrame() ?? '', /partial/);

  stdin.write('\x03'); // Ctrl+C
  await flush();
  assert.doesNotMatch(lastFrame() ?? '', /partial/);
});

test('Ctrl+C during an active turn calls onCancelTurn and renders cancelling notice', async () => {
  const store = makeStore();
  store.dispatch({
    type: 'runtime-event',
    event: { type: 'model-start', provider: 'ollama', model: 'qwen3:4b', streaming: false }
  });
  let cancels = 0;
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onCancelTurn={() => {
        cancels += 1;
      }}
    />
  );
  await flush();

  stdin.write('\x03');
  await flush();
  assert.equal(cancels, 1);
  assert.match(lastFrame() ?? '', /cancelling/);
});

test('Shift+Tab rotates mode and confirms the user-facing mode label', async () => {
  const store = makeStore();
  const captured: string[] = [];
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onPolicyChange={(mode) => {
        captured.push(mode);
      }}
    />
  );

  stdin.write('\x1b[Z');
  await flush();
  await flush();

  assert.deepEqual(captured, ['plan']);
  assert.equal(store.getState().policy, 'plan');
  assert.match(lastFrame() ?? '', /mode → Plan/);
  assert.match(lastFrame() ?? '', /Plan/);
});

test('Ctrl+O reports when no expandable tool output is available', async () => {
  const store = makeStore();
  const { stdin, lastFrame } = render(<App store={store} onSubmit={() => {}} />);

  stdin.write('\x0f');
  await flush();

  assert.match(lastFrame() ?? '', /no tool output to expand/);
});

test('Ctrl+O reports which tool output changed', async () => {
  const store = makeStore();
  store.dispatch({
    type: 'tool-hook-end',
    result: {
      tool: 'bash',
      status: 'ok',
      content: 'TOOL_RESULT bash ok\n$ ls\none\ntwo',
      meta: {}
    }
  });
  const { stdin, lastFrame } = render(<App store={store} onSubmit={() => {}} />);

  stdin.write('\x0f');
  await flush();

  assert.equal(
    store.getState().transcript.find((entry) => entry.kind === 'tool')?.expanded,
    true
  );
  assert.match(lastFrame() ?? '', /expanded bash output/);
});

test('submitted prompt immediately enters running state and blocks a second submit', async () => {
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

  stdin.write('first');
  await flush();
  stdin.write('\r');
  await flush();
  assert.deepEqual(submitted, ['first']);
  assert.notEqual(store.getState().activeTurn, null);
  assert.match(lastFrame() ?? '', /Running · Ctrl\+C cancel/);

  stdin.write('second');
  await flush();
  stdin.write('\r');
  await flush();
  assert.deepEqual(submitted, ['first']);
  assert.doesNotMatch(lastFrame() ?? '', /> second/);
});

test('Ctrl+C while approval is pending force-denies and cancels the turn', async () => {
  const store = makeStore();
  store.dispatch({ type: 'user-input', text: 'needs approval' });
  let resolved: UiApprovalDecision | null = null;
  const pending: PendingApproval = {
    id: 'pa_cancel',
    subject: approvalSubject,
    resolve: (decision) => {
      resolved = decision;
    }
  };
  store.dispatch({ type: 'approval-request', pending });
  let cancels = 0;

  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onCancelTurn={() => {
        cancels += 1;
      }}
    />
  );
  await flush();

  stdin.write('\x03');
  await flush();

  assert.equal(resolved, 'deny');
  assert.equal(store.getState().pendingApproval, null);
  assert.equal(cancels, 1);
  assert.match(lastFrame() ?? '', /cancelling/);
});

test('approval state ignores non-cancel global shortcuts', async () => {
  const store = makeStore();
  let resolved: UiApprovalDecision | null = null;
  const pending: PendingApproval = {
    id: 'pa_scope',
    subject: approvalSubject,
    resolve: (decision) => {
      resolved = decision;
    }
  };
  store.dispatch({ type: 'approval-request', pending });
  const policyChanges: string[] = [];
  const { stdin } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onPolicyChange={(mode) => {
        policyChanges.push(mode);
      }}
    />
  );
  await flush();

  stdin.write('\x1b[Z'); // Shift+Tab
  stdin.write('\x0f'); // Ctrl+O
  await flush();

  assert.deepEqual(policyChanges, []);
  assert.equal(store.getState().policy, 'yolo');
  assert.equal(resolved, null);
  assert.equal(store.getState().pendingApproval, pending);
});

test('approval state suppresses normal composer hints and keeps approval choices visible', async () => {
  const store = makeStore();
  let resolved: UiApprovalDecision | null = null;
  const pending: PendingApproval = {
    id: 'pa_hint',
    subject: approvalSubject,
    resolve: (decision) => {
      resolved = decision;
    }
  };
  store.dispatch({ type: 'approval-request', pending });
  const { stdin, lastFrame } = render(<App store={store} onSubmit={() => {}} />);
  await flush();

  const frame = lastFrame() ?? '';
  assert.match(frame, /Approval required/);
  assert.match(frame, /\[y\]es allow/);
  assert.doesNotMatch(frame, /Enter send/);
  assert.doesNotMatch(frame, /\/help commands/);

  stdin.write('n');
  await flush();
  assert.equal(resolved, 'deny');
});

test('regular text input still routes to onSubmit and appends a user entry', async () => {
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
  stdin.write('hello agent');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();
  assert.deepEqual(submitted, ['hello agent']);
  assert.match(lastFrame() ?? '', /hello agent/);
});

test('up arrow recalls the most recent submitted user input; down restores the draft', async () => {
  // Drive two submissions through the user-input path so the transcript
  // (and therefore the history projection) ends up with ['foo', 'bar'].
  const store = makeStore();
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={(text) => {
        store.dispatch({ type: 'runtime-event', event: { type: 'final', message: `ack ${text}` } });
      }}
    />
  );

  stdin.write('foo');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();
  stdin.write('bar');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();

  // Type a draft we expect to be saved on first ↑.
  stdin.write('draft');
  await flush();
  // ↑ → newest entry ('bar') is now in the input row.
  stdin.write('\x1b[A');
  await flush();
  const afterFirstUp = lastFrame() ?? '';
  assert.match(afterFirstUp, /> bar/);

  // ↑ again → older entry ('foo').
  stdin.write('\x1b[A');
  await flush();
  const afterSecondUp = lastFrame() ?? '';
  assert.match(afterSecondUp, /> foo/);

  // ↓ → back to 'bar'. ↓ once more → the saved draft.
  stdin.write('\x1b[B');
  await flush();
  assert.match(lastFrame() ?? '', /> bar/);
  stdin.write('\x1b[B');
  await flush();
  const afterRestore = lastFrame() ?? '';
  assert.match(afterRestore, /> draft/);
});
