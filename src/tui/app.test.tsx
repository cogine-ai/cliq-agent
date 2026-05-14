import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { App } from './app.js';
import { createInitialState, createUiStore } from './store.js';

const flush = () => new Promise<void>((r) => setImmediate(r));

const makeStore = () =>
  createUiStore(
    createInitialState({
      policy: 'auto',
      model: { provider: 'ollama', model: 'qwen3:4b' },
      session: { id: 'ses_smoke', cwd: '/tmp/smoke' }
    })
  );

test('mounts and renders status bar segments', () => {
  const store = makeStore();
  const { lastFrame } = render(<App store={store} onSubmit={() => {}} />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /ollama\/qwen3:4b/);
  assert.match(frame, /auto/);
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
  stdin.write('/policy read-only');
  await flush();
  stdin.write('\r');
  await flush();
  await flush(); // extra tick for the awaited onPolicyChange chain
  assert.deepEqual(captured, ['read-only']);
  assert.equal(store.getState().policy, 'read-only');
});

test('/reset awaits onReset and clears the transcript via session-reset', async () => {
  const store = makeStore();
  store.dispatch({ type: 'user-input', text: 'before reset' });
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
  const { stdin, lastFrame } = render(<App store={store} onSubmit={() => {}} />);

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
