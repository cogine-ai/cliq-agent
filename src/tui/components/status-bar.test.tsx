import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { createInitialState, type UiState } from '../store.js';
import { StatusBar } from './status-bar.js';

const init = (overrides: Partial<UiState> = {}): UiState => ({
  ...createInitialState({
    policy: 'yolo',
    model: { provider: 'ollama', model: 'qwen3:4b' },
    session: { id: 'ses_a1b2c3d4ef', cwd: '/tmp/repo' },
  }),
  ...overrides,
});

test('renders mode and hint before technical status details', () => {
  const { lastFrame } = render(
    <StatusBar state={init()} hint="Shift+Tab cycle · Ctrl+D exit" />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /bypass permissions on/);
  assert.match(frame, /Shift\+Tab cycle/);
  assert.match(frame, /ollama\/qwen3:4b/);
  assert.doesNotMatch(frame, /! YOLO/);
  assert.doesNotMatch(frame, / · yolo · /);
  assert.match(frame, /ses_a1b2c3/);
  assert.match(frame, /repo/);
  assert.match(frame, /tx idle/);
  assert.ok(frame.indexOf('bypass permissions on') < frame.indexOf('ollama/qwen3:4b'));
});

test('shows a red error indicator when errors are present', () => {
  const state = init({
    errors: [{ id: 'e1', stage: 'model', message: 'oops' }],
  });
  const { lastFrame } = render(<StatusBar state={state} />);
  const frame = lastFrame() ?? '';
  // ANSI red for ● — assert presence of the glyph at minimum
  assert.match(frame, /●/);
});

test('reflects updated policy mode', () => {
  const { lastFrame } = render(<StatusBar state={init({ policy: 'plan' })} />);
  assert.match(lastFrame() ?? '', /plan mode/);
});

test('renders the active tx state when state.tx is set', () => {
  const { lastFrame } = render(
    <StatusBar state={init({ tx: { txId: 'tx_abc123def', state: 'validated' } })} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /tx tx_abc123 validated/);
  assert.doesNotMatch(frame, /tx idle/);
});

test('renders the session token estimate when sessionTokens is non-null', () => {
  // Just over the 1k boundary to exercise the k-suffix formatter.
  const { lastFrame } = render(<StatusBar state={init({ sessionTokens: 12345 })} />);
  assert.match(lastFrame() ?? '', /12\.3k tok/);

  // Below 1k stays as raw integer.
  const small = render(<StatusBar state={init({ sessionTokens: 850 })} />);
  assert.match(small.lastFrame() ?? '', /850 tok/);

  // null hides the segment entirely.
  const none = render(<StatusBar state={init({ sessionTokens: null })} />);
  assert.doesNotMatch(none.lastFrame() ?? '', /tok/);
});

test('renders update notice when a newer version is available', () => {
  const state = {
    ...init(),
    versionUpdate: { current: '0.9.0', latest: '0.10.0' }
  };
  const { lastFrame } = render(<StatusBar state={state} />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /update 0\.10\.0/);
  assert.ok(frame.trimEnd().endsWith('update 0.10.0'));
});

test('renders supplied running-state hints in the footer', () => {
  const state = init({ activeTurn: { modelChunks: 0, modelChars: 0 } });
  const { lastFrame } = render(<StatusBar state={state} hint="Running · Ctrl+C cancel" />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /Running/);
  assert.match(frame, /Ctrl\+C cancel/);
});

test('does not synthesize running-state hints without an explicit hint', () => {
  const state = init({ activeTurn: { modelChunks: 0, modelChars: 0 } });
  const { lastFrame } = render(<StatusBar state={state} />);
  const frame = lastFrame() ?? '';
  assert.doesNotMatch(frame, /running/);
  assert.doesNotMatch(frame, /Ctrl\+C cancel/);
});

test('does not synthesize approval-state hints without an explicit hint', () => {
  const state = init({
    pendingApproval: {
      id: 'pa_status',
      subject: {
        kind: 'tool',
        toolName: 'bash',
        access: 'exec',
        channel: { kind: 'bash', commandHead: 'ls', unsafeForAllow: false },
        action: { bash: 'ls' } as never,
        display: { title: 'Allow bash command?', command: 'ls' }
      },
      resolve: () => undefined
    }
  });
  const { lastFrame } = render(<StatusBar state={state} />);
  const frame = lastFrame() ?? '';
  assert.doesNotMatch(frame, /approval/);
  assert.doesNotMatch(frame, /Ctrl\+C cancel/);
});
