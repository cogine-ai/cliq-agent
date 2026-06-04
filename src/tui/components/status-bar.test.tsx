import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { createInitialState, type UiState } from '../store.js';
import { BottomStatusBar, TopStatusBar } from './status-bar.js';

const init = (overrides: Partial<UiState> = {}): UiState => ({
  ...createInitialState({
    policy: 'yolo',
    model: { provider: 'ollama', model: 'qwen3:4b' },
    session: { id: 'ses_a1b2c3d4ef', cwd: '/tmp/repo' },
  }),
  ...overrides,
});

test('top status bar renders action hints without technical details', () => {
  const { lastFrame } = render(<TopStatusBar hint="Shift+Tab cycle · Ctrl+D exit" />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /Shift\+Tab cycle/);
  assert.doesNotMatch(frame, /ollama\/qwen3:4b/);
  assert.doesNotMatch(frame, /ses_a1b2c3/);
  assert.doesNotMatch(frame, /repo/);
  assert.doesNotMatch(frame, /tx idle/);
});

test('bottom status bar renders cwd and technical details without model, session, or policy mode', () => {
  const { lastFrame } = render(<BottomStatusBar state={init()} />);
  const frame = lastFrame() ?? '';
  assert.doesNotMatch(frame, /bypass permissions on/);
  assert.doesNotMatch(frame, /ollama\/qwen3:4b/);
  assert.doesNotMatch(frame, /! YOLO/);
  assert.doesNotMatch(frame, / · yolo · /);
  assert.doesNotMatch(frame, /ses_a1b2c3/);
  assert.match(frame, /\/tmp\/repo/);
  assert.match(frame, /tx idle/);
});

test('bottom status bar preserves the full cwd instead of only the basename', () => {
  const cwd = '/Users/kiedis/Coding/AI/cliq-agent';
  const { lastFrame } = render(<BottomStatusBar state={init({ session: { id: 'ses_x', cwd } })} />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /\/Users\/kiedis\/Coding\/AI\/cliq-agent/);
  assert.doesNotMatch(frame, /(^| · )\/cliq-agent( · |$)/);
});

test('shows a red error indicator when errors are present', () => {
  const state = init({
    errors: [{ id: 'e1', stage: 'model', message: 'oops' }],
  });
  const { lastFrame } = render(<BottomStatusBar state={state} />);
  const frame = lastFrame() ?? '';
  // ANSI red for ● — assert presence of the glyph at minimum
  assert.match(frame, /●/);
});

test('does not render policy mode label because the composer owns mode context', () => {
  const { lastFrame } = render(<BottomStatusBar state={init({ policy: 'plan' })} />);
  assert.doesNotMatch(lastFrame() ?? '', /plan mode/);
});

test('renders the active tx state when state.tx is set', () => {
  const { lastFrame } = render(
    <BottomStatusBar state={init({ tx: { txId: 'tx_abc123def', state: 'validated' } })} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /tx tx_abc123 validated/);
  assert.doesNotMatch(frame, /tx idle/);
});

test('renders the session token estimate when sessionTokens is non-null', () => {
  // Just over the 1k boundary to exercise the k-suffix formatter.
  const { lastFrame } = render(<BottomStatusBar state={init({ sessionTokens: 12345 })} />);
  assert.match(lastFrame() ?? '', /session 12\.3k tok/);

  // Below 1k stays as raw integer.
  const small = render(<BottomStatusBar state={init({ sessionTokens: 850 })} />);
  assert.match(small.lastFrame() ?? '', /session 850 tok/);

  // null hides the segment entirely.
  const none = render(<BottomStatusBar state={init({ sessionTokens: null })} />);
  assert.doesNotMatch(none.lastFrame() ?? '', /tok/);
});

test('keeps the session token estimate visible when cwd is long', () => {
  const cwd = '/Users/kiedis/Coding/AI/some/deeply/nested/workspace/with/a/very/long/project/name/that/exceeds/terminal/width';
  const { lastFrame } = render(<BottomStatusBar state={init({ session: { id: 'ses_x', cwd }, sessionTokens: 12345 })} />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /session 12\.3k tok/);
  assert.match(frame, /\/Users\/kiedis\/Coding\/AI/);
});

test('renders update notice when a newer version is available', () => {
  const state = {
    ...init(),
    versionUpdate: { current: '0.9.0', latest: '0.10.0' }
  };
  const { lastFrame } = render(<BottomStatusBar state={state} />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /update 0\.10\.0/);
  assert.ok(frame.trimEnd().endsWith('update 0.10.0'));
});

test('renders supplied running-state hints in the footer', () => {
  const { lastFrame } = render(<TopStatusBar hint="Running · Ctrl+C cancel" />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /Running/);
  assert.match(frame, /Ctrl\+C cancel/);
});

test('does not synthesize running-state hints without an explicit hint', () => {
  const { lastFrame } = render(<TopStatusBar hint={null} />);
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
  const { lastFrame } = render(<BottomStatusBar state={state} />);
  const frame = lastFrame() ?? '';
  assert.doesNotMatch(frame, /approval/);
  assert.doesNotMatch(frame, /Ctrl\+C cancel/);
});
