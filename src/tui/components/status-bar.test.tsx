import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { createInitialState, type UiState } from '../store.js';
import { StatusBar } from './status-bar.js';

const init = (overrides: Partial<UiState> = {}): UiState => ({
  ...createInitialState({
    policy: 'auto',
    model: { provider: 'ollama', model: 'qwen3:4b' },
    session: { id: 'ses_a1b2c3d4ef', cwd: '/tmp/repo' },
  }),
  ...overrides,
});

test('renders provider/model · policy · short session · cwd basename · tx idle', () => {
  const { lastFrame } = render(<StatusBar state={init()} />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /ollama\/qwen3:4b/);
  assert.match(frame, /auto/);
  assert.match(frame, /ses_a1b2c3/);
  assert.match(frame, /repo/);
  assert.match(frame, /tx idle/);
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
  const { lastFrame } = render(<StatusBar state={init({ policy: 'read-only' })} />);
  assert.match(lastFrame() ?? '', /read-only/);
});

test('renders the active tx state when state.tx is set', () => {
  const { lastFrame } = render(
    <StatusBar state={init({ tx: { txId: 'tx_abc123def', state: 'validated' } })} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /tx tx_abc123 validated/);
  assert.doesNotMatch(frame, /tx idle/);
});
