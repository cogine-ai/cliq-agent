import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { TranscriptRow } from './transcript-row.js';

test('renders a user entry with a > prefix', () => {
  const { lastFrame } = render(<TranscriptRow entry={{ kind: 'user', id: 'u1', text: 'hello' }} />);
  assert.match(lastFrame() ?? '', />/);
  assert.match(lastFrame() ?? '', /hello/);
});

test('renders an assistant entry plain', () => {
  const { lastFrame } = render(
    <TranscriptRow entry={{ kind: 'assistant', id: 'a1', text: 'response' }} />
  );
  assert.match(lastFrame() ?? '', /response/);
  assert.doesNotMatch(lastFrame() ?? '', />/);
});

test('renders a tool entry with status glyph and tool name', () => {
  const { lastFrame } = render(
    <TranscriptRow
      entry={{ kind: 'tool', id: 't1', tool: 'bash', status: 'ok', preview: 'ls' }}
    />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /bash/);
  assert.match(frame, /ls/);
});

test('renders a system entry as italic dim text', () => {
  const { lastFrame } = render(
    <TranscriptRow entry={{ kind: 'system', id: 's1', text: 'session reset' }} />
  );
  assert.match(lastFrame() ?? '', /session reset/);
});
