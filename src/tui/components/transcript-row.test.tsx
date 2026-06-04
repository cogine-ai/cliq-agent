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

test('renders a tool entry with status glyph, name, and summary', () => {
  const { lastFrame } = render(
    <TranscriptRow
      entry={{ kind: 'tool', id: 't1', tool: 'edit', status: 'ok', summary: 'src/foo.ts' }}
    />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /edit/);
  assert.match(frame, /src\/foo\.ts/);
});

test('renders a tool entry without a summary (running, no preview yet)', () => {
  const { lastFrame } = render(
    <TranscriptRow entry={{ kind: 'tool', id: 't1', tool: 'bash', status: 'running', summary: '' }} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /bash/);
  assert.doesNotMatch(frame, /—/); // no detail separator without a summary
});

test('renders short tool output folded to one line', () => {
  const lines = Array.from({ length: 6 }, (_, i) => `line-${i + 1}`).join('\n');
  const { lastFrame } = render(
    <TranscriptRow
      entry={{
        kind: 'tool',
        id: 't1',
        tool: 'ls',
        status: 'ok',
        summary: 'src',
        body: lines
      }}
    />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /line-1\b/);
  assert.doesNotMatch(frame, /line-2\b/);
  assert.match(frame, /5 more lines/);
});

test('renders medium tool output folded to two lines', () => {
  const lines = Array.from({ length: 12 }, (_, i) => `line-${i + 1}`).join('\n');
  const { lastFrame } = render(
    <TranscriptRow
      entry={{
        kind: 'tool',
        id: 't1',
        tool: 'grep',
        status: 'ok',
        summary: 'pattern in src',
        body: lines
      }}
    />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /line-1\b/);
  assert.match(frame, /line-2\b/);
  assert.doesNotMatch(frame, /line-3\b/);
  assert.match(frame, /10 more lines/);
});

test('renders long tool output folded to at most four lines', () => {
  const lines = Array.from({ length: 25 }, (_, i) => `line-${i + 1}`).join('\n');
  const { lastFrame } = render(
    <TranscriptRow
      entry={{
        kind: 'tool',
        id: 't1',
        tool: 'bash',
        status: 'ok',
        summary: 'npm test',
        body: lines
      }}
    />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /line-1\b/);
  assert.match(frame, /line-4\b/);
  assert.doesNotMatch(frame, /line-5\b/);
  assert.match(frame, /21 more lines/);
});

test('a trailing newline in bash body does not inflate the "more lines" count', () => {
  // 5 real lines plus a trailing newline — the fold should report 4 more,
  // not count the trailing newline as a sixth row.
  const body = ['a', 'b', 'c', 'd', 'e'].join('\n') + '\n';
  const { lastFrame } = render(
    <TranscriptRow
      entry={{ kind: 'tool', id: 't1', tool: 'bash', status: 'ok', summary: 'cmd', body }}
    />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /4 more lines/);
  assert.doesNotMatch(frame, /5 more lines/);
});

test('renders the full bash body when entry.expanded is true', () => {
  const lines = Array.from({ length: 25 }, (_, i) => `row-${i + 1}`).join('\n');
  const { lastFrame } = render(
    <TranscriptRow
      entry={{
        kind: 'tool',
        id: 't1',
        tool: 'bash',
        status: 'ok',
        summary: 'npm test',
        body: lines,
        expanded: true
      }}
    />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /row-1\b/);
  assert.match(frame, /row-25\b/);
  assert.doesNotMatch(frame, /more lines/);
});

test('renders a system entry as italic dim text', () => {
  const { lastFrame } = render(
    <TranscriptRow entry={{ kind: 'system', id: 's1', text: 'session reset' }} />
  );
  assert.match(lastFrame() ?? '', /session reset/);
});
