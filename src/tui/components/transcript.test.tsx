import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import type { TranscriptEntry } from '../store.js';
import { Transcript } from './transcript.js';

test('renders transcript entries in order', () => {
  const entries: TranscriptEntry[] = [
    { kind: 'user', id: 'u1', text: 'hi' },
    { kind: 'assistant', id: 'a1', text: 'hello back' },
  ];
  const { lastFrame } = render(<Transcript entries={entries} activeTurn={null} />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /hi/);
  assert.match(frame, /hello back/);
  assert.ok(frame.indexOf('hi') < frame.indexOf('hello back'), 'user entry must precede assistant');
});

test('renders an active-turn thinking row when activeTurn is present', () => {
  const { lastFrame } = render(
    <Transcript entries={[]} activeTurn={{ modelChunks: 3, modelChars: 842 }} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /thinking/);
  assert.match(frame, /0s/);
  assert.match(frame, /~ 211 tok/);
  assert.doesNotMatch(frame, /chars/);
});

test('omits active-turn token label before output is observed', () => {
  const { lastFrame } = render(
    <Transcript entries={[]} activeTurn={{ modelChunks: 0, modelChars: 0 }} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /thinking/);
  assert.match(frame, /0s/);
  assert.doesNotMatch(frame, /~ 0 tok/);
});

test('omits the thinking row when activeTurn is null', () => {
  const { lastFrame } = render(
    <Transcript entries={[{ kind: 'user', id: 'u1', text: 'hi' }]} activeTurn={null} />
  );
  assert.doesNotMatch(lastFrame() ?? '', /thinking/);
});

test('renders nothing when there are no entries and no active turn', () => {
  const { lastFrame } = render(<Transcript entries={[]} activeTurn={null} />);
  assert.equal(lastFrame(), '');
});

test('caps visible entries at 200 (older entries fall to shell scrollback)', () => {
  const entries: TranscriptEntry[] = Array.from({ length: 250 }, (_, i) => ({
    kind: 'user' as const,
    id: `u${i}`,
    text: `entry-${i}`,
  }));
  const { lastFrame } = render(<Transcript entries={entries} activeTurn={null} />);
  const frame = lastFrame() ?? '';
  // last entry (index 249) must be visible; first (index 0) must be cropped.
  assert.match(frame, /entry-249/);
  assert.doesNotMatch(frame, /entry-0\b/);
});
