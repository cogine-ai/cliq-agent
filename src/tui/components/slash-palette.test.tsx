import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { SlashPalette } from './slash-palette.js';

test('renders all slash commands when the query is just "/"', () => {
  const { lastFrame } = render(<SlashPalette query="/" />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /\/exit/);
  assert.match(frame, /\/reset/);
  assert.match(frame, /\/policy/);
  assert.match(frame, /\/help/);
  assert.match(frame, /tab to complete/);
});

test('narrows to a single command on a more specific prefix', () => {
  const { lastFrame } = render(<SlashPalette query="/po" />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /\/policy/);
  assert.doesNotMatch(frame, /\/exit/);
});

test('renders nothing when the query has no matches', () => {
  const { lastFrame } = render(<SlashPalette query="/zz" />);
  assert.equal(lastFrame(), '');
});

test('renders nothing for non-slash input', () => {
  const { lastFrame } = render(<SlashPalette query="hello" />);
  assert.equal(lastFrame(), '');
});
