import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { InputBar } from './input-bar.js';

test('renders an active prompt glyph by default', () => {
  const { lastFrame } = render(<InputBar onSubmit={() => {}} />);
  assert.match(lastFrame() ?? '', />/);
});

test('renders a dimmed waiting glyph when disabled', () => {
  const { lastFrame } = render(<InputBar onSubmit={() => {}} disabled />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /…/);
  assert.doesNotMatch(frame, /^>/m);
});

test('typing into the field accumulates and submit fires onSubmit with trimmed text', async () => {
  const submitted: string[] = [];
  const { stdin, lastFrame } = render(
    <InputBar
      onSubmit={(text) => {
        submitted.push(text);
      }}
    />
  );

  stdin.write('  hello world  ');
  // Allow Ink's input pipeline to flush.
  await new Promise((r) => setTimeout(r, 10));
  assert.match(lastFrame() ?? '', /hello world/);

  stdin.write('\r'); // Enter
  await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(submitted, ['hello world']);
});

test('empty submit is a no-op', async () => {
  const submitted: string[] = [];
  const { stdin } = render(
    <InputBar
      onSubmit={(text) => {
        submitted.push(text);
      }}
    />
  );
  stdin.write('   \r');
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(submitted.length, 0);
});
