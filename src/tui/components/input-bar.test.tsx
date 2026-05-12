import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { InputBar } from './input-bar.js';

test('renders an active prompt glyph by default', () => {
  const { lastFrame } = render(<InputBar value="" onChange={() => {}} onSubmit={() => {}} />);
  assert.match(lastFrame() ?? '', />/);
});

test('renders a dimmed waiting glyph when disabled', () => {
  const { lastFrame } = render(
    <InputBar value="" onChange={() => {}} onSubmit={() => {}} disabled />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /…/);
  assert.doesNotMatch(frame, /^>/m);
});

test('typing into the field invokes onChange and submit fires onSubmit with trimmed text', async () => {
  let value = '';
  const onChange = (next: string) => {
    value = next;
  };
  const submitted: string[] = [];
  const { stdin, rerender } = render(
    <InputBar
      value={value}
      onChange={onChange}
      onSubmit={(text) => {
        submitted.push(text);
      }}
    />
  );

  stdin.write('  hello world  ');
  await new Promise((r) => setTimeout(r, 10));
  // Re-render with the latest value so ink-text-input picks up the controlled state.
  rerender(
    <InputBar
      value={value}
      onChange={onChange}
      onSubmit={(text) => {
        submitted.push(text);
      }}
    />
  );

  stdin.write('\r');
  await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(submitted, ['hello world']);
});

test('empty submit is a no-op', async () => {
  const submitted: string[] = [];
  const { stdin } = render(
    <InputBar
      value=""
      onChange={() => {}}
      onSubmit={(text) => {
        submitted.push(text);
      }}
    />
  );
  stdin.write('   \r');
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(submitted.length, 0);
});

test('Tab key applies the completion when one is provided', async () => {
  let value = '/p';
  const changes: string[] = [];
  const onChange = (next: string) => {
    value = next;
    changes.push(next);
  };
  const { stdin } = render(
    <InputBar value={value} onChange={onChange} onSubmit={() => {}} completion="/policy " />
  );
  stdin.write('\t');
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(changes[changes.length - 1], '/policy ');
});

test('control chars (e.g. Ctrl+O = \\x0f) are stripped before reaching onChange', async () => {
  const calls: string[] = [];
  const { stdin } = render(
    <InputBar
      value=""
      onChange={(next) => {
        calls.push(next);
      }}
      onSubmit={() => {}}
    />
  );
  // Ctrl+O fires in Ink even though its bytes are control. The input bar
  // must drop them so the App-level keybinding handler is the only consumer.
  stdin.write('\x0f');
  await new Promise((r) => setTimeout(r, 10));
  // onChange is gated on cleaned !== value, so a pure-control keystroke
  // against an empty buffer must not fire onChange at all.
  assert.equal(calls.length, 0);
});

test('LF / Ctrl+J (\\x0a) is also stripped — single-line input must not gain a newline', async () => {
  const calls: string[] = [];
  const { stdin } = render(
    <InputBar
      value=""
      onChange={(next) => {
        calls.push(next);
      }}
      onSubmit={() => {}}
    />
  );
  // \x0a is LF; same byte as Ctrl+J. Some pastes also splice LFs into the
  // stream. Either way, it must not survive into the controlled value.
  stdin.write('\x0a');
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(calls.length, 0);
});

test('Tab is a no-op when completion equals current value', async () => {
  const changes: string[] = [];
  const { stdin } = render(
    <InputBar
      value="/policy"
      onChange={(next) => {
        changes.push(next);
      }}
      onSubmit={() => {}}
      completion="/policy"
    />
  );
  stdin.write('\t');
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(changes.length, 0);
});
