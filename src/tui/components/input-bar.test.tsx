import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { InputBar } from './input-bar.js';

// Yield the macrotask so Ink's stdin parser has a chance to dispatch the
// useInput callbacks queued by the prior stdin.write(). setImmediate is more
// deterministic than a fixed timeout (which is flaky on slow CI runners) and
// matches the helper already used in app.test.tsx.
const flush = () => new Promise<void>((r) => setImmediate(r));

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
  await flush();
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
  await flush();
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
  await flush();
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
  await flush();
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
  await flush();
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
  await flush();
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
  await flush();
  assert.equal(changes.length, 0);
});

test('raw Shift+Tab escape is swallowed before reaching the prompt buffer', async () => {
  const changes: string[] = [];
  const { stdin } = render(
    <InputBar
      value=""
      onChange={(next) => {
        changes.push(next);
      }}
      onSubmit={() => {}}
    />
  );
  stdin.write('\x1b[Z');
  await flush();
  assert.equal(changes.length, 0);
});

// Ink emits arrow keys as ANSI escape sequences (e.g. "\x1b[D" for left).
// ink-testing-library forwards stdin bytes through Ink's parser, so writing
// the raw sequence is the closest we can get to a real key press.
const KEY_LEFT = '\x1b[D';
const KEY_RIGHT = '\x1b[C';
const KEY_UP = '\x1b[A';
const KEY_DOWN = '\x1b[B';

test('left arrow then printable inserts at the cursor (middle of buffer)', async () => {
  let value = 'helo';
  const changes: string[] = [];
  const onChange = (next: string) => {
    value = next;
    changes.push(next);
  };
  const { stdin, rerender } = render(
    <InputBar value={value} onChange={onChange} onSubmit={() => {}} />
  );
  // Move cursor: 4 → 3 → 2. Now sitting between 'e' and 'l'.
  stdin.write(KEY_LEFT);
  await flush();
  stdin.write(KEY_LEFT);
  await flush();
  // Insert 'l' at the cursor: 'helo' → 'hello'.
  stdin.write('l');
  await flush();
  assert.equal(changes[changes.length - 1], 'hello');
  rerender(<InputBar value={value} onChange={onChange} onSubmit={() => {}} />);
});

test('backspace at cursor=0 is a no-op', async () => {
  let value = 'hi';
  const calls: string[] = [];
  const onChange = (next: string) => {
    value = next;
    calls.push(next);
  };
  const { stdin, rerender } = render(
    <InputBar value={value} onChange={onChange} onSubmit={() => {}} />
  );
  // Move cursor to position 0 (start of buffer).
  stdin.write(KEY_LEFT);
  await flush();
  stdin.write(KEY_LEFT);
  await flush();
  // Backspace from cursor=0 must not fire onChange.
  stdin.write('');
  await flush();
  assert.equal(calls.length, 0);
  rerender(<InputBar value={value} onChange={onChange} onSubmit={() => {}} />);
});

test('backspace at cursor in the middle deletes the char before the cursor', async () => {
  let value = 'helXlo';
  const changes: string[] = [];
  const onChange = (next: string) => {
    value = next;
    changes.push(next);
  };
  const { stdin, rerender } = render(
    <InputBar value={value} onChange={onChange} onSubmit={() => {}} />
  );
  // Cursor starts at end (=6). Walk left to position 4 (between 'X' and 'l').
  for (let i = 0; i < 2; i += 1) {
    stdin.write(KEY_LEFT);
    await flush();
  }
  // Backspace should delete 'X' (the char before the cursor at offset 4).
  stdin.write('');
  await flush();
  assert.equal(changes[changes.length - 1], 'hello');
  rerender(<InputBar value={value} onChange={onChange} onSubmit={() => {}} />);
});

test('right arrow at end of buffer is a no-op and never leaks the escape bytes', async () => {
  const changes: string[] = [];
  const { stdin } = render(
    <InputBar
      value="abc"
      onChange={(next) => {
        changes.push(next);
      }}
      onSubmit={() => {}}
    />
  );
  // Cursor starts at value.length=3 — right arrow has nowhere to go.
  stdin.write(KEY_RIGHT);
  await flush();
  assert.equal(changes.length, 0);
});

test('external value replacement (Tab completion) snaps cursor to end', async () => {
  // Boot the component with a value, walk the cursor left, then have the
  // parent push a fresh value through props (mimicking Tab completion).
  // The next keystroke after the replacement should append at the new end,
  // proving the cursor snapped rather than staying mid-buffer.
  let value = '/p';
  const changes: string[] = [];
  const onChange = (next: string) => {
    value = next;
    changes.push(next);
  };
  const { stdin, rerender } = render(
    <InputBar value={value} onChange={onChange} onSubmit={() => {}} completion="/policy " />
  );
  // Press Tab so the parent's useInput fires onChange('/policy ') — same
  // path Tab completion takes in production.
  stdin.write('\t');
  await flush();
  assert.equal(value, '/policy ');
  rerender(
    <InputBar value={value} onChange={onChange} onSubmit={() => {}} completion="/policy " />
  );
  // Now type a letter. If the cursor snapped to end (=8) it appends; if it
  // had stayed at 2 we'd see '/pXolicy '.
  stdin.write('x');
  await flush();
  assert.equal(value, '/policy x');
});

test('up arrow fires onHistoryPrev; down arrow fires onHistoryNext', async () => {
  let upCount = 0;
  let downCount = 0;
  const { stdin } = render(
    <InputBar
      value=""
      onChange={() => {}}
      onSubmit={() => {}}
      onHistoryPrev={() => {
        upCount += 1;
      }}
      onHistoryNext={() => {
        downCount += 1;
      }}
    />
  );
  stdin.write(KEY_UP);
  await flush();
  stdin.write(KEY_DOWN);
  await flush();
  assert.equal(upCount, 1);
  assert.equal(downCount, 1);
});

test('forward delete in the middle removes the char under the cursor', async () => {
  let value = 'helXlo';
  const changes: string[] = [];
  const onChange = (next: string) => {
    value = next;
    changes.push(next);
  };
  const { stdin, rerender } = render(
    <InputBar value={value} onChange={onChange} onSubmit={() => {}} />
  );
  // Cursor at end (=6). Walk left to position 3 (under 'X').
  for (let i = 0; i < 3; i += 1) {
    stdin.write(KEY_LEFT);
    await flush();
  }
  // Forward delete: removes 'X'. ink emits '\x1b[3~' for Delete.
  stdin.write('\x1b[3~');
  await flush();
  assert.equal(changes[changes.length - 1], 'hello');
  rerender(<InputBar value={value} onChange={onChange} onSubmit={() => {}} />);
});
