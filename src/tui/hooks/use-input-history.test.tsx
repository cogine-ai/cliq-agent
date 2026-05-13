import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';
import { Text } from 'ink';
import { useState } from 'react';

import { useInputHistory, type InputHistoryHandlers } from './use-input-history.js';

type Harness = {
  value: string;
  handlers: InputHistoryHandlers;
};

// Renders nothing; exposes the hook's handlers and the controlled value
// through a captured reference each render. Tests drive the handlers
// synchronously and read `captured.value` after each call.
function Probe({
  history,
  initial,
  capture
}: {
  history: readonly string[];
  initial: string;
  capture: (h: Harness) => void;
}) {
  const [value, setValue] = useState(initial);
  const handlers = useInputHistory({ history, current: value, setValue });
  capture({ value, handlers });
  return <Text>{value}</Text>;
}

function setup(history: readonly string[], initial = '') {
  let latest: Harness = { value: initial, handlers: null as unknown as InputHistoryHandlers };
  const { rerender, unmount } = render(
    <Probe
      history={history}
      initial={initial}
      capture={(h) => {
        latest = h;
      }}
    />
  );
  return {
    get value() {
      return latest.value;
    },
    handlers: () => latest.handlers,
    refresh: () => {
      rerender(
        <Probe
          history={history}
          initial={initial}
          capture={(h) => {
            latest = h;
          }}
        />
      );
    },
    unmount
  };
}

test('empty history: prev and next are no-ops', () => {
  const probe = setup([], 'draft');
  probe.handlers().onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'draft');
  probe.handlers().onHistoryNext();
  probe.refresh();
  assert.equal(probe.value, 'draft');
  probe.unmount();
});

test('prev enters history at the newest entry; saved draft is preserved', () => {
  const probe = setup(['foo', 'bar', 'baz'], 'in-progress');
  probe.handlers().onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'baz');
  probe.unmount();
});

test('prev walks backwards to the oldest entry; further prev is a no-op (no wrap)', () => {
  const probe = setup(['foo', 'bar', 'baz'], '');
  const { onHistoryPrev } = probe.handlers();
  onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'baz');
  probe.handlers().onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'bar');
  probe.handlers().onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'foo');
  probe.handlers().onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'foo');
  probe.unmount();
});

test('next from null index is a no-op (cannot step past the present)', () => {
  const probe = setup(['foo'], 'draft');
  probe.handlers().onHistoryNext();
  probe.refresh();
  assert.equal(probe.value, 'draft');
  probe.unmount();
});

test('walking back past the newest entry restores the saved draft', () => {
  const probe = setup(['foo', 'bar'], 'my-draft');
  probe.handlers().onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'bar');
  probe.handlers().onHistoryNext();
  probe.refresh();
  assert.equal(probe.value, 'my-draft');
  probe.unmount();
});

test('after restoring the draft, prev again starts from the newest entry', () => {
  const probe = setup(['foo', 'bar'], 'd1');
  probe.handlers().onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'bar');
  probe.handlers().onHistoryNext();
  probe.refresh();
  assert.equal(probe.value, 'd1');
  probe.handlers().onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'bar');
  probe.unmount();
});

test('resetHistoryNav after a recall: next prev starts fresh from newest with the latest current as draft', () => {
  const probe = setup(['foo', 'bar'], 'd1');
  probe.handlers().onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'bar');
  // Simulate the user typing a new draft after a recall: the parent edits
  // the buffer and calls resetHistoryNav so the next ↑ saves THIS draft.
  probe.handlers().resetHistoryNav();
  probe.refresh();
  // Now the next ↑ should save whatever `current` is at that moment (still
  // 'bar' from the recall) and put us back at the newest entry.
  probe.handlers().onHistoryPrev();
  probe.refresh();
  assert.equal(probe.value, 'bar');
  probe.handlers().onHistoryNext();
  probe.refresh();
  // Draft was 'bar' at the moment of the second ↑, so coming back down
  // restores 'bar' (not 'd1' — that was cleared by resetHistoryNav).
  assert.equal(probe.value, 'bar');
  probe.unmount();
});
