import { Box, Text, useInput, type Key } from 'ink';
import { useRef, useState } from 'react';

import { isShiftTabInput } from '../hooks/use-keybindings.js';

// ink-text-input v6 inserts the bare letter for Ctrl+<letter> combinations
// (its source only filters Ctrl+C explicitly), so Ctrl+O / Ctrl+G / Ctrl+L /
// etc. end up in the controlled buffer before the App-level keybinding
// handler can claim them. Rather than chase that with a swallow-ref against
// the in-renderer ordering of useInput callbacks, we use a tiny purpose-built
// single-line input that skips ALL modifier combinations.

// Pasted content still goes through this filter as defence — any embedded
// control bytes are dropped before they reach the controlled value.
const CONTROL_CHARS_IN_PASTE = /[\x00-\x1f\x7f]/g;

function MiniTextInput({
  value,
  onChange,
  onSubmit,
  onHistoryPrev,
  onHistoryNext,
  focus = true
}: {
  value: string;
  onChange: (next: string) => void;
  onSubmit?: (text: string) => void;
  onHistoryPrev?: () => void;
  onHistoryNext?: () => void;
  focus?: boolean;
}) {
  const [cursorOffset, setCursorOffset] = useState(value.length);
  // Echo detector: every time we initiate a value change we stash the
  // predicted string here. On the next render we compare the actual `value`
  // prop against it — if they match, the parent forwarded our own emission
  // and the cursor is already where we left it. If they DON'T match, the
  // parent (Tab completion, history recall, /reset etc.) replaced the value
  // out from under us and the cursor must snap to a sane spot.
  //
  // Why a ref and not useState? The textbook React pattern for "derive
  // state from props" stores the comparison key in useState and compares
  // during render (see "Adjusting state when a prop changes" in the React
  // docs). That works when props change *externally* only. Here the prop
  // ALSO changes as a forwarded echo of `emit()` — we need to stamp the
  // predicted next value *synchronously* before `onChange` so the next
  // render's comparison succeeds. useState would lag a render behind (the
  // setState commit hasn't happened yet by the time the parent forwards
  // our emission back), and we'd misclassify every keystroke as an
  // external replacement and snap the cursor to end of buffer. The ref
  // mutation is synchronous; that's the whole point of using it here.
  const lastEmittedRef = useRef<string | null>(value);

  if (lastEmittedRef.current !== value) {
    // External mutation. Setting state during render is intentional and
    // matches the "Adjusting state when a prop changes" pattern: React
    // discards the in-progress render and re-renders synchronously with
    // the corrected cursor — no flicker frame. Moving this into a
    // useEffect would paint one frame with a stale cursor before the
    // effect fired.
    if (cursorOffset !== value.length) {
      setCursorOffset(value.length);
    }
    lastEmittedRef.current = value;
  }

  function emit(next: string, nextCursor: number) {
    lastEmittedRef.current = next;
    setCursorOffset(nextCursor);
    onChange(next);
  }

  useInput(
    (input: string, key: Key) => {
      if (!focus) return;
      // App-level useKeybindings owns these. Returning here prevents the
      // letter component of a Ctrl combination (e.g. Ctrl+O → 'o') from
      // sneaking into the buffer.
      if (key.ctrl || key.meta) return;
      // Tab / Shift+Tab are reserved for slash completion and policy
      // rotation respectively — the parent's useInput claims both.
      if (isShiftTabInput(input, key)) return;
      if (key.tab) return;
      if (key.return) {
        onSubmit?.(value);
        return;
      }
      if (key.upArrow) {
        onHistoryPrev?.();
        return;
      }
      if (key.downArrow) {
        onHistoryNext?.();
        return;
      }
      if (key.leftArrow) {
        if (cursorOffset > 0) setCursorOffset(cursorOffset - 1);
        return;
      }
      if (key.rightArrow) {
        if (cursorOffset < value.length) setCursorOffset(cursorOffset + 1);
        return;
      }
      if (key.backspace) {
        if (cursorOffset === 0) return;
        const next = value.slice(0, cursorOffset - 1) + value.slice(cursorOffset);
        emit(next, cursorOffset - 1);
        return;
      }
      // Forward Delete removes the character UNDER the cursor. When the
      // cursor is at end-of-buffer there's nothing to delete; bundling it
      // with Backspace there would surprise mac users who lean on
      // fn+backspace (= Delete) at the end of a line.
      if (key.delete) {
        if (cursorOffset >= value.length) return;
        const next = value.slice(0, cursorOffset) + value.slice(cursorOffset + 1);
        emit(next, cursorOffset);
        return;
      }
      // Escape / pageUp / pageDown have no semantics in a single-line input;
      // swallow them so their raw bytes don't end up in the buffer.
      if (key.escape || key.pageUp || key.pageDown) {
        return;
      }
      if (input.length === 0) return;
      const printable = input.replace(CONTROL_CHARS_IN_PASTE, '');
      if (printable.length === 0) return;
      const next = value.slice(0, cursorOffset) + printable + value.slice(cursorOffset);
      emit(next, cursorOffset + printable.length);
    },
    { isActive: focus }
  );

  if (!focus) {
    return <Text>{value}</Text>;
  }
  const before = value.slice(0, cursorOffset);
  const under = value[cursorOffset];
  const after = under === undefined ? '' : value.slice(cursorOffset + 1);
  return (
    <Text>
      {before}
      <Text inverse>{under ?? ' '}</Text>
      {after}
    </Text>
  );
}

export function InputBar({
  value,
  onChange,
  onSubmit,
  onHistoryPrev,
  onHistoryNext,
  disabled = false,
  completion = null
}: {
  value: string;
  onChange: (next: string) => void;
  onSubmit: (text: string) => void;
  onHistoryPrev?: () => void;
  onHistoryNext?: () => void;
  disabled?: boolean;
  completion?: string | null;
}) {
  useInput(
    (_input, key) => {
      if (disabled) return;
      // Plain Tab completes; Shift+Tab is reserved for the App-level
      // policy-rotation handler and must not also trigger completion.
      if (key.tab && !key.shift && completion && completion !== value) {
        onChange(completion);
      }
    },
    { isActive: !disabled }
  );

  function handleSubmit(text: string) {
    const trimmed = text.trim();
    if (!trimmed) return;
    onSubmit(trimmed);
  }

  return (
    <Box>
      <Text color={disabled ? 'gray' : 'cyan'}>{disabled ? '… ' : '> '}</Text>
      {disabled ? (
        <Text dimColor>{value}</Text>
      ) : (
        <MiniTextInput
          value={value}
          onChange={onChange}
          onSubmit={handleSubmit}
          onHistoryPrev={onHistoryPrev}
          onHistoryNext={onHistoryNext}
        />
      )}
    </Box>
  );
}
