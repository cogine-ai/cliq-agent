import { Box, Text, useInput, type Key } from 'ink';

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
  focus = true
}: {
  value: string;
  onChange: (next: string) => void;
  onSubmit?: (text: string) => void;
  focus?: boolean;
}) {
  useInput(
    (input: string, key: Key) => {
      if (!focus) return;
      // App-level useKeybindings owns these. Returning here prevents the
      // letter component of a Ctrl combination (e.g. Ctrl+O → 'o') from
      // sneaking into the buffer.
      if (key.ctrl || key.meta) return;
      // Tab / Shift+Tab are reserved for slash completion and policy
      // rotation respectively — the parent's useInput claims both.
      if (key.tab) return;
      if (key.return) {
        onSubmit?.(value);
        return;
      }
      if (key.backspace || key.delete) {
        if (value.length === 0) return;
        onChange(value.slice(0, -1));
        return;
      }
      // No cursor / scrollback navigation yet. Ignore movement keys so they
      // don't accidentally insert their escape-sequence bytes.
      if (
        key.upArrow ||
        key.downArrow ||
        key.leftArrow ||
        key.rightArrow ||
        key.escape ||
        key.pageUp ||
        key.pageDown
      ) {
        return;
      }
      if (input.length === 0) return;
      const printable = input.replace(CONTROL_CHARS_IN_PASTE, '');
      if (printable.length === 0) return;
      onChange(value + printable);
    },
    { isActive: focus }
  );

  return (
    <Text>
      {value}
      {focus ? <Text inverse>{' '}</Text> : null}
    </Text>
  );
}

export function InputBar({
  value,
  onChange,
  onSubmit,
  disabled = false,
  completion = null
}: {
  value: string;
  onChange: (next: string) => void;
  onSubmit: (text: string) => void;
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
        <MiniTextInput value={value} onChange={onChange} onSubmit={handleSubmit} />
      )}
    </Box>
  );
}
