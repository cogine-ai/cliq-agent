import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';
import { useState } from 'react';

// ink-text-input forwards every byte ink sends it, so Ctrl combinations
// (Ctrl+O = \x0f, Ctrl+G = \x07, etc.) end up inserted into the buffer
// before the App-level keybinding handler can claim them. Filter at the
// onChange seam so these never reach the controlled value. Carriage return
// and tab are real input characters and are exempt.
const CONTROL_CHARS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;

function sanitizeInput(value: string): string {
  return value.replace(CONTROL_CHARS, '');
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
  // ink-text-input keeps its cursor in internal state initialized at mount
  // time. When we replace value externally (Tab completion), the cursor
  // sticks where it was — the user types and it lands mid-buffer. Force a
  // remount on each external rewrite so the cursor re-initializes to the
  // end of the new value.
  const [externalRev, setExternalRev] = useState(0);

  useInput(
    (_input, key) => {
      if (disabled) return;
      if (key.tab && completion && completion !== value) {
        onChange(completion);
        setExternalRev((r) => r + 1);
      }
    },
    { isActive: !disabled }
  );

  function handleChange(next: string) {
    const cleaned = sanitizeInput(next);
    if (cleaned !== value) onChange(cleaned);
  }

  function handleSubmit(text: string) {
    const trimmed = sanitizeInput(text).trim();
    if (!trimmed) return;
    onSubmit(trimmed);
  }

  return (
    <Box>
      <Text color={disabled ? 'gray' : 'cyan'}>{disabled ? '… ' : '> '}</Text>
      {disabled ? (
        <Text dimColor>{value}</Text>
      ) : (
        <TextInput
          key={externalRev}
          value={value}
          onChange={handleChange}
          onSubmit={handleSubmit}
        />
      )}
    </Box>
  );
}
