import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';

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
      if (key.tab && completion && completion !== value) {
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
        <TextInput value={value} onChange={onChange} onSubmit={handleSubmit} />
      )}
    </Box>
  );
}
