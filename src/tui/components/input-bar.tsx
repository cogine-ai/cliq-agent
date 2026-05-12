import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';
import { useState } from 'react';

export function InputBar({
  onSubmit,
  disabled = false,
}: {
  onSubmit: (text: string) => void;
  disabled?: boolean;
}) {
  const [value, setValue] = useState('');

  function handleSubmit(text: string) {
    const trimmed = text.trim();
    if (!trimmed) return;
    setValue('');
    onSubmit(trimmed);
  }

  return (
    <Box>
      <Text color={disabled ? 'gray' : 'cyan'}>{disabled ? '… ' : '> '}</Text>
      {disabled ? (
        <Text dimColor>{value}</Text>
      ) : (
        <TextInput value={value} onChange={setValue} onSubmit={handleSubmit} />
      )}
    </Box>
  );
}
