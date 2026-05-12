import { Box, Text } from 'ink';

import { matchSlash } from '../slash.js';

export function SlashPalette({ query }: { query: string }) {
  const matches = matchSlash(query);
  if (matches.length === 0) return null;

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="gray" paddingX={1}>
      {matches.map((cmd) => (
        <Box key={cmd.name}>
          <Text color="cyan">{cmd.name}</Text>
          {cmd.args ? <Text dimColor>{` ${cmd.args}`}</Text> : null}
          <Text dimColor>{`  — ${cmd.description}`}</Text>
        </Box>
      ))}
      <Text dimColor italic>{matches.length === 1 ? 'tab to complete' : 'keep typing or tab to complete'}</Text>
    </Box>
  );
}
