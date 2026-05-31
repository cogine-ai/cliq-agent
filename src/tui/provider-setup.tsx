import { Box, render, Text, useApp, useInput } from 'ink';

import { formatModelSetupMessage, type ModelSetupRequiredError } from '../model/config.js';

export type ProviderSetupProps = {
  error: ModelSetupRequiredError;
};

export function ProviderSetup({ error }: ProviderSetupProps) {
  const { exit } = useApp();
  const lines = formatModelSetupMessage(error).split('\n');

  useInput((input, key) => {
    if (input === 'q' || key.return || key.escape || (key.ctrl && (input === 'c' || input === 'd'))) {
      exit();
    }
  });

  return (
    <Box flexDirection="column">
      {lines.map((line, index) => (
        <Text key={`${index}:${line}`}>{line}</Text>
      ))}
      <Text>Press Enter or q to exit.</Text>
    </Box>
  );
}

export async function mountProviderSetupAndWait(error: ModelSetupRequiredError) {
  const instance = render(<ProviderSetup error={error} />, { exitOnCtrlC: false });
  await instance.waitUntilExit();
}
