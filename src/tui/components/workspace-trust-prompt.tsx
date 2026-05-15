import { Box, Text, useInput, type Key } from 'ink';

export type WorkspaceTrustPromptProps = {
  workspaceRealPath: string;
  cwdLabel?: string;
  onDecided: (trusted: boolean) => void;
};

export function WorkspaceTrustPrompt({ workspaceRealPath, cwdLabel, onDecided }: WorkspaceTrustPromptProps) {
  useInput((input: string, key: Key) => {
    if (input === 'y' || input === 'Y') {
      onDecided(true);
      return;
    }
    if (input === 'n' || input === 'N' || key.escape) {
      onDecided(false);
      return;
    }
  });

  const pathLine =
    cwdLabel && cwdLabel !== workspaceRealPath
      ? `${cwdLabel}\ncanonical: ${workspaceRealPath}`
      : workspaceRealPath;

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="yellow" paddingX={1}>
      <Text color="yellow" bold>
        Trusted workspace gate
      </Text>
      <Box flexDirection="column" marginTop={1}>
        <Text>Cliq is about to load project-level `.cliq/config` (hooks, extensions, validators) under:</Text>
        <Text>{pathLine}</Text>
      </Box>
      <Box marginTop={1}>
        <Text dimColor>
          This is separate from `--policy`; tool approvals still apply after startup.
        </Text>
      </Box>
      <Box marginTop={1}>
        <Text color="green">[y]es trust workspace </Text>
        <Text color="red"> [n]o decline </Text>
        <Text dimColor> Esc declines</Text>
      </Box>
    </Box>
  );
}
