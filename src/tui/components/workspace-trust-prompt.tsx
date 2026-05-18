import { Box, Text, useInput, type Key } from 'ink';
import { useRef } from 'react';

export type WorkspaceTrustPromptProps = {
  workspaceRealPath: string;
  cwdLabel?: string;
  onDecided: (trusted: boolean) => void;
};

export function WorkspaceTrustPrompt({ workspaceRealPath, cwdLabel, onDecided }: WorkspaceTrustPromptProps) {
  const decidedRef = useRef(false);

  useInput((input: string, key: Key) => {
    if (decidedRef.current) {
      return;
    }
    if (input === 'y' || input === 'Y') {
      decidedRef.current = true;
      onDecided(true);
      return;
    }
    if (input === 'n' || input === 'N' || key.escape) {
      decidedRef.current = true;
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
        <Text>
          If you approve, Cliq loads project-level `.cliq/config` and may read or edit files under the workspace, or run
          repo-configured hooks, extension scripts, and validators. Target:
        </Text>
        <Text>{pathLine}</Text>
      </Box>
      <Box marginTop={1}>
        <Text dimColor>This is separate from `--policy`; tool approvals still apply after startup.</Text>
      </Box>
      <Box marginTop={1}>
        <Text color="green">[y]es trust workspace </Text>
        <Text color="red"> [n]o decline </Text>
        <Text dimColor> Esc declines</Text>
      </Box>
    </Box>
  );
}
