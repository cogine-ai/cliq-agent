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
          If you approve, Cliq loads project-level `.cliq/config`, repo-configured hooks, extension scripts,
          validators, instructions, and skills for this workspace. Target:
        </Text>
        <Text>{pathLine}</Text>
      </Box>
      <Box marginTop={1}>
        <Text dimColor>
          This does not approve file edits, shell commands, MCP, or network access; `--policy` and tool approvals still
          decide runtime actions.
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
