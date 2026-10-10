import { Box, Text } from 'ink';

import type { PolicyMode } from '../../policy/types.js';
import { describePolicyMode, formatModeForComposer, getModeColor } from '../mode-language.js';

const CLIQ_LOGO = [
  '   ____ _     ___ ___  ',
  '  / ___| |   |_ _/ _ \\ ',
  ' | |   | |    | | | | |',
  ' | |___| |___ | | |_| |',
  '  \\____|_____|___\\__\\_\\'
];

export function TuiHeader({ policy = 'default' }: { policy?: PolicyMode }) {
  const mode = describePolicyMode(policy);
  return (
    <Box flexDirection="column" marginBottom={1} width="100%" alignItems="center">
      {CLIQ_LOGO.map((line) => (
        <Text key={line} bold color="cyan">
          {line}
        </Text>
      ))}
      <Text color={getModeColor(policy)} bold={mode.risk === 'danger'}>
        {`${formatModeForComposer(policy)} · ${mode.risk} risk`}
      </Text>
    </Box>
  );
}
