import { Box, Text } from 'ink';

const CLIQ_LOGO = [
  '   ____ _     ___ ___  ',
  '  / ___| |   |_ _/ _ \\ ',
  ' | |   | |    | | | | |',
  ' | |___| |___ | | |_| |',
  '  \\____|_____|___\\__\\_\\'
];

export function TuiHeader() {
  return (
    <Box flexDirection="column" marginBottom={1} width="100%" alignItems="center">
      {CLIQ_LOGO.map((line) => (
        <Text key={line} bold color="cyan">
          {line}
        </Text>
      ))}
    </Box>
  );
}
