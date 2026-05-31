import { Box, Text } from 'ink';

const CLIQ_LOGO = [
  '  CCCCC  L      III  QQQQ ',
  ' C       L       I  Q    Q',
  ' C       L       I  Q Q  Q',
  ' C       L       I  Q  Q Q',
  '  CCCCC  LLLLL  III  QQQQ '
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
