import { Text } from 'ink';

const DEFAULT_WIDTH = 80;
const MAX_WIDTH = 240;

export function Divider({ width, color }: { width?: number; color?: string }) {
  const effectiveWidth = Math.max(
    1,
    Math.min(width ?? process.stdout.columns ?? DEFAULT_WIDTH, MAX_WIDTH)
  );

  return (
    <Text color={color} dimColor={!color}>
      {'─'.repeat(effectiveWidth)}
    </Text>
  );
}
