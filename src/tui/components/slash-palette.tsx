import { Box, Text } from 'ink';

import { matchSlash } from '../slash.js';
import { semanticStyle, semanticTextProps } from '../semantic-styles.js';

export function SlashPalette({ query }: { query: string }) {
  const matches = matchSlash(query);
  if (matches.length === 0) return null;
  const showDetails = matches.length === 1;

  return (
    <Box flexDirection="column" borderStyle="round" borderColor={semanticStyle('muted').color} paddingX={1}>
      {matches.map((cmd) => (
        <Box key={cmd.name} flexDirection="column">
          <Box>
            <Text {...semanticTextProps('info')}>{`i ${cmd.name}`}</Text>
            {cmd.args ? <Text {...semanticTextProps('muted')}>{` ${cmd.args}`}</Text> : null}
            <Text {...semanticTextProps('muted')}>{`  — ${cmd.description}`}</Text>
          </Box>
          {showDetails
            ? cmd.details?.map((detail) => (
                <Box key={detail} marginLeft={2}>
                  <Text {...semanticTextProps('muted')}>{detail}</Text>
                </Box>
              ))
            : null}
        </Box>
      ))}
      <Text {...semanticTextProps('muted')} italic>
        {matches.length === 1 ? 'tab to complete' : 'keep typing or tab to complete'}
      </Text>
    </Box>
  );
}
