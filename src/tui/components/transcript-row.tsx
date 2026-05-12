import { Box, Text } from 'ink';

import type { TranscriptEntry } from '../store.js';

const TOOL_GLYPH = { running: '▸', ok: '✓', error: '✗' } as const;

export function TranscriptRow({ entry }: { entry: TranscriptEntry }) {
  switch (entry.kind) {
    case 'user':
      return (
        <Box>
          <Text color="cyan" bold>
            {'> '}
          </Text>
          <Text>{entry.text}</Text>
        </Box>
      );
    case 'assistant':
      return (
        <Box>
          <Text>{entry.text}</Text>
        </Box>
      );
    case 'tool': {
      const glyph = TOOL_GLYPH[entry.status];
      const color = entry.status === 'error' ? 'red' : entry.status === 'ok' ? 'green' : 'yellow';
      return (
        <Box>
          <Text color={color}>{glyph} </Text>
          <Text dimColor>tool: </Text>
          <Text>{entry.tool}</Text>
          {entry.preview ? (
            <>
              <Text dimColor>{' — '}</Text>
              <Text dimColor>{entry.preview}</Text>
            </>
          ) : null}
        </Box>
      );
    }
    case 'system':
      return (
        <Box>
          <Text dimColor italic>
            {entry.text}
          </Text>
        </Box>
      );
    default: {
      const _exhaustive: never = entry;
      return _exhaustive;
    }
  }
}
