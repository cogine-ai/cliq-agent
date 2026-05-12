import { Box, Text } from 'ink';

import type { TranscriptEntry } from '../store.js';

const TOOL_GLYPH = { running: '▸', ok: '✓', error: '✗' } as const;
const FOLDED_BODY_LINES = 20;

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
        <Box flexDirection="column">
          <Box>
            <Text color={color}>{glyph} </Text>
            <Text dimColor>tool: </Text>
            <Text>{entry.tool}</Text>
            {entry.summary ? (
              <>
                <Text dimColor>{' — '}</Text>
                <Text dimColor>{entry.summary}</Text>
              </>
            ) : null}
          </Box>
          {entry.body ? <ToolBody body={entry.body} expanded={entry.expanded === true} /> : null}
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

function ToolBody({ body, expanded }: { body: string; expanded: boolean }) {
  const lines = body.split('\n');
  const visible = expanded ? lines : lines.slice(0, FOLDED_BODY_LINES);
  const remaining = lines.length - visible.length;
  return (
    <Box flexDirection="column" marginLeft={2}>
      {visible.map((line, idx) => (
        // Body lines are indexed by position (no entry.id needed beyond row).
        // eslint-disable-next-line react/no-array-index-key
        <Text key={idx} dimColor>
          {line}
        </Text>
      ))}
      {remaining > 0 ? (
        <Text dimColor italic>
          {`… ${remaining} more line${remaining === 1 ? '' : 's'} (focus to expand — Stage 2.3)`}
        </Text>
      ) : null}
    </Box>
  );
}
