import { Box, Text } from 'ink';

import type { TranscriptEntry } from '../store.js';
import { formatApproxOutputTokens } from '../token-estimate.js';

const TOOL_GLYPH = { running: '▸', ok: '✓', error: '✗' } as const;
const TOOL_BODY_FOLD_BUCKET = 8;
const MAX_FOLDED_BODY_LINES = 4;
const USER_MESSAGE_BACKGROUND = 'blackBright';

export function TranscriptRow({ entry }: { entry: TranscriptEntry }) {
  switch (entry.kind) {
    case 'user':
      return <UserMessageBlock text={entry.text} />;
    case 'assistant': {
      const outputTokens = formatApproxOutputTokens(entry.outputTokenEstimate ?? 0);
      return (
        <Box flexDirection="column">
          <Text>{entry.text}</Text>
          {outputTokens ? <Text dimColor>{outputTokens}</Text> : null}
        </Box>
      );
    }
    case 'tool': {
      const glyph = TOOL_GLYPH[entry.status];
      const color = entry.status === 'error' ? 'red' : entry.status === 'ok' ? 'green' : 'yellow';
      return (
        <Box flexDirection="column">
          <Box width="100%" overflow="hidden">
            <Text color={color}>{glyph} </Text>
            <Text dimColor>tool: </Text>
            <Text>{entry.tool}</Text>
            {entry.summary ? (
              <>
                <Text dimColor>{' — '}</Text>
                <Text dimColor wrap="truncate">
                  {entry.summary}
                </Text>
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

function UserMessageBlock({ text }: { text: string }) {
  const lines = text.replace(/\n+$/, '').split('\n');
  return (
    <Box flexDirection="column" marginTop={1} marginBottom={1} backgroundColor={USER_MESSAGE_BACKGROUND}>
      {lines.map((line, idx) => (
        <Box key={`line-${idx}`} backgroundColor={USER_MESSAGE_BACKGROUND} paddingX={1}>
          <Text backgroundColor={USER_MESSAGE_BACKGROUND}>{line.length > 0 ? line : ' '}</Text>
        </Box>
      ))}
    </Box>
  );
}

function ToolBody({ body, expanded }: { body: string; expanded: boolean }) {
  // Bash output usually ends with a trailing newline; without trimming it the
  // split produces a phantom empty line that inflates the "N more lines" count
  // and renders a blank row when expanded.
  const lines = body.replace(/\n+$/, '').split('\n');
  const visibleLimit = expanded ? lines.length : foldedBodyLineLimit(lines.length);
  const visible = lines.slice(0, visibleLimit);
  const remaining = lines.length - visible.length;
  return (
    <Box flexDirection="column" marginLeft={2} overflow="hidden">
      {visible.map((line, idx) => (
        // Body lines are indexed by position (no entry.id needed beyond row).
        // eslint-disable-next-line react/no-array-index-key
        <Text key={idx} dimColor wrap="truncate">
          {line}
        </Text>
      ))}
      {remaining > 0 ? (
        <Text dimColor italic>
          {`… ${remaining} more line${remaining === 1 ? '' : 's'} (Ctrl+O to expand)`}
        </Text>
      ) : null}
    </Box>
  );
}

function foldedBodyLineLimit(totalLines: number): number {
  if (totalLines <= 1) return totalLines;
  return Math.min(MAX_FOLDED_BODY_LINES, Math.max(1, Math.ceil(totalLines / TOOL_BODY_FOLD_BUCKET)));
}
