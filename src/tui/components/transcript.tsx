import { Box, Text } from 'ink';

import type { ActiveTurn, TranscriptEntry } from '../store.js';
import { Spinner } from './spinner.js';
import { TranscriptRow } from './transcript-row.js';

const MAX_VISIBLE_ENTRIES = 200;

export function Transcript({
  entries,
  activeTurn,
}: {
  entries: TranscriptEntry[];
  activeTurn: ActiveTurn | null;
}) {
  // Cap visible entries; older ones remain in shell scrollback (inline mode).
  const visible =
    entries.length > MAX_VISIBLE_ENTRIES ? entries.slice(-MAX_VISIBLE_ENTRIES) : entries;

  if (visible.length === 0 && !activeTurn) {
    return <EmptyState />;
  }

  return (
    <Box flexDirection="column">
      {visible.map((entry) => (
        <TranscriptRow key={entry.id} entry={entry} />
      ))}
      {activeTurn ? (
        <Box>
          <Spinner />
          <Text dimColor>{` thinking… ${activeTurn.modelChars} chars`}</Text>
        </Box>
      ) : null}
    </Box>
  );
}

function EmptyState() {
  return (
    <Box flexDirection="column" marginBottom={1}>
      <Text bold color="cyan">
        Welcome to cliq.
      </Text>
      <Text dimColor>Type a prompt below, or try a slash command.</Text>
      <Text dimColor>
        {'  '}
        <Text bold>/help</Text>
        {' lists commands · '}
        <Text bold>Ctrl+D</Text>
        {' exits · '}
        <Text bold>Ctrl+C</Text>
        {' cancels a turn or clears input'}
      </Text>
    </Box>
  );
}
