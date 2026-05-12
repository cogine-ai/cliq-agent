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
