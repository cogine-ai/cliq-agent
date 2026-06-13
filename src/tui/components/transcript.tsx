import { Box, Text } from 'ink';
import { useEffect, useRef, useState } from 'react';

import type { ActiveTurn, TranscriptEntry } from '../store.js';
import { estimateOutputTokensFromChars, formatApproxOutputTokens } from '../token-estimate.js';
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
    return null;
  }

  return (
    <Box flexDirection="column">
      {visible.map((entry) => (
        <TranscriptRow key={entry.id} entry={entry} />
      ))}
      {activeTurn ? <ActiveTurnRow activeTurn={activeTurn} /> : null}
    </Box>
  );
}

function ActiveTurnRow({ activeTurn }: { activeTurn: ActiveTurn }) {
  const startedAt = useRef(Date.now());
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const tokenLabel = formatApproxOutputTokens(estimateOutputTokensFromChars(activeTurn.modelChars));

  useEffect(() => {
    const update = () => {
      setElapsedSeconds(Math.floor((Date.now() - startedAt.current) / 1000));
    };
    update();
    const id = setInterval(update, 1000);
    id.unref?.();
    return () => {
      clearInterval(id);
    };
  }, []);

  return (
    <Box>
      <Spinner />
      <Text dimColor>{` thinking… ${elapsedSeconds}s${tokenLabel ? ` · ${tokenLabel}` : ''}`}</Text>
    </Box>
  );
}
