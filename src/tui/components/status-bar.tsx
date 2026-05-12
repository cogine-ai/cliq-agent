import path from 'node:path';

import { Box, Text } from 'ink';

import type { UiState } from '../store.js';

export function StatusBar({ state }: { state: UiState }) {
  const segments = [
    `${state.model.provider}/${state.model.model}`,
    state.policy,
    shortSessionId(state.session.id),
    `/${path.basename(state.session.cwd)}`,
    'tx idle',
  ];
  const hasError = state.errors.length > 0;
  return (
    <Box>
      {hasError ? (
        <>
          <Text color="red">● </Text>
        </>
      ) : null}
      <Text dimColor>{segments.join(' · ')}</Text>
    </Box>
  );
}

function shortSessionId(id: string): string {
  // Session ids look like "ses_abc123def456…"; show "ses_abc123" for compactness.
  if (id.length <= 10) return id;
  return id.slice(0, 10);
}
