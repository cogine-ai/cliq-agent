import path from 'node:path';

import { Box, Text } from 'ink';

import type { UiState } from '../store.js';

export function StatusBar({ state }: { state: UiState }) {
  const segments = [
    `${state.model.provider}/${state.model.model}`,
    state.policy,
    shortSessionId(state.session.id),
    `/${path.basename(state.session.cwd)}`,
    formatTxStatus(state.tx)
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

function formatTxStatus(tx: UiState['tx']): string {
  if (!tx) return 'tx idle';
  return `tx ${shortTxId(tx.txId)} ${tx.state}`;
}

function shortTxId(id: string): string {
  // tx_abc123def... → tx_abc123 for compactness in the status bar
  if (id.length <= 9) return id;
  return id.slice(0, 9);
}

function shortSessionId(id: string): string {
  // Session ids look like "ses_abc123def456…"; show "ses_abc123" for compactness.
  if (id.length <= 10) return id;
  return id.slice(0, 10);
}
