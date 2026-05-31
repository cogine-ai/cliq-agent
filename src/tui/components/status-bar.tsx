import path from 'node:path';

import { Box, Text } from 'ink';

import type { UiState } from '../store.js';

export function TopStatusBar({ hint = null }: { hint?: string | null }) {
  if (!hint) return null;
  return (
    <Box width="100%" height={1} overflow="hidden">
      <Text dimColor wrap="truncate">
        {hint}
      </Text>
    </Box>
  );
}

export function BottomStatusBar({ state }: { state: UiState }) {
  const txStatus = formatTxStatus(state.tx);
  const cwdLabel = `/${path.basename(state.session.cwd)}`;
  const tokensLabel = state.sessionTokens !== null ? `${formatTokens(state.sessionTokens)} tok` : null;
  const detailLabel = [cwdLabel, txStatus, tokensLabel]
    .filter((part): part is string => part !== null)
    .join(' · ');
  const hasError = state.errors.length > 0;

  return (
    <Box width="100%" height={1} overflow="hidden">
      {hasError ? (
        <Box flexShrink={0}>
          <Text color="red">● </Text>
        </Box>
      ) : null}
      <Box flexShrink={1} overflow="hidden">
        <Text dimColor wrap="truncate">
          {detailLabel}
        </Text>
      </Box>
      {state.versionUpdate ? (
        <Box flexShrink={0} marginLeft={1}>
          <Text dimColor>{'· '}</Text>
          <Text color="yellow">{`update ${state.versionUpdate.latest}`}</Text>
        </Box>
      ) : null}
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

function formatTokens(tokens: number): string {
  if (tokens < 1000) return String(tokens);
  return `${(tokens / 1000).toFixed(1)}k`;
}
