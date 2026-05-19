import path from 'node:path';

import { Box, Text } from 'ink';

import { getPolicyModeDisplay } from '../policy-display.js';
import type { UiState } from '../store.js';

export function StatusBar({ state }: { state: UiState }) {
  const policyDisplay = getPolicyModeDisplay(state.policy);
  const txStatus = formatTxStatus(state.tx);
  const sessionId = shortSessionId(state.session.id);
  const cwdLabel = `/${path.basename(state.session.cwd)}`;
  const tokensLabel = state.sessionTokens !== null ? `${formatTokens(state.sessionTokens)} tok` : null;
  const hasError = state.errors.length > 0;

  return (
    <Box>
      {hasError ? <Text color="red">● </Text> : null}
      <Text dimColor>{`${state.model.provider}/${state.model.model}`}</Text>
      <Sep />
      <Text color={policyDisplay.color}>{policyDisplay.label}</Text>
      <Sep />
      <Text dimColor>{sessionId}</Text>
      <Sep />
      <Text dimColor>{cwdLabel}</Text>
      <Sep />
      <Text dimColor>{txStatus}</Text>
      {tokensLabel !== null ? (
        <>
          <Sep />
          <Text dimColor>{tokensLabel}</Text>
        </>
      ) : null}
    </Box>
  );
}

function Sep() {
  return <Text dimColor>{' · '}</Text>;
}

function formatTxStatus(tx: UiState['tx']): string {
  if (!tx) return 'tx idle';
  return `tx ${shortTxId(tx.txId)} ${tx.state}`;
}

function shortSessionId(id: string): string {
  // Session ids look like "ses_abc123def456…"; show "ses_abc123" for compactness.
  if (id.length <= 10) return id;
  return id.slice(0, 10);
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
