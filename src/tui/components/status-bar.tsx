import path from 'node:path';

import { Box, Text } from 'ink';

import { formatModeForStatus, getModeColor } from '../mode-language.js';
import type { UiState } from '../store.js';

export function StatusBar({ state }: { state: UiState }) {
  const policyColor = getModeColor(state.policy);
  const txStatus = formatTxStatus(state.tx);
  const sessionId = shortSessionId(state.session.id);
  const cwdLabel = `/${path.basename(state.session.cwd)}`;
  const tokensLabel = state.sessionTokens !== null ? `${formatTokens(state.sessionTokens)} tok` : null;
  const hasError = state.errors.length > 0;
  const interactionHint = formatInteractionHint(state);

  return (
    <Box width="100%" justifyContent="space-between">
      <Box>
        {hasError ? <Text color="red">● </Text> : null}
        <Text dimColor>{`${state.model.provider}/${state.model.model}`}</Text>
        <Sep />
        <Text color={policyColor}>{formatModeForStatus(state.policy)}</Text>
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
      <Box>
        {interactionHint ? <Text color={state.pendingApproval ? 'yellow' : 'cyan'}>{interactionHint}</Text> : null}
        {interactionHint && state.versionUpdate ? <Text dimColor>{' · '}</Text> : null}
        {state.versionUpdate ? <Text color="yellow">{`update ${state.versionUpdate.latest}`}</Text> : null}
      </Box>
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

function formatInteractionHint(state: UiState): string | null {
  if (state.pendingApproval) {
    return state.pendingApproval.subject.kind === 'tool'
      ? 'approval: y/n/a/s/W · Ctrl+C cancel'
      : 'approval: y/n/Esc · Ctrl+C cancel';
  }
  if (state.activeTurn) {
    return 'running: Ctrl+C cancel';
  }
  return null;
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
