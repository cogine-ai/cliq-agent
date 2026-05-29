import path from 'node:path';

import { Box, Text } from 'ink';

import { getModeColor } from '../mode-language.js';
import type { UiState } from '../store.js';

export function StatusBar({ state, hint = null }: { state: UiState; hint?: string | null }) {
  const policyColor = getModeColor(state.policy);
  const txStatus = formatTxStatus(state.tx);
  const sessionId = shortSessionId(state.session.id);
  const cwdLabel = `/${path.basename(state.session.cwd)}`;
  const tokensLabel = state.sessionTokens !== null ? `${formatTokens(state.sessionTokens)} tok` : null;
  const detailLabel = [
    `${state.model.provider}/${state.model.model}`,
    sessionId,
    cwdLabel,
    txStatus,
    tokensLabel
  ]
    .filter((part): part is string => part !== null)
    .join(' · ');
  const hasError = state.errors.length > 0;

  return (
    <Box width="100%" height={1} overflow="hidden">
      <Box flexShrink={0}>
        {hasError ? <Text color="red">● </Text> : null}
        <Text color={policyColor} bold={state.policy === 'yolo'}>
          {formatModeForFooter(state.policy)}
        </Text>
      </Box>
      {hint ? (
        <Box flexShrink={1} overflow="hidden">
          <Sep />
          <Text dimColor wrap="truncate">
            {hint}
          </Text>
        </Box>
      ) : null}
      <Box flexShrink={1} overflow="hidden" marginLeft={1}>
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

function Sep() {
  return <Text dimColor>{' · '}</Text>;
}

function formatTxStatus(tx: UiState['tx']): string {
  if (!tx) return 'tx idle';
  return `tx ${shortTxId(tx.txId)} ${tx.state}`;
}

function formatModeForFooter(policy: UiState['policy']): string {
  switch (policy) {
    case 'default':
      return 'default mode';
    case 'accept-edits':
      return 'accept edits on';
    case 'plan':
      return 'plan mode';
    case 'yolo':
      return 'bypass permissions on';
    default: {
      const _exhaustive: never = policy;
      return _exhaustive;
    }
  }
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
