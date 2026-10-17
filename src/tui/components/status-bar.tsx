import path from 'node:path';

import { Box, Text } from 'ink';

import type { UiState } from '../store.js';
import {
  semanticStyle,
  semanticTextProps,
  type SemanticTone
} from '../semantic-styles.js';

export function TopStatusBar({
  hint = null,
  tone = 'muted'
}: {
  hint?: string | null;
  tone?: SemanticTone;
}) {
  if (!hint) return null;
  const style = semanticStyle(tone);
  return (
    <Box width="100%" height={1} overflow="hidden">
      <Text {...semanticTextProps(tone)} wrap="truncate">
        {`${style.marker} ${hint}`}
      </Text>
    </Box>
  );
}

export function BottomStatusBar({ state }: { state: UiState }) {
  const txStatus = formatTxStatus(state.tx);
  const cwdLabel = formatCwdLabel(state.session.cwd);
  const tokensLabel = state.sessionTokens !== null ? `session ${formatTokens(state.sessionTokens)} tok` : null;
  const hasError = state.errors.length > 0;

  return (
    <Box width="100%" height={1} overflow="hidden">
      {hasError ? (
        <Box flexShrink={0}>
          <Text {...semanticTextProps('error')}>{`${semanticStyle('error').marker} error `}</Text>
        </Box>
      ) : null}
      <Box flexShrink={1} minWidth={0} overflow="hidden">
        <Text {...semanticTextProps('muted')} wrap="truncate">
          {cwdLabel}
        </Text>
      </Box>
      <StatusSegment label={txStatus} tone={txTone(state.tx)} />
      {tokensLabel ? <StatusSegment label={tokensLabel} /> : null}
      {state.versionUpdate ? (
        <Box flexShrink={0} marginLeft={1}>
          <Text {...semanticTextProps('warning')}>
            {`${semanticStyle('warning').marker} update ${state.versionUpdate.latest}`}
          </Text>
        </Box>
      ) : null}
    </Box>
  );
}

function StatusSegment({ label, tone = 'muted' }: { label: string; tone?: SemanticTone }) {
  const style = semanticStyle(tone);
  return (
    <Box flexShrink={0} marginLeft={1}>
      <Text {...semanticTextProps(tone)}>{`${style.marker} ${label}`}</Text>
    </Box>
  );
}

function txTone(tx: UiState['tx']): SemanticTone {
  if (!tx) return 'muted';
  if (tx.state === 'staging') return 'active';
  if (tx.state === 'finalized') return 'info';
  return 'success';
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

function formatCwdLabel(cwd: string): string {
  const resolved = path.resolve(cwd);
  return resolved === path.parse(resolved).root ? resolved : resolved.replace(/\/+$/, '');
}

function formatTokens(tokens: number): string {
  if (tokens < 1000) return String(tokens);
  return `${(tokens / 1000).toFixed(1)}k`;
}
