import { Box, Text, useInput, type Key } from 'ink';
import { useEffect, useRef, useState } from 'react';

import type { ApprovalSubject, PolicyMode } from '../../policy/types.js';
import {
  semanticStyle,
  semanticTextProps,
  type SemanticTone
} from '../semantic-styles.js';
import type { UiApprovalDecision } from '../store.js';

export type ApprovalModalProps = {
  subject: ApprovalSubject;
  policy: PolicyMode;
  activationKey?: string;
  onDecide: (decision: UiApprovalDecision) => void;
};

export function ApprovalModal({ subject, policy, activationKey, onDecide }: ApprovalModalProps) {
  const isTool = subject.kind === 'tool';
  const tone = approvalTone(subject);
  const style = semanticStyle(tone);
  const isActiveRef = useRef(false);
  const [isActive, setIsActive] = useState(false);

  useEffect(() => {
    isActiveRef.current = false;
    setIsActive(false);
    const handle = setImmediate(() => {
      isActiveRef.current = true;
      setIsActive(true);
    });
    return () => {
      clearImmediate(handle);
      isActiveRef.current = false;
    };
  }, [activationKey]);

  // Capital W is intentional for "allow-workspace" — it persists to
  // ~/.cliq/workspaces/<id>/permissions.json and survives the cliq
  // invocation, so the shift requirement adds an extra deliberate keystroke
  // beyond the lowercase per-session and per-turn options. Other modal keys
  // (`y`, `n`, `a`, `s`) are accepted in both cases.
  useInput(
    (input: string, key: Key) => {
      if (!isActiveRef.current) return;
      if (input === 'y' || input === 'Y') {
        onDecide('allow');
        return;
      }
      if (input === 'n' || input === 'N' || key.escape) {
        onDecide('deny');
        return;
      }
      // 'allow-for-this-turn' is a tool-approval sugar; spec A.6 does not apply
      // it to tx-apply prompts (those are end-of-turn, no "remaining tools"
      // bucket to short-circuit). Same constraint applies to allow-session
      // and allow-workspace — those need a channel to derive a rule against.
      if (!isTool) {
        if (input === 'a' || input === 'A') {
          // Tx-apply / permission-request modals don't have an "allow turn"
          // bucket. Silently ignore.
        }
        return;
      }
      if (input === 'a' || input === 'A') {
        onDecide('allow-turn');
        return;
      }
      if (input === 's' || input === 'S') {
        onDecide('allow-session');
        return;
      }
      if (input === 'W') {
        onDecide('allow-workspace');
      }
    }
  );

  return (
    <Box flexDirection="column" borderStyle="round" borderColor={style.color} paddingX={1}>
      <Text {...semanticTextProps(tone)} bold>
        {`${style.marker} Approval required`}
      </Text>
      <RiskNotice subject={subject} tone={tone} />
      {subject.kind === 'tool' ? (
        <ToolBody subject={subject} policy={policy} />
      ) : subject.kind === 'tx-apply' ? (
        <TxApplyBody subject={subject} policy={policy} />
      ) : (
        <PermissionBody subject={subject} policy={policy} />
      )}
      <Hotkeys allowTurn={isTool} allowScopes={isTool} />
      {!isActive ? (
        <Text {...semanticTextProps('warning')}>… Waiting for approval input</Text>
      ) : null}
    </Box>
  );
}

function ToolBody({
  subject,
  policy
}: {
  subject: Extract<ApprovalSubject, { kind: 'tool' }>;
  policy: PolicyMode;
}) {
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text>{subject.display.title}</Text>
      <Field label="tool" value={subject.toolName} />
      <Field label="access" value={subject.access} />
      {subject.display.server ? <Field label="server" value={subject.display.server} /> : null}
      {subject.display.tool ? <Field label="mcp tool" value={subject.display.tool} /> : null}
      {subject.display.path ? <Field label="path" value={subject.display.path} /> : null}
      {subject.display.command ? (
        <Field label="command" value={subject.display.command} />
      ) : null}
      {subject.tx?.txId ? <Field label="tx" value={subject.tx.txId} /> : null}
      {subject.display.detail ? (
        <Field label="detail" value={subject.display.detail} />
      ) : null}
      <Field label="policy" value={policy} />
    </Box>
  );
}

function TxApplyBody({
  subject,
  policy
}: {
  subject: Extract<ApprovalSubject, { kind: 'tx-apply' }>;
  policy: PolicyMode;
}) {
  const d = subject.diffSummary;
  const blocking = subject.validators.filter((v) => v.severity === 'blocking');
  const advisory = subject.validators.filter((v) => v.severity === 'advisory');
  const blockingPass = blocking.filter((v) => v.status === 'pass').length;
  const advisoryPass = advisory.filter((v) => v.status === 'pass').length;
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text>{`Apply transaction ${subject.txId}?`}</Text>
      <Field label="files" value={`${d.filesChanged} changed (+${d.additions}/-${d.deletions})`} />
      <Field
        label="validators"
        value={`blocking ${blockingPass}/${blocking.length}, advisory ${advisoryPass}/${advisory.length}`}
      />
      {subject.blockingFailures.length > 0 ? (
        <Field
          label="blocking failures"
          value={subject.blockingFailures.join(', ')}
          warn
        />
      ) : null}
      <Field label="artifact" value={subject.artifactRef} />
      <Field label="policy" value={policy} />
    </Box>
  );
}

function PermissionBody({
  subject,
  policy
}: {
  subject: Extract<ApprovalSubject, { kind: 'permission-request' }>;
  policy: PolicyMode;
}) {
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text>Allow permission request?</Text>
      <Field label="source" value={subject.source} />
      {subject.toolName ? <Field label="tool" value={subject.toolName} /> : null}
      <Field label="reason" value={subject.reason} />
      <Field
        label="capabilities"
        value={subject.requestedCapabilities.join(', ') || 'none'}
      />
      <Field label="policy" value={policy} />
    </Box>
  );
}

function Field({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <Box>
      <Text {...semanticTextProps('muted')}>{`  ${label}: `}</Text>
      <Text {...(warn ? semanticTextProps('error') : {})}>
        {warn ? `${semanticStyle('error').marker} ${value}` : value}
      </Text>
    </Box>
  );
}

function approvalTone(subject: ApprovalSubject): SemanticTone {
  if (subject.kind === 'tool' && (subject.access === 'exec' || subject.channel.kind === 'bash')) {
    return 'danger';
  }
  if (subject.kind === 'tx-apply' && subject.blockingFailures.length > 0) return 'danger';
  return 'warning';
}

function RiskNotice({ subject, tone }: { subject: ApprovalSubject; tone: SemanticTone }) {
  const message =
    subject.kind === 'tool'
      ? subject.access === 'exec'
        ? 'Risk: command execution'
        : subject.access === 'write'
          ? 'Risk: workspace modification'
          : `Review: ${subject.access} access`
      : subject.kind === 'tx-apply'
        ? subject.blockingFailures.length > 0
          ? `Risk: ${subject.blockingFailures.length} blocking validator failure${subject.blockingFailures.length === 1 ? '' : 's'}`
          : `Review: apply ${subject.diffSummary.filesChanged} changed file${subject.diffSummary.filesChanged === 1 ? '' : 's'}`
        : 'Risk: additional capabilities requested';
  return (
    <Text {...semanticTextProps(tone)}>
      {`${semanticStyle(tone).marker} ${message}`}
    </Text>
  );
}

function Hotkeys({ allowTurn, allowScopes }: { allowTurn: boolean; allowScopes: boolean }) {
  // Layout intentionally walks "once → turn → session → workspace". The
  // persistent workspace choice is explicitly dangerous rather than muted.
  return (
    <Box marginTop={1}>
      <Text {...semanticTextProps('success')}>✓ [y]es allow </Text>
      <Text {...semanticTextProps('error')}> ✗ [n]o deny </Text>
      {allowTurn ? <Text {...semanticTextProps('info')}> i [a]llow this turn </Text> : null}
      {allowScopes ? (
        <>
          <Text {...semanticTextProps('info')}> i [s]ession </Text>
          <Text {...semanticTextProps('danger')}> ! [W]orkspace (persistent) </Text>
        </>
      ) : null}
      <Text {...semanticTextProps('error')}> ✗ Esc=deny</Text>
    </Box>
  );
}
