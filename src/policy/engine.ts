import {
  EMPTY_PERMISSION_TABLE,
  matchAgainstTable,
  type PermissionRule,
  type PermissionTable,
  type TableDecision
} from './decision-table.js';
import type { ApprovalDecision, ApprovalSubject, PolicyMode } from './types.js';

type PolicyEngineOptions = {
  mode: PolicyMode;
  /**
   * Optional decision table consulted before the legacy {@link PolicyMode}
   * preset. Defaults to {@link EMPTY_PERMISSION_TABLE}, in which case the
   * engine behaves exactly like the pre-#62-A implementation. The
   * deny/allow/ask matcher only applies to tool subjects with a
   * {@link AccessChannel}; tx-apply and permission-request subjects always
   * fall through to the preset.
   */
  table?: PermissionTable;
};

export function createPolicyEngine({ mode, table = EMPTY_PERMISSION_TABLE }: PolicyEngineOptions) {
  async function decide(subject: ApprovalSubject): Promise<ApprovalDecision> {
    if (subject.kind === 'permission-request') {
      return decidePermissionRequest(subject);
    }

    if (subject.kind === 'tool') {
      const tableDecision = matchAgainstTable(table, subject.channel);
      const resolved = applyTableDecision(tableDecision, subject);
      if (resolved) return resolved;
      // Fallthrough → continue to the legacy PolicyMode preset below.
    }

    if (mode === 'auto') {
      return { behavior: 'allow', decidedBy: 'policy' };
    }

    if (mode === 'read-only') {
      if (subject.kind === 'tx-apply') {
        return {
          behavior: 'deny',
          reason: 'policy mode read-only blocks transaction apply',
          decidedBy: 'policy'
        };
      }
      if (subject.access !== 'read') {
        return {
          behavior: 'deny',
          reason: `policy mode read-only blocks ${subject.access} tools`,
          decidedBy: 'policy'
        };
      }
      return { behavior: 'allow', decidedBy: 'policy' };
    }

    if (requiresConfirmation(subject)) {
      return {
        behavior: 'ask',
        prompt: formatApprovalPrompt(subject),
        decidedBy: 'policy'
      };
    }

    return { behavior: 'allow', decidedBy: 'policy' };
  }

  function applyTableDecision(
    tableDecision: TableDecision,
    subject: Extract<ApprovalSubject, { kind: 'tool' }>
  ): ApprovalDecision | undefined {
    switch (tableDecision.kind) {
      case 'deny':
        return {
          behavior: 'deny',
          reason: describeRule('deny', tableDecision.rule, subject),
          decidedBy: 'policy'
        };
      case 'allow':
        return {
          behavior: 'allow',
          reason: describeRule('allow', tableDecision.rule, subject),
          decidedBy: 'policy'
        };
      case 'ask':
        return {
          behavior: 'ask',
          prompt: formatApprovalPrompt(subject),
          decidedBy: 'policy'
        };
      case 'fallthrough':
        return undefined;
    }
  }

  function describeRule(
    kind: 'allow' | 'deny',
    rule: PermissionRule,
    subject: Extract<ApprovalSubject, { kind: 'tool' }>
  ): string {
    return `${kind} by ${rule.source} rule "${rule.channel}: ${rule.pattern}" (subject: ${subject.toolName})`;
  }

  function requiresConfirmation(subject: ApprovalSubject): boolean {
    if (mode === 'confirm-all') return true;

    if (subject.kind === 'tx-apply') {
      return mode === 'confirm-write';
    }

    if (subject.kind === 'tool') {
      return (
        (mode === 'confirm-write' && subject.access === 'write') ||
        (mode === 'confirm-bash' && subject.access === 'exec')
      );
    }

    return false;
  }

  function formatApprovalPrompt(subject: ApprovalSubject): string {
    const lines: string[] = [];

    if (subject.kind === 'tool') {
      lines.push(subject.display.title);
      lines.push(`tool: ${subject.toolName}`);
      lines.push(`access: ${subject.access}`);
      lines.push(`policy: ${mode}`);
      if (subject.display.path) lines.push(`path: ${subject.display.path}`);
      if (subject.display.command) lines.push(`command: ${subject.display.command}`);
      if (subject.tx?.txId) lines.push(`tx: ${subject.tx.txId}`);
      if (subject.display.detail) lines.push(`detail: ${subject.display.detail}`);
      return lines.join('\n');
    }

    if (subject.kind === 'tx-apply') {
      lines.push('Apply transaction?');
      lines.push(`tx: ${subject.txId}`);
      lines.push(
        `diff: ${subject.diffSummary.filesChanged} files changed (+${subject.diffSummary.additions}/-${subject.diffSummary.deletions})`
      );
      lines.push(`validators: ${subject.validators.length}`);
      lines.push(`blocking failures: ${subject.blockingFailures.length}`);
      lines.push(`artifact: ${subject.artifactRef}`);
      lines.push(`policy: ${mode}`);
      return lines.join('\n');
    }

    lines.push('Allow permission request?');
    lines.push(`source: ${subject.source}`);
    if (subject.toolName) lines.push(`tool: ${subject.toolName}`);
    lines.push(`reason: ${subject.reason}`);
    lines.push(`capabilities: ${subject.requestedCapabilities.join(', ') || 'none'}`);
    lines.push(`policy: ${mode}`);
    return lines.join('\n');
  }

  function decidePermissionRequest(subject: Extract<ApprovalSubject, { kind: 'permission-request' }>): ApprovalDecision {
    if (mode === 'auto') {
      return { behavior: 'allow', decidedBy: 'policy' };
    }
    if (mode === 'read-only') {
      return {
        behavior: 'deny',
        reason: 'policy mode read-only blocks permission requests',
        decidedBy: 'policy'
      };
    }
    return {
      behavior: 'ask',
      prompt: formatApprovalPrompt(subject),
      decidedBy: 'policy'
    };
  }

  return { mode, decide };
}
