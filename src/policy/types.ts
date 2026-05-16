import type { ModelAction } from '../protocol/model/actions.js';
import type { DiffSummary, ValidatorResultSummary } from '../workspace/transactions/types.js';

export type PolicyMode = 'auto' | 'confirm-write' | 'read-only' | 'confirm-bash' | 'confirm-all';

export type ToolAccess = 'read' | 'write' | 'exec';

/**
 * Fine-grained "what is the model actually trying to do?" classification used by
 * the policy decision table (see {@link AccessChannel} matchers in
 * `src/policy/decision-table.ts`). This is intentionally orthogonal to
 * {@link ToolAccess}: `access` keeps the legacy read/write/exec trichotomy that
 * the existing PolicyMode preset relies on, while `channel` is the surface that
 * allow/deny/ask rules match against.
 *
 * Channels are open-ended on purpose so we can land MCP and network later
 * without re-shaping the subject type.
 *
 * TODO(no-issue: MCP runtime): `mcp` channel is wired through the type system
 * but no MCP server runtime exists in tree as of #62-A. When MCP lands, build
 * subjects with `channel: { kind: 'mcp', server, tool }` from the MCP call
 * site and register default deny rules for unknown servers in
 * `src/policy/decision-table.ts` BUILTIN_DENY.
 *
 * TODO(#63): `network` channel only records the model's stated intent here.
 * Real enforcement (DNS allowlist, egress firewall, sandbox netns) is the
 * responsibility of the OS sandbox layer tracked in #63. Until then the
 * `host` field is best-effort and a missing host MUST NOT be treated as
 * "no network access".
 */
export type AccessChannel =
  | { kind: 'fs-read'; path: string }
  | { kind: 'fs-write'; path: string; op: 'create' | 'modify' | 'delete' }
  | { kind: 'bash'; commandHead: string }
  | { kind: 'mcp'; server: string; tool: string }
  | { kind: 'network'; host?: string };

export type AccessChannelKind = AccessChannel['kind'];

export type PolicyConfirm = (prompt: string) => Promise<boolean>;

export type ApprovalSubject =
  | {
      kind: 'tool';
      toolName: string;
      access: ToolAccess;
      /**
       * Fine-grained channel for the decision-table matcher. Always present
       * on tool subjects; legacy `access` is retained for the PolicyMode
       * preset and for backward compatibility with hooks that read it.
       */
      channel: AccessChannel;
      action: ModelAction;
      display: {
        title: string;
        detail?: string;
        path?: string;
        command?: string;
      };
      tx?: {
        enabled: boolean;
        txId?: string;
        mode?: 'edit';
      };
    }
  | {
      kind: 'tx-apply';
      txId: string;
      diffSummary: DiffSummary;
      validators: ValidatorResultSummary[];
      blockingFailures: string[];
      artifactRef: string;
    }
  | {
      kind: 'permission-request';
      source: 'hook' | 'tool' | 'runtime';
      toolName?: string;
      reason: string;
      requestedCapabilities: string[];
    };

export type ApprovalSubjectKind = ApprovalSubject['kind'];

export type ApprovalDecision =
  | { behavior: 'allow'; reason?: string; decidedBy: 'policy' | 'user' | 'hook' }
  | { behavior: 'deny'; reason: string; decidedBy: 'policy' | 'user' | 'hook' }
  | { behavior: 'ask'; prompt: string; decidedBy: 'policy' | 'hook' };

export type ApprovalDecider = (subject: ApprovalSubject) => Promise<ApprovalDecision>;
