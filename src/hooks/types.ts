import type { ApprovalSubject } from '../policy/types.js';
import type { ModelAction } from '../protocol/model/actions.js';
import type { ToolResult } from '../tools/types.js';
import type { DiffSummary, ValidatorResultSummary } from '../workspace/transactions/types.js';

export type HookEventName =
  | 'SessionStart'
  | 'UserPromptSubmit'
  | 'PreToolUse'
  | 'PostToolUse'
  | 'PermissionRequest'
  | 'TxFinalized'
  | 'TxValidated'
  | 'TxApplyReview'
  | 'Stop';

export type HookCommandConfig = {
  type: 'command';
  command: string;
  timeoutMs?: number;
  statusMessage?: string;
  required?: boolean;
};

export type HookMatcherConfig = {
  matcher?: string;
  hooks: HookCommandConfig[];
};

export type HooksConfig = Partial<Record<HookEventName, HookMatcherConfig[]>>;

export type HookInput = {
  schemaVersion: 1;
  hookEventName: HookEventName;
  sessionId: string;
  cwd: string;
  turnId?: string;
  model?: string;
  prompt?: string;
  finalMessage?: string;
  toolName?: string;
  toolUseId?: string;
  matcherAliases?: string[];
  action?: ModelAction;
  toolResult?: ToolResult & { _truncated?: true };
  approvalSubject?: ApprovalSubject;
  tx?: {
    txId: string;
    state?: string;
    diffSummary?: DiffSummary | { _truncated: true; preview?: string };
    validators?: ValidatorResultSummary[] | { _truncated: true; preview?: string };
    blockingFailures?: string[];
    artifactRef?: string;
  };
};

/**
 * Scope of a permission decision returned by a PermissionRequest hook.
 * Accepted on the wire for forward compatibility; the runner currently treats
 * every hook allow as one-shot. Session/workspace persistence is wired through
 * the TUI approval modal (`extendApprovalScope` in cli.ts), not hook scope.
 */
export type HookPermissionScope = 'once' | 'session' | 'workspace';

export type HookOutput = {
  continue?: boolean;
  decision?: 'allow' | 'deny';
  reason?: string;
  systemMessage?: string;
  additionalContext?: string;
  permissionDecision?: {
    behavior: 'allow' | 'deny';
    message?: string;
    /** Optional scope. Ignored by the runner today; reserved for forward compatibility. */
    scope?: HookPermissionScope;
  };
  [key: string]: unknown;
};

export type HookDecision = {
  behavior: 'allow' | 'deny';
  reason?: string;
};

export type HookRunResult =
  | {
      status: 'ok';
      command: string;
      output: HookOutput | null;
      stdout: string;
      stderr: string;
      exitCode: 0;
      timedOut: false;
    }
  | {
      status: 'denied';
      command: string;
      decision: HookDecision;
      output?: HookOutput | null;
      stdout: string;
      stderr: string;
      exitCode: number | null;
      timedOut: false;
    }
  | {
      status: 'error';
      command: string;
      error: string;
      stdout: string;
      stderr: string;
      exitCode: number | null;
      timedOut: boolean;
    };
