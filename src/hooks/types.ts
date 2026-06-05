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
 * Interactive TUI runs wire `'session'` and `'workspace'` through the same
 * `extendApprovalScope` path as the approval modal. Headless / one-shot runs
 * omit the runner callback, so those scopes still behave as `'once'`.
 *
 * Defaulting unspecified scopes to `'once'` preserves behavior for hooks that
 * have not been updated.
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
    /**
     * Optional scope. Missing → `'once'`. Unknown / non-string values are
     * also coerced to `'once'` rather than rejected, to keep the hook
     * surface forward-compatible: an older runner reading a newer hook's
     * `'forever'`-style scope will fall back to one-shot instead of crashing.
     *
     * `'session'` extends the in-process table; `'workspace'` also persists
     * to ~/.cliq/workspaces/<id>/permissions.json when the runner provides
     * `extendHookAllow` (interactive TUI only).
     */
    scope?: HookPermissionScope;
  };
  /**
   * Optional additional allowlist entries that the hook wants to append to
   * the current session's in-process permission table. Each entry uses the
   * same "<channel>: <pattern>" grammar as the CLI/workspace config in
   * **Not wired yet**: the runner ignores this field today so hook authors
   * can adopt the wire shape ahead of consumption.
   */
  additionalAllowlistEntries?: string[];
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
