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
 * Scope of a permission decision returned by a PermissionRequest hook. v0
 * defines the wire shape but only `'once'` has any runtime effect; `'session'`
 * and `'workspace'` are accepted from the hook so authors can start emitting
 * the field, but the runner intentionally treats them as `'once'` until the
 * session/workspace allowlist persistence lands in #62-B.
 *
 * Defaulting unspecified scopes to `'once'` preserves byte-for-byte behavior
 * for hooks that haven't been updated.
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
     * TODO(#62-B): wire `'session'` (in-process allowlist) and `'workspace'`
     * (persisted to ~/.cliq/workspaces/<id>/permissions.json) end-to-end
     * once the user-visible allowlist surface lands.
     */
    scope?: HookPermissionScope;
  };
  /**
   * Optional additional allowlist entries that the hook wants to append to
   * the current session's in-process permission table. Each entry uses the
   * same "<channel>: <pattern>" grammar as the CLI/workspace config in
   * #62-B. Type-only today; the runner ignores it and surfaces a single
   * warning so hook authors can start adopting the field.
   *
   * TODO(#62-B): consume these entries via composePermissionTable session
   * layer when the persistence + CLI surface lands.
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
