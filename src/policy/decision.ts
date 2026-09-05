import type { DiffSummary, ValidatorResultSummary } from '../workspace/transactions/types.js';

export type PolicyMode = 'default' | 'accept-edits' | 'plan' | 'yolo';

export type ToolAccess = 'read' | 'write' | 'exec' | 'plan';

/**
 * Fine-grained "what is the model actually trying to do?" classification used by
 * the policy decision table (see {@link AccessChannel} matchers in
 * `src/policy/decision-table.ts`). This is intentionally orthogonal to
 * {@link ToolAccess}: `access` selects the PolicyMode preset, while `channel` is the surface that
 * allow/deny/ask rules match against.
 *
 * Channels are open-ended on purpose so we can land MCP and network runtime
 * execution later without re-shaping the subject type.
 *
 * The subject describes intent, not an execution grant or OS containment.
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
  | {
      kind: 'bash';
      commandHead: string;
      /**
       * True when syntax after the head can execute additional shell code and
       * therefore must not be auto-approved by a bash allow rule.
       */
      unsafeForAllow: boolean;
      /**
       * When a nested shell inline script (`bash -c`, etc.) resolves to a
       * builtin-deny head such as `rm`, surface it here so deny rules apply
       * even though the outer command head differs (e.g. `bash -c "rm …"`).
       */
      nestedBuiltinDenyHead?: string;
    }
  | { kind: 'mcp'; server: string; tool: string }
  | { kind: 'network'; host?: string }
  | { kind: 'plan'; op: 'draft' | 'update' | 'finalize'; planId?: string }
  | { kind: 'plan-progress'; planId?: string };

export type AccessChannelKind = AccessChannel['kind'];

export type PolicyConfirm = (prompt: string) => Promise<boolean>;

export type PolicySubject =
  | {
      kind: 'tool';
      toolName: string;
      access: ToolAccess;
      /**
       * Fine-grained channel for the decision-table matcher, derived from the
       * same normalized input as display and execution intent.
       */
      channel: AccessChannel;
      display: {
        title: string;
        detail?: string;
        path?: string;
        command?: string;
        server?: string;
        tool?: string;
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

export type ApprovalDecision =
  | { behavior: 'allow'; reason?: string; decidedBy: 'policy' | 'user' | 'hook' }
  | { behavior: 'deny'; reason: string; decidedBy: 'policy' | 'user' | 'hook' }
  | { behavior: 'ask'; prompt: string; decidedBy: 'policy' | 'hook' };
