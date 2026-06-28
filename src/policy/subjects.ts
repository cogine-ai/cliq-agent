import type { ModelAction } from '../protocol/model/actions.js';
import type { TxReviewSnapshot } from '../workspace/transactions/inspect.js';
import {
  bashCommandHasUnsafeAllowSyntax,
  bashNestedBuiltinDenyHead,
  parseBashCommandHead
} from './bash-parse.js';
import type { AccessChannel, ApprovalSubject, ToolAccess } from './types.js';

type ToolApprovalDisplay = Extract<ApprovalSubject, { kind: 'tool' }>['display'];

const MAX_FALLBACK_DETAIL_LENGTH = 300;
const TRUNCATED_DETAIL_MARKER = '... (truncated)';

export function buildToolApprovalSubject(opts: {
  definition: { name: string; access: ToolAccess };
  action: ModelAction;
  tx?: { enabled: boolean; txId?: string; mode?: 'edit' };
}): ApprovalSubject {
  return {
    kind: 'tool',
    toolName: opts.definition.name,
    access: opts.definition.access,
    channel: deriveChannel(opts.definition, opts.action),
    action: opts.action,
    display: buildToolDisplay(opts.definition.name, opts.action, opts.tx?.enabled === true),
    ...(opts.tx ? { tx: opts.tx } : {})
  };
}

/**
 * Derive a fine-grained {@link AccessChannel} from the tool definition + the
 * model's action. The channel is the surface that the decision-table matcher
 * uses, so it MUST be deterministic for a given action shape — callers
 * (including the runner and headless path) all funnel through
 * {@link buildToolApprovalSubject} to keep this guarantee.
 *
 * TODO(no-issue: edit-op-detection): the edit tool currently always reports
 * `op: 'modify'` because we don't distinguish create/delete edits at the
 * action layer yet. When we add explicit create/delete edit actions, refine
 * this so rules like `fs-write:.git/**:delete` are expressible.
 */
function deriveChannel(
  definition: { name: string; access: ToolAccess },
  action: ModelAction
): AccessChannel {
  if ('bash' in action) {
    // parseBashCommandHead returns null for unidentifiable invocations
    // (leading operator, unterminated quote …). Surface that as an empty
    // string so the decision-table matcher treats it as "no head" and
    // falls through to ask/preset rather than guessing.
    const commandHead = parseBashCommandHead(action.bash) ?? '';
    const nestedBuiltinDenyHead = bashNestedBuiltinDenyHead(action.bash) ?? undefined;
    return {
      kind: 'bash',
      commandHead,
      unsafeForAllow: bashCommandHasUnsafeAllowSyntax(action.bash),
      ...(nestedBuiltinDenyHead ? { nestedBuiltinDenyHead } : {})
    };
  }

  if ('edit' in action) {
    return { kind: 'fs-write', path: action.edit.path, op: 'modify' };
  }

  if ('plan' in action) {
    return {
      kind: 'plan',
      op: action.plan.op,
      ...('planId' in action.plan && action.plan.planId ? { planId: action.plan.planId } : {})
    };
  }

  if ('todo' in action) {
    return {
      kind: 'plan-progress',
      ...(action.todo.planId ? { planId: action.todo.planId } : {})
    };
  }

  if ('mcp' in action) {
    return { kind: 'mcp', server: action.mcp.server, tool: action.mcp.tool };
  }

  const readPath = extractReadPath(action);
  if (readPath !== undefined) {
    return { kind: 'fs-read', path: readPath };
  }

  // Fallback: unknown action shape. Classify by the tool definition's
  // legacy access class so the decision table at least has a stable kind
  // to match on. Empty-string path means "no path known" — same convention
  // as bash above so allowlist matching falls through.
  if (definition.access === 'read') {
    return { kind: 'fs-read', path: '' };
  }
  return { kind: 'fs-write', path: '', op: 'modify' };
}

function extractReadPath(action: ModelAction): string | undefined {
  if ('read' in action) return action.read.path;
  if ('ls' in action) return action.ls.path ?? '';
  if ('find' in action) return action.find.path ?? '';
  if ('grep' in action) return action.grep.path ?? '';
  return undefined;
}

export function buildTxApplyApprovalSubject(snapshot: TxReviewSnapshot): ApprovalSubject {
  const diffSummary = snapshot.tx.diffSummary;
  if (!diffSummary) {
    throw new Error(`tx ${snapshot.tx.id} cannot build approval subject without diffSummary`);
  }
  return {
    kind: 'tx-apply',
    txId: snapshot.tx.id,
    diffSummary,
    validators: snapshot.tx.validators ?? [],
    blockingFailures: snapshot.tx.blockingFailures ?? [],
    artifactRef: snapshot.artifactRef
  };
}

function buildToolDisplay(
  toolName: string,
  action: ModelAction,
  txEnabled: boolean
): ToolApprovalDisplay {
  if ('bash' in action) {
    return {
      title: 'Allow bash command?',
      command: action.bash
    };
  }

  if ('edit' in action) {
    return {
      title: txEnabled ? 'Allow staged edit?' : 'Allow edit?',
      path: action.edit.path
    };
  }

  if ('plan' in action) {
    return {
      title: 'Record plan artifact?',
      detail: formatFallbackDetail(action)
    };
  }

  if ('todo' in action) {
    return {
      title: 'Update plan progress?',
      detail: formatFallbackDetail(action)
    };
  }

  if ('mcp' in action) {
    return {
      title: 'Allow MCP tool?',
      server: action.mcp.server,
      tool: action.mcp.tool,
      detail: formatFallbackDetail(action)
    };
  }

  return {
    title: `Allow ${toolName}?`,
    detail: formatFallbackDetail(action)
  };
}

function formatFallbackDetail(action: ModelAction): string {
  const detail = JSON.stringify(action);
  if (detail.length <= MAX_FALLBACK_DETAIL_LENGTH) return detail;
  const readablePrefix = detail.slice(0, MAX_FALLBACK_DETAIL_LENGTH - TRUNCATED_DETAIL_MARKER.length);
  return `${readablePrefix}${TRUNCATED_DETAIL_MARKER}`;
}
