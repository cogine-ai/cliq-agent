import type { ModelAction } from '../protocol/model/actions.js';
import type { TxReviewSnapshot } from '../workspace/transactions/inspect.js';
import type { ApprovalSubject, ToolAccess } from './types.js';

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
    action: opts.action,
    display: buildToolDisplay(opts.definition.name, opts.action, opts.tx?.enabled === true),
    ...(opts.tx ? { tx: opts.tx } : {})
  };
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
