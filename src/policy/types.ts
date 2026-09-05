import type { ModelAction } from '../protocol/model/actions.js';
import type { ApprovalDecision, PolicySubject } from './decision.js';

export type { AccessChannel, AccessChannelKind, ApprovalDecision, PolicyConfirm, PolicyMode, ToolAccess } from './decision.js';

/** Only the retiring runner and its hooks carry the old action alongside policy intent. */
export type ApprovalSubject =
  | (Extract<PolicySubject, { kind: 'tool' }> & { action: ModelAction })
  | Exclude<PolicySubject, { kind: 'tool' }>;
export type ApprovalSubjectKind = ApprovalSubject['kind'];
export type ApprovalDecider = (subject: ApprovalSubject) => Promise<ApprovalDecision>;
