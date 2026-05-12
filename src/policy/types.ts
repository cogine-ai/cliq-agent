import type { ModelAction } from '../protocol/model/actions.js';
import type { DiffSummary, ValidatorResultSummary } from '../workspace/transactions/types.js';

export type PolicyMode = 'auto' | 'confirm-write' | 'read-only' | 'confirm-bash' | 'confirm-all';

export type ToolAccess = 'read' | 'write' | 'exec';

export type PolicyConfirm = (prompt: string) => Promise<boolean>;

export type ApprovalSubject =
  | {
      kind: 'tool';
      toolName: string;
      access: ToolAccess;
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
