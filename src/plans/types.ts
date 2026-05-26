import type { PolicyMode } from '../policy/types.js';

export type PlanStatus = 'draft' | 'finalized' | 'approved' | 'rejected' | 'canceled';

export type PlanTargetMode = Exclude<PolicyMode, 'plan'>;

export type PlanArtifact = {
  id: string;
  sessionId: string;
  workspaceId: string;
  status: PlanStatus;
  title: string;
  contentMarkdown: string;
  createdAt: string;
  updatedAt: string;
  finalizedAt?: string;
  approvedAt?: string;
  rejectedAt?: string;
  canceledAt?: string;
  approvedTargetMode?: PlanTargetMode;
  paths: {
    json: string;
  };
};

export type PlanReviewSnapshot = {
  id: string;
  title: string;
  contentMarkdown: string;
  path: string;
};
