import type { PolicyMode } from '../policy/types.js';

export type PlanStatus = 'draft' | 'finalized' | 'approved' | 'rejected' | 'canceled';

export type PlanTargetMode = Exclude<PolicyMode, 'plan'>;

export type PlanItemStatus = 'pending' | 'in_progress' | 'completed';

export type PlanItem = {
  id: string;
  title: string;
  status: PlanItemStatus;
  notes?: string;
};

export type PlanItemInput = {
  id?: string;
  title: string;
  status?: PlanItemStatus;
  notes?: string;
};

export type PlanArtifact = {
  id: string;
  sessionId: string;
  workspaceId: string;
  status: PlanStatus;
  title: string;
  contentMarkdown: string;
  items: PlanItem[];
  createdAt: string;
  updatedAt: string;
  finalizedAt?: string;
  approvedAt?: string;
  rejectedAt?: string;
  canceledAt?: string;
  approvedTargetMode?: PlanTargetMode;
  paths: {
    json: string;
    markdown: string;
  };
};

export type PlanReviewSnapshot = {
  id: string;
  title: string;
  contentMarkdown: string;
  items: PlanItem[];
  path: string;
  markdownPath: string;
};
