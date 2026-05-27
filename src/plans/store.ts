import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { withPathLock } from '../lib/path-lock.js';
import type { PolicyMode } from '../policy/types.js';
import { makeId, mutateSession, nowIso, resolveCliqHome, workspaceIdFromRealPath } from '../session/store.js';
import type { Session } from '../session/types.js';
import type { PlanArtifact, PlanStatus, PlanTargetMode } from './types.js';

const SAFE_ID = /^[A-Za-z0-9_-]+$/;
const PLAN_FILE = 'plan.json';

export type PlanStorageRef = {
  workspaceId: string;
  workspaceRealPath: string;
  sessionDir: string;
};

export type DraftPlanInput = {
  title: string;
  contentMarkdown: string;
};

export type UpdatePlanInput = {
  planId?: string;
  title?: string;
  contentMarkdown: string;
};

export type FinalizePlanInput = {
  planId?: string;
};

export type ApprovePlanInput = {
  planId: string;
  targetMode: PlanTargetMode;
};

function assertSafeId(kind: string, id: string) {
  if (!SAFE_ID.test(id)) {
    throw new Error(`invalid ${kind} id: ${id}`);
  }
}

function assertNonEmpty(value: string, label: string) {
  if (!value.trim()) {
    throw new Error(`${label} cannot be empty`);
  }
}

function isTargetMode(value: PolicyMode): value is PlanTargetMode {
  return value === 'default' || value === 'accept-edits' || value === 'yolo';
}

export function assertPlanTargetMode(value: PolicyMode): asserts value is PlanTargetMode {
  if (!isTargetMode(value)) {
    throw new Error(`plan approval target mode must be default, accept-edits, or yolo (got ${value})`);
  }
}

export async function resolvePlanStorageRef(
  cwd: string,
  session: Pick<Session, 'id'>,
  cliqHome = resolveCliqHome()
): Promise<PlanStorageRef> {
  assertSafeId('session', session.id);
  const workspaceRealPath = await fs.realpath(cwd);
  const workspaceId = workspaceIdFromRealPath(workspaceRealPath);
  return {
    workspaceId,
    workspaceRealPath,
    sessionDir: path.join(cliqHome, 'plans', workspaceId, session.id)
  };
}

export async function planArtifactPath(
  cwd: string,
  session: Pick<Session, 'id'>,
  planId: string,
  cliqHome = resolveCliqHome()
) {
  assertSafeId('plan', planId);
  const ref = await resolvePlanStorageRef(cwd, session, cliqHome);
  return path.join(ref.sessionDir, planId, PLAN_FILE);
}

async function atomicWriteJson(target: string, value: unknown) {
  await fs.mkdir(path.dirname(target), { recursive: true });
  const temp = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  try {
    await fs.writeFile(temp, JSON.stringify(value, null, 2), 'utf8');
    await fs.rename(temp, target);
  } catch (error) {
    await fs.rm(temp, { force: true });
    throw error;
  }
}

function isPlanStatus(value: unknown): value is PlanStatus {
  return value === 'draft' || value === 'finalized' || value === 'approved' || value === 'rejected' || value === 'canceled';
}

function isPlanArtifact(value: unknown): value is PlanArtifact {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const raw = value as Partial<PlanArtifact> & { paths?: unknown };
  const paths = raw.paths as { json?: unknown } | undefined;
  return (
    typeof raw.id === 'string' &&
    typeof raw.sessionId === 'string' &&
    typeof raw.workspaceId === 'string' &&
    isPlanStatus(raw.status) &&
    typeof raw.title === 'string' &&
    typeof raw.contentMarkdown === 'string' &&
    typeof raw.createdAt === 'string' &&
    typeof raw.updatedAt === 'string' &&
    (raw.finalizedAt === undefined || typeof raw.finalizedAt === 'string') &&
    (raw.approvedAt === undefined || typeof raw.approvedAt === 'string') &&
    (raw.rejectedAt === undefined || typeof raw.rejectedAt === 'string') &&
    (raw.canceledAt === undefined || typeof raw.canceledAt === 'string') &&
    (raw.approvedTargetMode === undefined || isTargetMode(raw.approvedTargetMode as PolicyMode)) &&
    !!paths &&
    typeof paths === 'object' &&
    typeof paths.json === 'string'
  );
}

async function readJson(target: string): Promise<unknown> {
  return JSON.parse(await fs.readFile(target, 'utf8')) as unknown;
}

async function writePlanArtifact(artifact: PlanArtifact) {
  await withPathLock(artifact.paths.json, async () => {
    await atomicWriteJson(artifact.paths.json, artifact);
  });
}

export async function readPlanArtifact(
  cwd: string,
  session: Pick<Session, 'id'>,
  planId: string,
  cliqHome = resolveCliqHome()
): Promise<PlanArtifact> {
  const target = await planArtifactPath(cwd, session, planId, cliqHome);
  const ref = await resolvePlanStorageRef(cwd, session, cliqHome);
  const raw = await readJson(target);
  if (!isPlanArtifact(raw)) {
    throw new Error(`invalid plan artifact: ${target}`);
  }
  if (raw.id !== planId || raw.sessionId !== session.id || raw.workspaceId !== ref.workspaceId) {
    throw new Error(`mismatched plan artifact: ${target}`);
  }
  if (raw.paths.json !== target) {
    throw new Error(`plan artifact path mismatch: ${target}`);
  }
  return { ...raw, paths: { json: target } };
}

export async function readReferencedPlanArtifact(
  cwd: string,
  session: Session,
  planId: string
): Promise<PlanArtifact | null> {
  if (session.activePlanId !== planId && session.approvedPlanId !== planId) {
    return null;
  }
  try {
    return await readPlanArtifact(cwd, session, planId);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

export async function createDraftPlan(
  cwd: string,
  session: Session,
  input: DraftPlanInput
): Promise<PlanArtifact> {
  assertNonEmpty(input.title, 'plan title');
  assertNonEmpty(input.contentMarkdown, 'plan content');
  const ref = await resolvePlanStorageRef(cwd, session);
  const id = makeId('plan');
  const now = nowIso();
  const jsonPath = path.join(ref.sessionDir, id, PLAN_FILE);
  const artifact: PlanArtifact = {
    id,
    sessionId: session.id,
    workspaceId: ref.workspaceId,
    status: 'draft',
    title: input.title.trim(),
    contentMarkdown: input.contentMarkdown.trim(),
    createdAt: now,
    updatedAt: now,
    paths: { json: jsonPath }
  };

  await writePlanArtifact(artifact);
  await mutateSession(cwd, session, (current) => {
    current.activePlanId = artifact.id;
    delete current.approvedPlanId;
  });
  return artifact;
}

function planIdForActiveSession(session: Session, planId?: string) {
  const resolved = planId ?? session.activePlanId;
  if (!resolved) {
    throw new Error('no active plan is available');
  }
  if (session.activePlanId !== resolved) {
    throw new Error(`plan ${resolved} is not the active plan for this session`);
  }
  return resolved;
}

export async function updatePlan(
  cwd: string,
  session: Session,
  input: UpdatePlanInput
): Promise<PlanArtifact> {
  assertNonEmpty(input.contentMarkdown, 'plan content');
  const planId = planIdForActiveSession(session, input.planId);
  const current = await readPlanArtifact(cwd, session, planId);
  if (current.status === 'approved' || current.status === 'rejected' || current.status === 'canceled') {
    throw new Error(`cannot update a ${current.status} plan`);
  }
  if (input.title !== undefined) {
    assertNonEmpty(input.title, 'plan title');
  }

  const { finalizedAt: _finalizedAt, approvedAt: _approvedAt, rejectedAt: _rejectedAt, canceledAt: _canceledAt, approvedTargetMode: _approvedTargetMode, ...base } = current;
  const next: PlanArtifact = {
    ...base,
    status: 'draft',
    title: input.title?.trim() ?? current.title,
    contentMarkdown: input.contentMarkdown.trim(),
    updatedAt: nowIso()
  };

  await writePlanArtifact(next);
  await mutateSession(cwd, session, (mutating) => {
    mutating.activePlanId = next.id;
    delete mutating.approvedPlanId;
  });
  return next;
}

export async function finalizePlan(
  cwd: string,
  session: Session,
  input: FinalizePlanInput = {}
): Promise<PlanArtifact> {
  const planId = planIdForActiveSession(session, input.planId);
  const current = await readPlanArtifact(cwd, session, planId);
  if (current.status !== 'draft' && current.status !== 'finalized') {
    throw new Error(`cannot finalize a ${current.status} plan`);
  }
  const now = nowIso();
  const next: PlanArtifact = {
    ...current,
    status: 'finalized',
    finalizedAt: current.finalizedAt ?? now,
    updatedAt: now
  };

  await writePlanArtifact(next);
  await mutateSession(cwd, session, (mutating) => {
    mutating.activePlanId = next.id;
    delete mutating.approvedPlanId;
  });
  return next;
}

async function markReviewedPlan(
  cwd: string,
  session: Session,
  planId: string,
  status: Extract<PlanStatus, 'approved' | 'rejected' | 'canceled'>,
  targetMode?: PlanTargetMode
): Promise<PlanArtifact> {
  const current = await readPlanArtifact(cwd, session, planId);
  if (current.status !== 'finalized') {
    throw new Error(`plan ${planId} must be finalized before it can be ${status}`);
  }
  const now = nowIso();
  const next: PlanArtifact = {
    ...current,
    status,
    updatedAt: now,
    ...(status === 'approved' ? { approvedAt: now, approvedTargetMode: targetMode } : {}),
    ...(status === 'rejected' ? { rejectedAt: now } : {}),
    ...(status === 'canceled' ? { canceledAt: now } : {})
  };

  await writePlanArtifact(next);
  await mutateSession(cwd, session, (mutating) => {
    if (status === 'approved') {
      mutating.approvedPlanId = next.id;
    } else if (mutating.approvedPlanId === next.id) {
      delete mutating.approvedPlanId;
    }
    if (mutating.activePlanId === next.id) {
      delete mutating.activePlanId;
    }
  });
  return next;
}

export async function approvePlan(
  cwd: string,
  session: Session,
  input: ApprovePlanInput
): Promise<PlanArtifact> {
  assertPlanTargetMode(input.targetMode);
  return await markReviewedPlan(cwd, session, input.planId, 'approved', input.targetMode);
}

export async function rejectPlan(cwd: string, session: Session, planId: string): Promise<PlanArtifact> {
  return await markReviewedPlan(cwd, session, planId, 'rejected');
}

export async function cancelPlan(cwd: string, session: Session, planId: string): Promise<PlanArtifact> {
  return await markReviewedPlan(cwd, session, planId, 'canceled');
}
