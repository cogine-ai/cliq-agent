import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession, workspaceIdFromRealPath } from '../session/store.js';
import {
  approvePlan,
  cancelPlan,
  createDraftPlan,
  finalizePlan,
  readPlanArtifact,
  rejectPlan,
  resolvePlanStorageRef,
  updatePlan
} from './store.js';

const originalCliqHome = process.env.CLIQ_HOME;
const cleanupDirs: string[] = [];

test.after(async () => {
  if (originalCliqHome === undefined) {
    delete process.env.CLIQ_HOME;
  } else {
    process.env.CLIQ_HOME = originalCliqHome;
  }
  await Promise.all(cleanupDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function tempScope() {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-plan-ws-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-plan-home-'));
  cleanupDirs.push(cwd, home);
  process.env.CLIQ_HOME = home;
  return { cwd, home, session: createSession(cwd) };
}

test('plan artifacts live under ~/.cliq/plans/<workspace>/<session> and update session refs', async () => {
  const { cwd, home, session } = await tempScope();

  const draft = await createDraftPlan(cwd, session, {
    title: 'Implement plan workflow',
    contentMarkdown: '## Steps\n- Draft'
  });
  const ref = await resolvePlanStorageRef(cwd, session, home);
  const expectedWorkspaceId = workspaceIdFromRealPath(await import('node:fs/promises').then(({ realpath }) => realpath(cwd)));

  assert.equal(ref.workspaceId, expectedWorkspaceId);
  assert.equal(draft.workspaceId, expectedWorkspaceId);
  assert.equal(draft.sessionId, session.id);
  assert.equal(draft.status, 'draft');
  assert.equal(session.activePlanId, draft.id);
  assert.equal(session.approvedPlanId, undefined);
  assert.equal(draft.paths.json.startsWith(path.join(home, 'plans', expectedWorkspaceId, session.id)), true);

  const raw = JSON.parse(await readFile(draft.paths.json, 'utf8')) as { id: string; contentMarkdown: string };
  assert.equal(raw.id, draft.id);
  assert.equal(raw.contentMarkdown, '## Steps\n- Draft');
});

test('update resets finalized plans to draft and finalize marks them ready for review', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Original',
    contentMarkdown: '## One'
  });

  const finalized = await finalizePlan(cwd, session, { planId: draft.id });
  assert.equal(finalized.status, 'finalized');
  assert.equal(session.activePlanId, draft.id);

  const updated = await updatePlan(cwd, session, {
    planId: draft.id,
    title: 'Revised',
    contentMarkdown: '## Two'
  });
  assert.equal(updated.status, 'draft');
  assert.equal(updated.title, 'Revised');
  assert.equal(updated.finalizedAt, undefined);

  const refinalized = await finalizePlan(cwd, session);
  assert.equal(refinalized.status, 'finalized');
  assert.equal(refinalized.contentMarkdown, '## Two');
});

test('approval, rejection, and cancellation persist status and session references', async () => {
  const approvedScope = await tempScope();
  const approvedDraft = await createDraftPlan(approvedScope.cwd, approvedScope.session, {
    title: 'Approve me',
    contentMarkdown: '## Plan'
  });
  await finalizePlan(approvedScope.cwd, approvedScope.session);
  const approved = await approvePlan(approvedScope.cwd, approvedScope.session, {
    planId: approvedDraft.id,
    targetMode: 'accept-edits'
  });
  assert.equal(approved.status, 'approved');
  assert.equal(approved.approvedTargetMode, 'accept-edits');
  assert.equal(approvedScope.session.approvedPlanId, approvedDraft.id);
  assert.equal(approvedScope.session.activePlanId, undefined);

  const rejectedScope = await tempScope();
  const rejectedDraft = await createDraftPlan(rejectedScope.cwd, rejectedScope.session, {
    title: 'Reject me',
    contentMarkdown: '## Plan'
  });
  await finalizePlan(rejectedScope.cwd, rejectedScope.session);
  const rejected = await rejectPlan(rejectedScope.cwd, rejectedScope.session, rejectedDraft.id);
  assert.equal(rejected.status, 'rejected');
  assert.equal(rejectedScope.session.activePlanId, undefined);

  const canceledScope = await tempScope();
  const canceledDraft = await createDraftPlan(canceledScope.cwd, canceledScope.session, {
    title: 'Cancel me',
    contentMarkdown: '## Plan'
  });
  await finalizePlan(canceledScope.cwd, canceledScope.session);
  const canceled = await cancelPlan(canceledScope.cwd, canceledScope.session, canceledDraft.id);
  assert.equal(canceled.status, 'canceled');
  assert.equal(canceledScope.session.activePlanId, undefined);
});

test('readPlanArtifact rejects non-active arbitrary ids through update/finalize guards', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Only plan',
    contentMarkdown: '## Plan'
  });

  await assert.rejects(() => updatePlan(cwd, session, { planId: 'plan_other', contentMarkdown: 'x' }), /not the active plan/);
  await assert.rejects(() => finalizePlan(cwd, session, { planId: 'plan_other' }), /not the active plan/);

  const loaded = await readPlanArtifact(cwd, session, draft.id);
  assert.equal(loaded.id, draft.id);
});
