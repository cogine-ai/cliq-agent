import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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
  assert.equal(draft.paths.markdown.endsWith(path.join(draft.id, 'plan.md')), true);
  assert.deepEqual(draft.items, [{ id: 'item_1', title: 'Draft', status: 'pending' }]);

  const raw = JSON.parse(await readFile(draft.paths.json, 'utf8')) as { id: string; contentMarkdown: string; items: unknown[] };
  assert.equal(raw.id, draft.id);
  assert.equal(raw.contentMarkdown, '## Steps\n- Draft');
  assert.deepEqual(raw.items, [{ id: 'item_1', title: 'Draft', status: 'pending' }]);
  assert.equal(await readFile(draft.paths.markdown, 'utf8'), '## Steps\n- Draft');
});

test('plan artifacts accept explicit items and editable markdown updates content and items', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Editable plan',
    contentMarkdown: '## Steps\n- Inspect',
    items: [
      { id: 'inspect', title: 'Inspect current code', status: 'completed' },
      { title: 'Implement follow-up', notes: 'after review' }
    ]
  });

  assert.deepEqual(draft.items, [
    { id: 'inspect', title: 'Inspect current code', status: 'completed' },
    { id: 'item_2', title: 'Implement follow-up', status: 'pending', notes: 'after review' }
  ]);

  await writeFile(draft.paths.markdown, '## Edited\n- [~] Update plan review\n- [ ] Run tests\n', 'utf8');
  const edited = await readPlanArtifact(cwd, session, draft.id);

  assert.equal(edited.contentMarkdown, '## Edited\n- [~] Update plan review\n- [ ] Run tests');
  assert.deepEqual(edited.items, [
    { id: 'item_1', title: 'Update plan review', status: 'in_progress' },
    { id: 'item_2', title: 'Run tests', status: 'pending' }
  ]);
});

test('finalized and approved plan artifacts freeze reviewed content despite later markdown edits', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Freeze reviewed plan',
    contentMarkdown: '## Steps\n- Reviewed'
  });

  const finalized = await finalizePlan(cwd, session, { planId: draft.id });
  await writeFile(finalized.paths.markdown, '## Tampered\n- Changed before approval', 'utf8');

  const rereadFinalized = await readPlanArtifact(cwd, session, draft.id);
  assert.equal(rereadFinalized.status, 'finalized');
  assert.equal(rereadFinalized.contentMarkdown, '## Steps\n- Reviewed');
  assert.deepEqual(rereadFinalized.items, [{ id: 'item_1', title: 'Reviewed', status: 'pending' }]);

  const approved = await approvePlan(cwd, session, { planId: draft.id, targetMode: 'accept-edits' });
  assert.equal(approved.contentMarkdown, '## Steps\n- Reviewed');
  assert.deepEqual(approved.items, [{ id: 'item_1', title: 'Reviewed', status: 'pending' }]);

  await writeFile(approved.paths.markdown, '## Tampered\n- Changed after approval', 'utf8');
  const rereadApproved = await readPlanArtifact(cwd, session, draft.id);
  assert.equal(rereadApproved.status, 'approved');
  assert.equal(rereadApproved.contentMarkdown, '## Steps\n- Reviewed');
  assert.deepEqual(rereadApproved.items, [{ id: 'item_1', title: 'Reviewed', status: 'pending' }]);
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

test('approvePlan rejects non-approval policy modes as target mode', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Invalid approval mode',
    contentMarkdown: '## Plan'
  });
  await finalizePlan(cwd, session, { planId: draft.id });

  await assert.rejects(
    () => approvePlan(cwd, session, { planId: draft.id, targetMode: 'plan' as never }),
    /plan approval target mode must be default, accept-edits, or yolo/
  );
  assert.equal(session.approvedPlanId, undefined);
});

test('readPlanArtifact rejects tampered identity and path fields', async () => {
  const idScope = await tempScope();
  const idDraft = await createDraftPlan(idScope.cwd, idScope.session, {
    title: 'Tampered identity',
    contentMarkdown: '## Plan'
  });
  const idRaw = JSON.parse(await readFile(idDraft.paths.json, 'utf8')) as Record<string, unknown>;
  await writeFile(idDraft.paths.json, JSON.stringify({ ...idRaw, id: 'plan_other' }, null, 2), 'utf8');
  await assert.rejects(() => readPlanArtifact(idScope.cwd, idScope.session, idDraft.id), /mismatched plan artifact/);

  const pathScope = await tempScope();
  const pathDraft = await createDraftPlan(pathScope.cwd, pathScope.session, {
    title: 'Tampered path',
    contentMarkdown: '## Plan'
  });
  const pathRaw = JSON.parse(await readFile(pathDraft.paths.json, 'utf8')) as Record<string, unknown>;
  await writeFile(
    pathDraft.paths.json,
    JSON.stringify({ ...pathRaw, paths: { json: path.join(pathScope.home, 'plans', 'evil.json') } }, null, 2),
    'utf8'
  );
  await assert.rejects(() => readPlanArtifact(pathScope.cwd, pathScope.session, pathDraft.id), /path mismatch/);

  const markdownScope = await tempScope();
  const markdownDraft = await createDraftPlan(markdownScope.cwd, markdownScope.session, {
    title: 'Tampered markdown path',
    contentMarkdown: '## Plan'
  });
  const markdownRaw = JSON.parse(await readFile(markdownDraft.paths.json, 'utf8')) as Record<string, unknown>;
  await writeFile(
    markdownDraft.paths.json,
    JSON.stringify({ ...markdownRaw, paths: { ...markdownDraft.paths, markdown: path.join(markdownScope.home, 'plans', 'evil.md') } }, null, 2),
    'utf8'
  );
  await assert.rejects(() => readPlanArtifact(markdownScope.cwd, markdownScope.session, markdownDraft.id), /markdown path mismatch/);
});
