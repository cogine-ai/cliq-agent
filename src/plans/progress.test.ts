import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from '../session/store.js';
import {
  approvePlan,
  createDraftPlan,
  finalizePlan,
  planProgressPath,
  readPlanArtifact,
  readPlanProgress,
  updatePlanProgress
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
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-plan-progress-ws-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-plan-progress-home-'));
  cleanupDirs.push(cwd, home);
  process.env.CLIQ_HOME = home;
  return { cwd, home, session: createSession(cwd) };
}

test('approvePlan seeds execution progress beside the approved plan artifact', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Execute tracker',
    contentMarkdown: '## Steps\n- Inspect code\n- Implement tracker',
    items: [
      { id: 'inspect', title: 'Inspect code' },
      { id: 'implement', title: 'Implement tracker' }
    ]
  });
  await finalizePlan(cwd, session);

  const approved = await approvePlan(cwd, session, { planId: draft.id, targetMode: 'accept-edits' });
  const progress = await readPlanProgress(cwd, session, approved.id);

  assert.equal(progress.planId, approved.id);
  assert.equal(progress.sessionId, session.id);
  assert.equal(progress.paths.json.endsWith(path.join(approved.id, 'progress.json')), true);
  assert.deepEqual(progress.items, [
    { id: 'inspect', title: 'Inspect code', status: 'pending', activeForm: 'Inspecting code' },
    { id: 'implement', title: 'Implement tracker', status: 'pending', activeForm: 'Implementing tracker' }
  ]);
});

test('approvePlan starts execution progress from pending regardless of review snapshot status', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Execute tracker',
    contentMarkdown: '## Steps\n- [~] Inspect code\n- [x] Implement tracker',
    items: [
      { id: 'inspect', title: 'Inspect code', status: 'in_progress' },
      { id: 'implement', title: 'Implement tracker', status: 'completed' }
    ]
  });
  await finalizePlan(cwd, session);

  const approved = await approvePlan(cwd, session, { planId: draft.id, targetMode: 'accept-edits' });
  const progress = await readPlanProgress(cwd, session, approved.id);

  assert.deepEqual(progress.items.map((item) => [item.id, item.status]), [
    ['inspect', 'pending'],
    ['implement', 'pending']
  ]);
});

test('approvePlan does not mark the plan approved when progress seeding fails', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Progress failure',
    contentMarkdown: '## Steps\n- Seed tracker'
  });
  await finalizePlan(cwd, session);
  await mkdir(await planProgressPath(cwd, session, draft.id));

  await assert.rejects(
    () => approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' }),
    /EISDIR|directory|EEXIST|not a file|illegal operation/i
  );

  const artifact = await readPlanArtifact(cwd, session, draft.id);
  assert.equal(artifact.status, 'finalized');
  assert.equal(session.approvedPlanId, undefined);
});

test('updatePlanProgress persists execution status without mutating the approved snapshot', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Execute tracker',
    contentMarkdown: '## Steps\n- Inspect code\n- Implement tracker'
  });
  await finalizePlan(cwd, session);
  const approved = await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });

  const updated = await updatePlanProgress(cwd, session, {
    planId: approved.id,
    items: [
      { id: 'item_1', title: 'Inspect code', status: 'completed', activeForm: 'Inspecting code' },
      { id: 'item_2', title: 'Implement tracker', status: 'in_progress', activeForm: 'Implementing tracker' }
    ]
  });

  assert.deepEqual(updated.items.map((item) => [item.id, item.status]), [
    ['item_1', 'completed'],
    ['item_2', 'in_progress']
  ]);
  assert.deepEqual(approved.items.map((item) => [item.id, item.status]), [
    ['item_1', 'pending'],
    ['item_2', 'pending']
  ]);
});

test('updatePlanProgress rejects stale plan ids and multiple in-progress items', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Execute tracker',
    contentMarkdown: '## Steps\n- One\n- Two'
  });
  await finalizePlan(cwd, session);
  await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });

  await assert.rejects(
    () =>
      updatePlanProgress(cwd, session, {
        planId: 'plan_other',
        items: [{ id: 'item_1', title: 'One', status: 'in_progress', activeForm: 'Doing one' }]
      }),
    /approved plan/
  );

  await assert.rejects(
    () =>
      updatePlanProgress(cwd, session, {
        planId: draft.id,
        items: [
          { id: 'item_1', title: 'One', status: 'in_progress', activeForm: 'Doing one' },
          { id: 'item_2', title: 'Two', status: 'in_progress', activeForm: 'Doing two' }
        ]
      }),
    /at most one in_progress/
  );
});
