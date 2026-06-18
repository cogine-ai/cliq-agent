import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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
  readReferencedPlanProgress,
  readOrSeedReferencedPlanProgress,
  updatePlanProgress
} from './store.js';
import { buildApprovedPlanInstructionMessages } from './instructions.js';

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

test('approvePlan reseeds existing progress from the current finalized artifact', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Reworked tracker',
    contentMarkdown: '## Steps\n- Old work',
    items: [{ id: 'old', title: 'Old work' }]
  });
  await finalizePlan(cwd, session);
  const approved = await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });
  await updatePlanProgress(cwd, session, {
    planId: approved.id,
    items: [{ id: 'old', title: 'Old work', status: 'completed', activeForm: 'Working on Old work' }]
  });

  const oldArtifact = await readPlanArtifact(cwd, session, approved.id);
  const { approvedAt: _approvedAt, approvedTargetMode: _approvedTargetMode, ...base } = oldArtifact;
  await writeFile(
    oldArtifact.paths.json,
    JSON.stringify(
      {
        ...base,
        status: 'finalized',
        contentMarkdown: '## Steps\n- New work',
        items: [{ id: 'new', title: 'New work', status: 'completed' }],
        updatedAt: new Date().toISOString()
      },
      null,
      2
    )
  );
  session.activePlanId = approved.id;
  delete session.approvedPlanId;

  await approvePlan(cwd, session, { planId: approved.id, targetMode: 'default' });
  const progress = await readPlanProgress(cwd, session, approved.id);

  assert.deepEqual(progress.items.map((item) => [item.id, item.title, item.status]), [
    ['new', 'New work', 'pending']
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

test('updatePlanProgress lazily seeds historical approved plans missing progress', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Legacy tracker',
    contentMarkdown: '## Steps\n- Inspect code\n- Implement tracker'
  });
  await finalizePlan(cwd, session);
  const approved = await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });
  await rm(await planProgressPath(cwd, session, approved.id), { force: true });

  const updated = await updatePlanProgress(cwd, session, {
    planId: approved.id,
    items: [
      { id: 'item_1', title: 'Inspect code', status: 'completed', activeForm: 'Inspecting code' },
      { id: 'item_2', title: 'Implement tracker', status: 'in_progress', activeForm: 'Implementing tracker' }
    ]
  });

  assert.equal(updated.planId, approved.id);
  assert.deepEqual(updated.items.map((item) => [item.id, item.status]), [
    ['item_1', 'completed'],
    ['item_2', 'in_progress']
  ]);
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

test('updatePlanProgress fills missing activeForm from existing tracker or title', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Execute tracker',
    contentMarkdown: '## Steps\n- Inspect code\n- 汇总生成项目清单'
  });
  await finalizePlan(cwd, session);
  const approved = await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });
  await updatePlanProgress(cwd, session, {
    planId: approved.id,
    items: [
      { id: 'item_1', title: 'Inspect code', status: 'pending', activeForm: 'Checking code' },
      { id: 'item_2', title: '汇总生成项目清单', status: 'pending', activeForm: 'Working on 汇总生成项目清单' }
    ]
  });

  const updated = await updatePlanProgress(cwd, session, {
    planId: approved.id,
    items: [
      { id: 'item_1', title: 'Inspect code', status: 'completed' },
      { id: 'report', title: '汇总生成项目清单', status: 'in_progress' }
    ]
  });

  assert.deepEqual(updated.items, [
    { id: 'item_1', title: 'Inspect code', status: 'completed', activeForm: 'Checking code' },
    { id: 'report', title: '汇总生成项目清单', status: 'in_progress', activeForm: 'Working on 汇总生成项目清单' }
  ]);
});

test('updatePlanProgress rejects explicit blank activeForm instead of inheriting prior tracker phrase', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Execute tracker',
    contentMarkdown: '## Steps\n- Inspect code'
  });
  await finalizePlan(cwd, session);
  const approved = await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });
  await updatePlanProgress(cwd, session, {
    planId: approved.id,
    items: [{ id: 'item_1', title: 'Inspect code', status: 'pending', activeForm: 'Checking code' }]
  });

  await assert.rejects(
    () =>
      updatePlanProgress(cwd, session, {
        planId: approved.id,
        items: [{ id: 'item_1', title: 'Inspect code', status: 'in_progress', activeForm: '   ' }]
      }),
    /invalid plan progress items/
  );

  const progress = await readPlanProgress(cwd, session, approved.id);
  assert.deepEqual(progress.items, [
    { id: 'item_1', title: 'Inspect code', status: 'pending', activeForm: 'Checking code' }
  ]);
});

test('readReferencedPlanProgress does not recreate progress while building instructions', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Tracked workflow',
    contentMarkdown: '## Steps\n- Inspect code\n- Implement tracker'
  });
  await finalizePlan(cwd, session);
  await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });
  await updatePlanProgress(cwd, session, {
    planId: draft.id,
    items: [
      { id: 'item_1', title: 'Inspect code', status: 'completed', activeForm: 'Inspecting code' },
      { id: 'item_2', title: 'Implement tracker', status: 'in_progress', activeForm: 'Implementing tracker' }
    ]
  });
  await rm(await planProgressPath(cwd, session, draft.id), { force: true });

  assert.equal(await readReferencedPlanProgress(cwd, session, draft.id), null);
  await assert.rejects(() => readPlanProgress(cwd, session, draft.id), /ENOENT|no such file/i);

  const messages = await buildApprovedPlanInstructionMessages(cwd, session);
  assert.doesNotMatch(messages[0]?.content ?? '', /Plan execution tracker:/);
  await assert.rejects(() => readPlanProgress(cwd, session, draft.id), /ENOENT|no such file/i);

  const seeded = await readOrSeedReferencedPlanProgress(cwd, session, draft.id);
  assert.ok(seeded);
  assert.deepEqual(seeded.items.map((item) => [item.id, item.status]), [
    ['item_1', 'pending'],
    ['item_2', 'pending']
  ]);
});

test('readOrSeedReferencedPlanProgress preserves existing execution progress', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Tracked workflow',
    contentMarkdown: '## Steps\n- Inspect code'
  });
  await finalizePlan(cwd, session);
  await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });
  await updatePlanProgress(cwd, session, {
    planId: draft.id,
    items: [{ id: 'item_1', title: 'Inspect code', status: 'completed', activeForm: 'Inspecting code' }]
  });

  const progress = await readPlanProgress(cwd, session, draft.id);
  const seeded = await readOrSeedReferencedPlanProgress(cwd, session, draft.id);
  assert.equal(seeded?.items[0]?.status, 'completed');
  assert.equal(seeded?.updatedAt, progress.updatedAt);
});

test('readOrSeedReferencedPlanProgress does not seed stale approved plans', async () => {
  const { cwd, session } = await tempScope();
  const oldDraft = await createDraftPlan(cwd, session, {
    title: 'Old workflow',
    contentMarkdown: '## Steps\n- Old work'
  });
  await finalizePlan(cwd, session);
  await approvePlan(cwd, session, { planId: oldDraft.id, targetMode: 'default' });
  await rm(await planProgressPath(cwd, session, oldDraft.id), { force: true });

  const currentDraft = await createDraftPlan(cwd, session, {
    title: 'Current workflow',
    contentMarkdown: '## Steps\n- Current work'
  });
  await finalizePlan(cwd, session);
  await approvePlan(cwd, session, { planId: currentDraft.id, targetMode: 'default' });

  assert.equal(await readOrSeedReferencedPlanProgress(cwd, session, oldDraft.id), null);
  await assert.rejects(() => readPlanProgress(cwd, session, oldDraft.id), /ENOENT|no such file/i);
});

test('readPlanProgress rejects tampered identity and path fields', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Tampered progress',
    contentMarkdown: '## Steps\n- One'
  });
  await finalizePlan(cwd, session);
  await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });

  const progressPath = await planProgressPath(cwd, session, draft.id);
  const raw = JSON.parse(await readFile(progressPath, 'utf8')) as Record<string, unknown>;
  await writeFile(progressPath, JSON.stringify({ ...raw, planId: 'plan_other' }, null, 2), 'utf8');
  await assert.rejects(() => readPlanProgress(cwd, session, draft.id), /mismatched plan progress/);

  const pathRaw = JSON.parse(await readFile(progressPath, 'utf8')) as Record<string, unknown>;
  await writeFile(
    progressPath,
    JSON.stringify({ ...pathRaw, planId: draft.id, paths: { json: path.join(path.dirname(progressPath), 'evil.json') } }, null, 2),
    'utf8'
  );
  await assert.rejects(() => readPlanProgress(cwd, session, draft.id), /plan progress path mismatch/);
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

  await assert.rejects(
    () =>
      updatePlanProgress(cwd, session, {
        planId: draft.id,
        items: [{ status: 'pending' }] as never
      }),
    /invalid plan progress items/
  );

  await assert.rejects(
    () =>
      updatePlanProgress(cwd, session, {
        planId: draft.id,
        items: [{ title: 'One', status: 'pending', activeForm: 1 }] as never
      }),
    /invalid plan progress items/
  );

  await assert.rejects(
    () =>
      updatePlanProgress(cwd, session, {
        planId: draft.id,
        items: [{ title: 'One', status: 'pending', activeForm: '   ' }]
      }),
    /invalid plan progress items/
  );
});
