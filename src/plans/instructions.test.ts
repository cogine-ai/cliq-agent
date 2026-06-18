import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from '../session/store.js';
import { approvePlan, createDraftPlan, finalizePlan, updatePlanProgress } from './store.js';
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
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-plan-instructions-ws-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-plan-instructions-home-'));
  cleanupDirs.push(cwd, home);
  process.env.CLIQ_HOME = home;
  return { cwd, session: createSession(cwd) };
}

test('buildApprovedPlanInstructionMessages returns [] without an approved plan reference', async () => {
  const { cwd, session } = await tempScope();

  assert.deepEqual(await buildApprovedPlanInstructionMessages(cwd, session), []);
});

test('buildApprovedPlanInstructionMessages returns [] when the referenced artifact is missing', async () => {
  const { cwd, session } = await tempScope();
  session.approvedPlanId = 'plan_missing';

  assert.deepEqual(await buildApprovedPlanInstructionMessages(cwd, session), []);
});

test('buildApprovedPlanInstructionMessages returns [] for non-approved artifacts', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Draft plan',
    contentMarkdown: '## Draft'
  });
  session.approvedPlanId = draft.id;

  assert.deepEqual(await buildApprovedPlanInstructionMessages(cwd, session), []);
});

test('buildApprovedPlanInstructionMessages falls back to default when approved target mode is absent', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Approved without mode',
    contentMarkdown: '## Steps\n- Run'
  });
  await finalizePlan(cwd, session);
  const approved = await approvePlan(cwd, session, { planId: draft.id, targetMode: 'accept-edits' });
  const raw = JSON.parse(await readFile(approved.paths.json, 'utf8')) as Record<string, unknown>;
  delete raw.approvedTargetMode;
  await writeFile(approved.paths.json, JSON.stringify(raw, null, 2), 'utf8');

  const messages = await buildApprovedPlanInstructionMessages(cwd, session);

  assert.equal(messages.length, 1);
  assert.match(messages[0]?.content ?? '', /Approved target mode: default/);
});

test('buildApprovedPlanInstructionMessages returns approved plan context', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Approved workflow',
    contentMarkdown: '## Steps\n- Implement safely'
  });
  await finalizePlan(cwd, session);
  await approvePlan(cwd, session, { planId: draft.id, targetMode: 'yolo' });

  const messages = await buildApprovedPlanInstructionMessages(cwd, session);

  assert.deepEqual(messages.map((message) => [message.role, message.layer, message.source]), [
    ['system', 'core', 'plan:approved']
  ]);
  assert.match(messages[0]?.content ?? '', new RegExp(draft.id));
  assert.match(messages[0]?.content ?? '', /Plan file: .*plan\.md/);
  assert.match(messages[0]?.content ?? '', /Plan items:/);
  assert.match(messages[0]?.content ?? '', /\[pending\] Implement safely/);
  assert.match(messages[0]?.content ?? '', /Approved target mode: yolo/);
  assert.match(messages[0]?.content ?? '', /Implement safely/);
});

test('buildApprovedPlanInstructionMessages includes execution tracker state and update rules', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Tracked workflow',
    contentMarkdown: '## Steps\n- Inspect code\n- Implement tracker'
  });
  await finalizePlan(cwd, session);
  await approvePlan(cwd, session, { planId: draft.id, targetMode: 'accept-edits' });
  await updatePlanProgress(cwd, session, {
    planId: draft.id,
    items: [
      { id: 'item_1', title: 'Inspect code', status: 'completed', activeForm: 'Inspecting code' },
      { id: 'item_2', title: 'Implement tracker', status: 'in_progress', activeForm: 'Implementing tracker' }
    ]
  });

  const messages = await buildApprovedPlanInstructionMessages(cwd, session);
  const content = messages[0]?.content ?? '';

  assert.match(content, /Plan execution tracker:/);
  assert.match(content, /\[completed\] Inspect code/);
  assert.match(content, /\[in_progress\] Implement tracker - Implementing tracker/);
  assert.match(content, /Use the todo action to keep this tracker current/);
  assert.match(content, /Todo action shape:/);
  assert.match(content, /activeForm field is optional/);
  assert.match(content, /keeps the previous phrase for the same item id or derives one from the title/);
  assert.match(content, /replaces the full tracker list/);
  assert.match(content, /at most one item in_progress/);
  assert.match(content, /Do not mark an item completed/);
});
