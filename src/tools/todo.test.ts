import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from '../session/store.js';
import { approvePlan, createDraftPlan, finalizePlan, readPlanProgress } from '../plans/store.js';
import { todoTool } from './todo.js';

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
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-todo-tool-ws-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-todo-tool-home-'));
  cleanupDirs.push(cwd, home);
  process.env.CLIQ_HOME = home;
  return { cwd, session: createSession(cwd) };
}

test('todoTool.supports validates execution tracker payloads', () => {
  assert.equal(
    todoTool.supports({
      todo: {
        planId: 'plan_1',
        items: [{ id: 'item_1', title: 'Inspect', status: 'pending', activeForm: 'Inspecting' }]
      }
    }),
    true
  );
  assert.equal(todoTool.supports({ todo: { items: [{ title: 'Inspect', status: 'pending' }] } } as never), false);
  assert.equal(todoTool.supports({ todo: { items: 'nope' } } as never), false);
  assert.equal(todoTool.supports({ todo: null } as never), false);
});

test('todoTool.execute updates approved-plan execution progress', async () => {
  const { cwd, session } = await tempScope();
  const draft = await createDraftPlan(cwd, session, {
    title: 'Tracker',
    contentMarkdown: '## Steps\n- Inspect\n- Implement'
  });
  await finalizePlan(cwd, session);
  await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });

  const result = await todoTool.execute(
    {
      todo: {
        planId: draft.id,
        items: [
          { id: 'item_1', title: 'Inspect', status: 'completed', activeForm: 'Inspecting' },
          { id: 'item_2', title: 'Implement', status: 'in_progress', activeForm: 'Implementing' }
        ]
      }
    },
    { cwd, session }
  );

  assert.equal(result.status, 'ok');
  assert.equal(result.meta.planId, draft.id);
  assert.equal(result.meta.itemCount, 2);
  assert.match(result.content, /continue to use the todo list/i);

  const progress = await readPlanProgress(cwd, session, draft.id);
  assert.deepEqual(progress.items.map((item) => [item.title, item.status]), [
    ['Inspect', 'completed'],
    ['Implement', 'in_progress']
  ]);
});
