import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../../.github/workflows/kernel-foundation.yml', import.meta.url);

test('Kernel foundation checkout never persists the GitHub credential', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  const checkouts = workflow.match(/uses: actions\/checkout@v4/g) ?? [];
  const disabledPersistence = workflow.match(/persist-credentials: false/g) ?? [];

  assert.equal(checkouts.length, 2);
  assert.equal(disabledPersistence.length, checkouts.length);
});

test('Linux qualification cleanup kills and removes the whole delegated cgroup tree', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');

  assert.match(workflow, /"\$CLIQ_CGROUP_PARENT\/cgroup\.kill"/);
  assert.match(workflow, /find "\$CLIQ_CGROUP_PARENT" -mindepth 1 -depth -type d/);
});
