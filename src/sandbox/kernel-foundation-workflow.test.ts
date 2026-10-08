import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../../.github/workflows/kernel-foundation.yml', import.meta.url);

function stepBlocks(workflow: string): string[] {
  const lines = workflow.split('\n');
  const blocks: string[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const start = /^(\s*)- (?:uses|name|run):/.exec(lines[index]);
    if (!start) continue;

    let end = index + 1;
    while (end < lines.length && !new RegExp(`^${start[1]}- (?:uses|name|run):`).test(lines[end])) {
      end += 1;
    }
    blocks.push(lines.slice(index, end).join('\n'));
    index = end - 1;
  }

  return blocks;
}

test('Kernel foundation checkout never persists the GitHub credential', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  const checkouts = stepBlocks(workflow).filter((block) =>
    /- uses: actions\/checkout@/.test(block)
  );

  assert.ok(checkouts.length > 0, 'workflow must have checkout steps to verify');
  for (const checkout of checkouts) {
    assert.match(checkout, /\n\s+with:\n\s+persist-credentials: false(?:\n|$)/);
  }
});

test('Linux qualification cleanup kills and removes the whole delegated cgroup tree', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  const cleanup = stepBlocks(workflow).find((block) =>
    /- name: Remove delegated cgroup subtree/.test(block)
  );

  assert.ok(cleanup, 'cleanup step must exist');
  assert.match(
    cleanup,
    /printf '1\\n' \| sudo tee "\$CLIQ_CGROUP_PARENT\/cgroup\.kill"[\s\S]*grep -q '\^populated 0\$' "\$CLIQ_CGROUP_PARENT\/cgroup\.events"[\s\S]*while IFS= read -r -d '' child; do\n\s+sudo rmdir "\$child"\n\s+done < <\(find "\$CLIQ_CGROUP_PARENT" -mindepth 1 -depth -type d -print0\)\n\s+sudo rmdir "\$CLIQ_CGROUP_PARENT"/
  );
});
