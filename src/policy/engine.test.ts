import assert from 'node:assert/strict';
import test from 'node:test';

import { composePermissionTable, type PermissionRule } from './decision-table.js';
import { createPolicyEngine } from './engine.js';
import { buildToolApprovalSubject, buildTxApplyApprovalSubject } from './subjects.js';
import type { ApprovalSubject, ToolAccess } from './types.js';
import type { ModelAction } from '../protocol/model/actions.js';
import type { TxReviewSnapshot } from '../workspace/transactions/inspect.js';

const wsRule = (channel: PermissionRule['channel'], pattern: string): PermissionRule => ({
  channel,
  pattern,
  source: 'workspace'
});

function toolSubject(
  name: string,
  access: ToolAccess,
  action: ModelAction = { read: { path: 'README.md' } }
): ApprovalSubject {
  return buildToolApprovalSubject({
    definition: { name, access },
    action
  });
}

function txApplySubject(blockingFailures: string[] = []): ApprovalSubject {
  const snapshot = {
    tx: {
      id: 'tx_123',
      kind: 'edit',
      state: 'validated',
      workspaceId: 'ws',
      sessionId: 'sess',
      workspaceRealPath: '/tmp/ws',
      createdAt: '2026-05-12T00:00:00Z',
      updatedAt: '2026-05-12T00:00:01Z',
      diffSummary: {
        filesChanged: 1,
        additions: 2,
        deletions: 1,
        creates: [],
        modifies: ['src/index.ts'],
        deletes: []
      },
      validators: [{ name: 'tsc', severity: 'blocking', status: 'pass', durationMs: 12 }],
      blockingFailures
    },
    diff: null,
    audit: [],
    bashEffects: [],
    validatorResults: [],
    validatorArtifactResults: [],
    validatorArtifactErrors: [],
    artifactRef: 'tx/tx_123/'
  } satisfies TxReviewSnapshot;

  return buildTxApplyApprovalSubject(snapshot);
}

function permissionRequestSubject(): ApprovalSubject {
  return {
    kind: 'permission-request',
    source: 'tool',
    toolName: 'bash',
    reason: 'needs network access',
    requestedCapabilities: ['network']
  };
}

test('yolo allows registered tool subjects that passed core validation', async () => {
  const policy = createPolicyEngine({ mode: 'yolo' });

  assert.deepEqual(await policy.decide(toolSubject('edit', 'write')), {
    behavior: 'allow',
    decidedBy: 'policy'
  });
});

test('permission requests follow policy modes', async () => {
  const subject = permissionRequestSubject();

  assert.deepEqual(await createPolicyEngine({ mode: 'yolo' }).decide(subject), {
    behavior: 'allow',
    decidedBy: 'policy'
  });
  assert.deepEqual(await createPolicyEngine({ mode: 'plan' }).decide(subject), {
    behavior: 'deny',
    reason: 'policy mode plan blocks permission requests',
    decidedBy: 'policy'
  });

  for (const mode of ['default', 'accept-edits'] as const) {
    const decision = await createPolicyEngine({ mode }).decide(subject);
    assert.equal(decision.behavior, 'ask');
    assert.equal(decision.decidedBy, 'policy');
    if (decision.behavior === 'ask') {
      assert.match(decision.prompt, /Allow permission request\?/);
      assert.match(decision.prompt, /network/);
      assert.match(decision.prompt, new RegExp(`policy: ${mode}`));
    }
  }
});

test('plan allows plan artifacts and denies write, exec, tx-apply, and permission-request subjects', async () => {
  const policy = createPolicyEngine({ mode: 'plan' });

  assert.deepEqual(await policy.decide(toolSubject('read', 'read')), {
    behavior: 'allow',
    decidedBy: 'policy'
  });
  assert.deepEqual(
    await policy.decide(toolSubject('plan', 'plan', { plan: { op: 'draft', title: 'T', content: '## Plan' } })),
    {
      behavior: 'allow',
      decidedBy: 'policy'
    }
  );
  assert.deepEqual(await policy.decide(toolSubject('edit', 'write')), {
    behavior: 'deny',
    reason: 'policy mode plan blocks write tools',
    decidedBy: 'policy'
  });
  assert.deepEqual(await policy.decide(toolSubject('bash', 'exec')), {
    behavior: 'deny',
    reason: 'policy mode plan blocks exec tools',
    decidedBy: 'policy'
  });
  assert.deepEqual(await policy.decide(txApplySubject()), {
    behavior: 'deny',
    reason: 'policy mode plan blocks transaction apply',
    decidedBy: 'policy'
  });
  assert.deepEqual(await policy.decide(permissionRequestSubject()), {
    behavior: 'deny',
    reason: 'policy mode plan blocks permission requests',
    decidedBy: 'policy'
  });
});

test('plan hard-denies exec even when a permission table allow rule matches', async () => {
  const policy = createPolicyEngine({
    mode: 'plan',
    table: composePermissionTable({ allow: [wsRule('bash', '*')] })
  });

  assert.deepEqual(await policy.decide(toolSubject('bash', 'exec', { bash: 'pwd' })), {
    behavior: 'deny',
    reason: 'policy mode plan blocks exec tools',
    decidedBy: 'policy'
  });
});

test('default asks for write and exec tool subjects and allows reads', async () => {
  const policy = createPolicyEngine({ mode: 'default' });
  const edit = buildToolApprovalSubject({
    definition: { name: 'edit', access: 'write' },
    action: { edit: { path: 'src/index.ts', old_text: 'old', new_text: 'new' } },
    tx: { enabled: true, txId: 'tx_123', mode: 'edit' }
  });

  assert.deepEqual(await policy.decide(toolSubject('read', 'read')), {
    behavior: 'allow',
    decidedBy: 'policy'
  });

  const bashDecision = await policy.decide(toolSubject('bash', 'exec', { bash: 'npm test' }));
  assert.equal(bashDecision.behavior, 'ask');
  assert.equal(bashDecision.decidedBy, 'policy');
  if (bashDecision.behavior === 'ask') {
    assert.match(bashDecision.prompt, /Allow bash command\?/);
    assert.match(bashDecision.prompt, /npm test/);
    assert.match(bashDecision.prompt, /policy: default/);
  }

  const decision = await policy.decide(edit);
  assert.equal(decision.behavior, 'ask');
  assert.equal(decision.decidedBy, 'policy');
  if (decision.behavior === 'ask') {
    assert.match(decision.prompt, /Allow staged edit\?/);
    assert.match(decision.prompt, /src\/index\.ts/);
    assert.match(decision.prompt, /policy: default/);
    assert.match(decision.prompt, /tx: tx_123/);
  }
});

test('accept-edits asks for exec tool subjects with command payload and allows write', async () => {
  const policy = createPolicyEngine({ mode: 'accept-edits' });

  assert.deepEqual(await policy.decide(toolSubject('edit', 'write')), {
    behavior: 'allow',
    decidedBy: 'policy'
  });

  const decision = await policy.decide(toolSubject('bash', 'exec', { bash: 'npm test' }));
  assert.equal(decision.behavior, 'ask');
  assert.equal(decision.decidedBy, 'policy');
  if (decision.behavior === 'ask') {
    assert.match(decision.prompt, /Allow bash command\?/);
    assert.match(decision.prompt, /npm test/);
    assert.match(decision.prompt, /policy: accept-edits/);
  }
});

test('default allows read tool subjects without prompting', async () => {
  const policy = createPolicyEngine({ mode: 'default' });

  assert.equal((await policy.decide(toolSubject('read', 'read'))).behavior, 'allow');
});

test('decision table: workspace allow short-circuits a default preset', async () => {
  const policy = createPolicyEngine({
    mode: 'default',
    table: composePermissionTable({ allow: [wsRule('fs-write', 'docs/*')] })
  });
  const edit = buildToolApprovalSubject({
    definition: { name: 'edit', access: 'write' },
    action: { edit: { path: 'docs/notes.md', old_text: 'a', new_text: 'b' } }
  });
  const decision = await policy.decide(edit);
  assert.equal(decision.behavior, 'allow');
  if (decision.behavior === 'allow') {
    assert.match(decision.reason ?? '', /allow by workspace rule "fs-write: docs\/\*"/);
  }
});

test('decision table: workspace deny beats a workspace allow on the same channel', async () => {
  const policy = createPolicyEngine({
    mode: 'yolo',
    table: composePermissionTable({
      deny: [wsRule('fs-write', '.env')],
      allow: [wsRule('fs-write', '*')]
    })
  });
  const edit = buildToolApprovalSubject({
    definition: { name: 'edit', access: 'write' },
    action: { edit: { path: '.env', old_text: 'a', new_text: 'b' } }
  });
  const decision = await policy.decide(edit);
  assert.equal(decision.behavior, 'deny');
  if (decision.behavior === 'deny') {
    assert.match(decision.reason, /deny by workspace rule "fs-write: \.env"/);
  }
});

test('decision table: bash allow rules do not auto-approve executable shell syntax', async () => {
  const policy = createPolicyEngine({
    mode: 'yolo',
    table: composePermissionTable({ allow: [wsRule('bash', 'git *')] })
  });

  const unsafeCommands = [
    'git status && rm -rf /',
    'git status; rm -rf /',
    'git status | sh',
    'git status\nrm -rf /',
    'git status $(rm -rf /)',
    'git status `rm -rf /`',
    'git status <(rm -rf /)',
    'git status >(rm -rf /)'
  ];

  for (const bash of unsafeCommands) {
    const subject = buildToolApprovalSubject({
      definition: { name: 'bash', access: 'exec' },
      action: { bash }
    });
    const decision = await policy.decide(subject);
    assert.equal(decision.behavior, 'ask', bash);
  }
});

test('decision table: bash allow rules do not auto-approve compound syntax inside bash -c', async () => {
  const policy = createPolicyEngine({
    mode: 'yolo',
    table: composePermissionTable({ allow: [wsRule('bash', '*')] })
  });

  for (const bash of [
    "bash -c 'git status && rm -rf /'",
    "bash -lc 'git status && rm -rf /'",
    "bash -o pipefail -c 'git status && rm -rf /'",
    "bash -c 'bash -c \"git status && rm -rf /\"'",
    'bash -c "git status; rm -rf /"',
    'sh -c "git status | sh"',
    "env -S 'git status && rm -rf /'",
    "env --split-string='git status && rm -rf /'",
    "env -S'bash -c \"git status && rm -rf /\"'",
    "env -iS 'bash -c \"git status && rm -rf /\"'",
    "env -iS'bash -c \"git status && rm -rf /\"'",
    "/usr/bin/env -S bash -c 'git status && rm -rf /'",
    "/usr/bin/env -i -S bash -c 'git status && rm -rf /'"
  ]) {
    const subject = buildToolApprovalSubject({
      definition: { name: 'bash', access: 'exec' },
      action: { bash }
    });
    const decision = await policy.decide(subject);
    assert.equal(decision.behavior, 'ask', bash);
  }
});

test('decision table: bash allow rules do not auto-approve delegation or interpreter wrappers', async () => {
  const policy = createPolicyEngine({
    mode: 'default',
    table: composePermissionTable({ allow: [wsRule('bash', '*')] })
  });

  for (const bash of [
    'exec bash -c "git status && rm -rf /"',
    'eval "rm -rf /"',
    'timeout 5 bash -c "git status && rm -rf /"',
    'nohup bash -c "git status && rm -rf /"',
    '/usr/bin/time bash -c "git status && rm -rf /"',
    "timeout 5 env -S 'bash -c \"git status && rm -rf /\"'",
    "nohup /usr/bin/env -S 'bash -c \"git status && rm -rf /\"'",
    "/usr/bin/time -p env --split-string='bash -c \"git status && rm -rf /\"'",
    "timeout 5 /usr/bin/env -S 'python -c \"import os; os.system(\\\"rm -rf /\\\")\"'",
    "python -c 'import os; os.system(\"rm -rf /\")'",
    "python3 -c'import os; os.system(\"rm -rf /\")'",
    "python3.12 -c 'import os; os.system(\"rm -rf /\")'",
    "ruby -e'system(\"rm -rf /\")'",
    "perl -e'system(\"rm -rf /\")'",
    "node -p '1+2'",
    "php -r 'system(\"rm -rf /\");'",
    "env - -S bash -c 'git status && rm -rf /'"
  ]) {
    const subject = buildToolApprovalSubject({
      definition: { name: 'bash', access: 'exec' },
      action: { bash }
    });
    const decision = await policy.decide(subject);
    assert.equal(decision.behavior, 'ask', bash);
  }
});

test('decision table: bash without identifiable head never matches allow (no silent approve)', async () => {
  const policy = createPolicyEngine({
    mode: 'default',
    // Even a "*" allow must not approve "&& ls"; the channel.commandHead
    // sentinel forces fallthrough so the default preset asks the user.
    table: composePermissionTable({ allow: [wsRule('bash', '*')] })
  });
  const subject = buildToolApprovalSubject({
    definition: { name: 'bash', access: 'exec' },
    action: { bash: '&& ls' }
  });
  const decision = await policy.decide(subject);
  assert.equal(decision.behavior, 'ask');
});

test('decision table: builtin deny blocks plain `rm` even when user adds a broad bash allow', async () => {
  const policy = createPolicyEngine({
    mode: 'yolo',
    table: composePermissionTable({ allow: [wsRule('bash', '*')] })
  });
  const subject = buildToolApprovalSubject({
    definition: { name: 'bash', access: 'exec' },
    action: { bash: 'rm -rf /' }
  });
  const decision = await policy.decide(subject);
  assert.equal(decision.behavior, 'deny');
  if (decision.behavior === 'deny') {
    assert.match(decision.reason, /builtin/);
  }
});

test('decision table: builtin deny blocks nested rm inside bash -c even with broad bash allow', async () => {
  const policy = createPolicyEngine({
    mode: 'yolo',
    table: composePermissionTable({ allow: [wsRule('bash', '*')] })
  });

  for (const bash of [
    'bash -c "rm -rf /"',
    'timeout 5 bash -c "rm -rf /"',
    "timeout 5 env -S 'rm -rf /'",
    "timeout 5 env --split-string='rm -rf /'",
    "timeout 5 env -iS'rm -rf /'",
    "nohup env -S 'rm -rf /'",
    "/usr/bin/time env -S 'rm -rf /'",
    'builtin exec bash -c "rm -rf /"',
    'builtin rm -rf /',
    'busybox rm -rf /',
    'su -c "rm -rf /"'
  ]) {
    const subject = buildToolApprovalSubject({
      definition: { name: 'bash', access: 'exec' },
      action: { bash }
    });
    const decision = await policy.decide(subject);
    assert.equal(decision.behavior, 'deny', bash);
    if (decision.behavior === 'deny') {
      assert.match(decision.reason, /builtin/);
    }
  }
});

test('decision table: find -exec cannot be auto-approved by bash allow rules', async () => {
  const policy = createPolicyEngine({
    mode: 'default',
    table: composePermissionTable({ allow: [wsRule('bash', '*')] })
  });
  const subject = buildToolApprovalSubject({
    definition: { name: 'bash', access: 'exec' },
    action: { bash: 'find . -name foo -exec rm {} \\;' }
  });
  const decision = await policy.decide(subject);
  assert.equal(decision.behavior, 'ask');
});

test('decision table: plan channel keys include op and plan id', async () => {
  const policy = createPolicyEngine({
    mode: 'yolo',
    table: composePermissionTable({ deny: [wsRule('plan', 'finalize *')] })
  });

  const finalizeDecision = await policy.decide(
    toolSubject('plan', 'plan', { plan: { op: 'finalize', planId: 'plan_1' } })
  );
  assert.equal(finalizeDecision.behavior, 'deny');
  if (finalizeDecision.behavior === 'deny') {
    assert.match(finalizeDecision.reason, /deny by workspace rule "plan: finalize \*"/);
  }

  const updateDecision = await policy.decide(
    toolSubject('plan', 'plan', { plan: { op: 'update', planId: 'plan_1', content: '## Revised' } })
  );
  assert.equal(updateDecision.behavior, 'allow');
});

test('decision table: ask wins over preset yolo', async () => {
  const policy = createPolicyEngine({
    mode: 'yolo',
    table: composePermissionTable({ ask: [wsRule('fs-write', 'src/*')] })
  });
  const edit = buildToolApprovalSubject({
    definition: { name: 'edit', access: 'write' },
    action: { edit: { path: 'src/index.ts', old_text: 'a', new_text: 'b' } }
  });
  const decision = await policy.decide(edit);
  assert.equal(decision.behavior, 'ask');
});

test('tx-apply follows default, accept-edits, plan, and yolo modes', async () => {
  const defaultPolicy = createPolicyEngine({ mode: 'default' });
  const acceptEdits = createPolicyEngine({ mode: 'accept-edits' });
  const plan = createPolicyEngine({ mode: 'plan' });
  const yolo = createPolicyEngine({ mode: 'yolo' });

  const writeDecision = await defaultPolicy.decide(txApplySubject());
  assert.equal(writeDecision.behavior, 'ask');
  if (writeDecision.behavior === 'ask') {
    assert.match(writeDecision.prompt, /Apply transaction\?/);
    assert.match(writeDecision.prompt, /tx_123/);
    assert.match(writeDecision.prompt, /1 files changed/);
    assert.match(writeDecision.prompt, /policy: default/);
  }

  assert.deepEqual(await acceptEdits.decide(txApplySubject()), {
    behavior: 'allow',
    decidedBy: 'policy'
  });
  const acceptEditsWithFailures = await acceptEdits.decide(txApplySubject(['tsc failed']));
  assert.equal(acceptEditsWithFailures.behavior, 'ask');
  if (acceptEditsWithFailures.behavior === 'ask') {
    assert.match(acceptEditsWithFailures.prompt, /tx_123/);
    assert.match(acceptEditsWithFailures.prompt, /tsc failed/);
  }
  assert.deepEqual(await plan.decide(txApplySubject()), {
    behavior: 'deny',
    reason: 'policy mode plan blocks transaction apply',
    decidedBy: 'policy'
  });
  assert.deepEqual(await yolo.decide(txApplySubject()), {
    behavior: 'allow',
    decidedBy: 'policy'
  });
});
