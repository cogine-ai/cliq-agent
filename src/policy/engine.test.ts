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

function txApplySubject(): ApprovalSubject {
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
      blockingFailures: []
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

test('auto allows registered tool subjects that passed core validation', async () => {
  const policy = createPolicyEngine({ mode: 'auto' });

  assert.deepEqual(await policy.decide(toolSubject('edit', 'write')), {
    behavior: 'allow',
    decidedBy: 'policy'
  });
});

test('permission requests follow policy modes', async () => {
  const subject = permissionRequestSubject();

  assert.deepEqual(await createPolicyEngine({ mode: 'auto' }).decide(subject), {
    behavior: 'allow',
    decidedBy: 'policy'
  });
  assert.deepEqual(await createPolicyEngine({ mode: 'read-only' }).decide(subject), {
    behavior: 'deny',
    reason: 'policy mode read-only blocks permission requests',
    decidedBy: 'policy'
  });

  for (const mode of ['confirm-write', 'confirm-bash', 'confirm-all'] as const) {
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

test('read-only denies write, exec, and tx-apply subjects', async () => {
  const policy = createPolicyEngine({ mode: 'read-only' });

  assert.deepEqual(await policy.decide(toolSubject('read', 'read')), {
    behavior: 'allow',
    decidedBy: 'policy'
  });
  assert.deepEqual(await policy.decide(toolSubject('edit', 'write')), {
    behavior: 'deny',
    reason: 'policy mode read-only blocks write tools',
    decidedBy: 'policy'
  });
  assert.deepEqual(await policy.decide(toolSubject('bash', 'exec')), {
    behavior: 'deny',
    reason: 'policy mode read-only blocks exec tools',
    decidedBy: 'policy'
  });
  assert.deepEqual(await policy.decide(txApplySubject()), {
    behavior: 'deny',
    reason: 'policy mode read-only blocks transaction apply',
    decidedBy: 'policy'
  });
});

test('confirm-write asks for write tool subjects and allows read and exec', async () => {
  const policy = createPolicyEngine({ mode: 'confirm-write' });
  const edit = buildToolApprovalSubject({
    definition: { name: 'edit', access: 'write' },
    action: { edit: { path: 'src/index.ts', old_text: 'old', new_text: 'new' } },
    tx: { enabled: true, txId: 'tx_123', mode: 'edit' }
  });

  assert.deepEqual(await policy.decide(toolSubject('read', 'read')), {
    behavior: 'allow',
    decidedBy: 'policy'
  });
  assert.deepEqual(await policy.decide(toolSubject('bash', 'exec', { bash: 'npm test' })), {
    behavior: 'allow',
    decidedBy: 'policy'
  });

  const decision = await policy.decide(edit);
  assert.equal(decision.behavior, 'ask');
  assert.equal(decision.decidedBy, 'policy');
  if (decision.behavior === 'ask') {
    assert.match(decision.prompt, /Allow staged edit\?/);
    assert.match(decision.prompt, /src\/index\.ts/);
    assert.match(decision.prompt, /policy: confirm-write/);
    assert.match(decision.prompt, /tx: tx_123/);
  }
});

test('confirm-bash asks for exec tool subjects with command payload and allows write', async () => {
  const policy = createPolicyEngine({ mode: 'confirm-bash' });

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
    assert.match(decision.prompt, /policy: confirm-bash/);
  }
});

test('confirm-all asks for every tool subject', async () => {
  const policy = createPolicyEngine({ mode: 'confirm-all' });

  assert.equal((await policy.decide(toolSubject('read', 'read'))).behavior, 'ask');
  assert.equal((await policy.decide(toolSubject('edit', 'write'))).behavior, 'ask');
  assert.equal((await policy.decide(toolSubject('bash', 'exec', { bash: 'npm test' }))).behavior, 'ask');
});

test('decision table: workspace allow short-circuits a confirm-write preset', async () => {
  const policy = createPolicyEngine({
    mode: 'confirm-write',
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
    mode: 'auto',
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

test('decision table: compound bash never matches allow (chained-command bypass)', async () => {
  const policy = createPolicyEngine({
    mode: 'auto',
    table: composePermissionTable({ allow: [wsRule('bash', 'git *')] })
  });
  const subject = buildToolApprovalSubject({
    definition: { name: 'bash', access: 'exec' },
    action: { bash: 'git status && rm -rf /' }
  });
  const decision = await policy.decide(subject);
  assert.equal(decision.behavior, 'ask');
  assert.equal(subject.kind, 'tool');
  if (subject.kind === 'tool') {
    assert.equal(subject.channel.kind, 'bash');
    if (subject.channel.kind === 'bash') {
      assert.equal(subject.channel.compound, true);
    }
  }
});

test('decision table: bash without identifiable head never matches allow (no silent approve)', async () => {
  const policy = createPolicyEngine({
    mode: 'confirm-bash',
    // Even a "*" allow must not approve "&& ls"; the channel.commandHead
    // sentinel forces fallthrough so the confirm-bash preset asks the user.
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
    mode: 'auto',
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

test('decision table: ask wins over preset auto', async () => {
  const policy = createPolicyEngine({
    mode: 'auto',
    table: composePermissionTable({ ask: [wsRule('fs-write', 'src/*')] })
  });
  const edit = buildToolApprovalSubject({
    definition: { name: 'edit', access: 'write' },
    action: { edit: { path: 'src/index.ts', old_text: 'a', new_text: 'b' } }
  });
  const decision = await policy.decide(edit);
  assert.equal(decision.behavior, 'ask');
});

test('tx-apply asks in confirm-write and confirm-all modes', async () => {
  const confirmWrite = createPolicyEngine({ mode: 'confirm-write' });
  const confirmAll = createPolicyEngine({ mode: 'confirm-all' });
  const confirmBash = createPolicyEngine({ mode: 'confirm-bash' });

  const writeDecision = await confirmWrite.decide(txApplySubject());
  assert.equal(writeDecision.behavior, 'ask');
  if (writeDecision.behavior === 'ask') {
    assert.match(writeDecision.prompt, /Apply transaction\?/);
    assert.match(writeDecision.prompt, /tx_123/);
    assert.match(writeDecision.prompt, /1 files changed/);
    assert.match(writeDecision.prompt, /policy: confirm-write/);
  }

  assert.equal((await confirmAll.decide(txApplySubject())).behavior, 'ask');
  assert.deepEqual(await confirmBash.decide(txApplySubject()), {
    behavior: 'allow',
    decidedBy: 'policy'
  });
});
