import assert from 'node:assert/strict';
import test from 'node:test';

import { createPolicyEngine } from './engine.js';
import { buildToolApprovalSubject } from './subjects.js';
import type { ApprovalSubject, ToolAccess } from './types.js';
import type { ModelAction } from '../protocol/model/actions.js';

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
  return {
    kind: 'tx-apply',
    txId: 'tx_123',
    diffSummary: {
      filesChanged: 1,
      additions: 2,
      deletions: 1,
      creates: [],
      modifies: ['src/index.ts'],
      deletes: []
    },
    validators: [{ name: 'tsc', severity: 'blocking', status: 'pass', durationMs: 12 }],
    blockingFailures: [],
    artifactRef: 'tx/tx_123/'
  };
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
