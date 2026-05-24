import * as assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import type { PermissionTable } from './decision-table.js';
import { buildToolApprovalSubject } from './subjects.js';
import type { ApprovalSubject } from './types.js';
import { createWorkspaceTrustContext } from '../session/trust.js';
import { extendApprovalScope } from './approval-scope.js';
import { createInteractivePolicyEngine } from './interactive-policy.js';

const bashSubject: ApprovalSubject = buildToolApprovalSubject({
  definition: { name: 'bash', access: 'exec' },
  action: { bash: 'npm test' }
});

test('createInteractivePolicyEngine grants one-shot allow when workspace persist fails', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-live-policy-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-live-policy-home-'));
  try {
    const ctx = await createWorkspaceTrustContext(cwd, home);
    const table: PermissionTable = { deny: [], allow: [], ask: [] };
    const failures: Array<{ scope: 'session' | 'workspace'; reason: string }> = [];
    const live = createInteractivePolicyEngine({
      initialMode: 'confirm-bash',
      requestApproval: async () => 'allow-workspace',
      table,
      extendAllow: (subject, scope) =>
        extendApprovalScope(ctx, table, subject, scope, {
          appendPersisted: async () => {
            throw new Error('disk full');
          }
        }),
      onExtendAllowFailure: (failure) => {
        failures.push(failure);
      }
    });
    const decision = await live.engine.decide(bashSubject);
    assert.deepEqual(decision, { behavior: 'allow', decidedBy: 'user' });
    assert.deepEqual(table.allow, []);
    assert.deepEqual(failures, [{ scope: 'workspace', reason: 'disk full' }]);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('createInteractivePolicyEngine allow-turn skips later asks until resetTurn', async () => {
  const table: PermissionTable = { deny: [], allow: [], ask: [] };
  let approvalCalls = 0;
  const live = createInteractivePolicyEngine({
    initialMode: 'confirm-bash',
    requestApproval: async () => {
      approvalCalls += 1;
      return 'allow-turn';
    },
    table,
    extendAllow: async () => ({ ok: true })
  });

  const first = await live.engine.decide(bashSubject);
  assert.deepEqual(first, { behavior: 'allow', decidedBy: 'user' });

  const second = await live.engine.decide(bashSubject);
  assert.deepEqual(second, { behavior: 'allow', decidedBy: 'user' });
  assert.equal(approvalCalls, 1, 'allow-turn must satisfy later asks in the same turn');

  live.resetTurn();
  const third = await live.engine.decide(bashSubject);
  assert.deepEqual(third, { behavior: 'allow', decidedBy: 'user' });
  assert.equal(approvalCalls, 2, 'resetTurn must reopen the approval modal');
});

test('createInteractivePolicyEngine deny returns user denial', async () => {
  const table: PermissionTable = { deny: [], allow: [], ask: [] };
  const live = createInteractivePolicyEngine({
    initialMode: 'confirm-bash',
    requestApproval: async () => 'deny',
    table,
    extendAllow: async () => ({ ok: true })
  });
  const decision = await live.engine.decide(bashSubject);
  assert.equal(decision.behavior, 'deny');
  if (decision.behavior === 'deny') {
    assert.equal(decision.decidedBy, 'user');
    assert.match(decision.reason, /user denied/i);
  }
});

test('createInteractivePolicyEngine one-shot allow does not persist for later asks', async () => {
  const table: PermissionTable = { deny: [], allow: [], ask: [] };
  let approvalCalls = 0;
  const live = createInteractivePolicyEngine({
    initialMode: 'confirm-bash',
    requestApproval: async () => {
      approvalCalls += 1;
      return 'allow';
    },
    table,
    extendAllow: async () => ({ ok: true })
  });
  await live.engine.decide(bashSubject);
  await live.engine.decide(bashSubject);
  assert.equal(approvalCalls, 2, 'plain allow must not auto-approve the next ask');
});

test('createInteractivePolicyEngine rebuilds after successful session extend', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-live-session-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-live-session-home-'));
  try {
    const ctx = await createWorkspaceTrustContext(cwd, home);
    const table: PermissionTable = { deny: [], allow: [], ask: [] };
    let approvalCalls = 0;
    const live = createInteractivePolicyEngine({
      initialMode: 'confirm-bash',
      requestApproval: async () => {
        approvalCalls += 1;
        return 'allow-session';
      },
      table,
      extendAllow: (subject, scope) => extendApprovalScope(ctx, table, subject, scope)
    });
    const first = await live.engine.decide(bashSubject);
    assert.deepEqual(first, { behavior: 'allow', decidedBy: 'user' });
    assert.equal(table.allow.length, 1);

    const second = await live.engine.decide(bashSubject);
    assert.equal(second.behavior, 'allow');
    assert.notEqual(second.decidedBy, 'user');
    assert.equal(approvalCalls, 1, 'session allow rule must satisfy later asks without reopening the modal');
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});
