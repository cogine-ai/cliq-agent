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
      initialMode: 'accept-edits',
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

test('createInteractivePolicyEngine rebuilds after successful session extend', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-live-session-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-live-session-home-'));
  try {
    const ctx = await createWorkspaceTrustContext(cwd, home);
    const table: PermissionTable = { deny: [], allow: [], ask: [] };
    let approvalCalls = 0;
    const live = createInteractivePolicyEngine({
      initialMode: 'accept-edits',
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

test('createInteractivePolicyEngine session allow does not bypass unsafe compound bash', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-session-unsafe-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-session-unsafe-home-'));
  try {
    const ctx = await createWorkspaceTrustContext(cwd, home);
    const table: PermissionTable = { deny: [], allow: [], ask: [] };
    const safeSubject = buildToolApprovalSubject({
      definition: { name: 'bash', access: 'exec' },
      action: { bash: 'git status' }
    });
    const unsafeSubject = buildToolApprovalSubject({
      definition: { name: 'bash', access: 'exec' },
      action: { bash: 'git status && rm -rf /' }
    });
    const approvalSubjects: ApprovalSubject[] = [];
    let approvalCalls = 0;
    const live = createInteractivePolicyEngine({
      initialMode: 'accept-edits',
      requestApproval: async (subject) => {
        approvalCalls += 1;
        approvalSubjects.push(subject);
        return approvalCalls === 1 ? 'allow-session' : 'deny';
      },
      table,
      extendAllow: (subject, scope) => extendApprovalScope(ctx, table, subject, scope)
    });

    const first = await live.engine.decide(safeSubject);
    assert.deepEqual(first, { behavior: 'allow', decidedBy: 'user' });
    assert.equal(table.allow.length, 1);
    assert.equal(table.allow[0]?.pattern, 'git');

    const second = await live.engine.decide(safeSubject);
    assert.equal(second.behavior, 'allow');
    assert.notEqual(second.decidedBy, 'user');
    assert.equal(approvalCalls, 1, 'session allow must satisfy later safe git commands without reopening the modal');

    const third = await live.engine.decide(unsafeSubject);
    assert.deepEqual(third, {
      behavior: 'deny',
      reason: 'user denied via TUI approval modal',
      decidedBy: 'user'
    });
    assert.equal(
      approvalCalls,
      2,
      'unsafe compound syntax must reopen approval even when session allow covers the command head'
    );
    assert.equal(approvalSubjects[1], unsafeSubject);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});
