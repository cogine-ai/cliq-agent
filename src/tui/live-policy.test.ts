import * as assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { mock, test } from 'node:test';

import type { PermissionTable } from '../policy/decision-table.js';
import { buildToolApprovalSubject } from '../policy/subjects.js';
import type { ApprovalSubject } from '../policy/types.js';
import { createWorkspaceTrustContext } from '../session/trust.js';
import { extendApprovalScope } from './extend-approval-scope.js';
import { createTuiLivePolicyEngine } from './live-policy.js';

const bashSubject: ApprovalSubject = buildToolApprovalSubject({
  definition: { name: 'bash', access: 'exec' },
  action: { bash: 'npm test' }
});

test('createTuiLivePolicyEngine grants one-shot allow when workspace persist fails', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-live-policy-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-live-policy-home-'));
  const stderrChunks: string[] = [];
  const stderrMock = mock.method(process.stderr, 'write', (chunk: string | Uint8Array) => {
    stderrChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return true;
  });
  try {
    const ctx = await createWorkspaceTrustContext(cwd, home);
    const table: PermissionTable = { deny: [], allow: [], ask: [] };
    let rebuilds = 0;
    const live = createTuiLivePolicyEngine(
      'confirm-bash',
      async () => 'allow-workspace',
      table,
      (subject, scope) =>
        extendApprovalScope(ctx, table, subject, scope, {
          appendPersisted: async () => {
            throw new Error('disk full');
          }
        }),
      () => {
        rebuilds += 1;
      }
    );
    const decision = await live.engine.decide(bashSubject);
    assert.deepEqual(decision, { behavior: 'allow', decidedBy: 'user' });
    assert.deepEqual(table.allow, []);
    assert.equal(rebuilds, 0);
    assert.match(stderrChunks.join(''), /could not extend approval to workspace: disk full/);
  } finally {
    stderrMock.mock.restore();
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('createTuiLivePolicyEngine rebuilds after successful session extend', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-live-session-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-live-session-home-'));
  try {
    const ctx = await createWorkspaceTrustContext(cwd, home);
    const table: PermissionTable = { deny: [], allow: [], ask: [] };
    let rebuilds = 0;
    let approvalCalls = 0;
    const live = createTuiLivePolicyEngine(
      'confirm-bash',
      async () => {
        approvalCalls += 1;
        return 'allow-session';
      },
      table,
      (subject, scope) => extendApprovalScope(ctx, table, subject, scope),
      () => {
        rebuilds += 1;
        live.rebuildForExtendedAllow();
      }
    );
    const first = await live.engine.decide(bashSubject);
    assert.deepEqual(first, { behavior: 'allow', decidedBy: 'user' });
    assert.equal(rebuilds, 1);
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
