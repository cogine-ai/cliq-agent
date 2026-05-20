import * as assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import type { PermissionTable } from '../policy/decision-table.js';
import { buildToolApprovalSubject } from '../policy/subjects.js';
import type { ApprovalSubject } from '../policy/types.js';
import { readPersistedWorkspacePermissions } from '../session/permissions.js';
import { createWorkspaceTrustContext } from '../session/trust.js';
import {
  approvalSubjectToPermissionRule,
  extendApprovalScope
} from './extend-approval-scope.js';

const bashSubject: ApprovalSubject = buildToolApprovalSubject({
  definition: { name: 'bash', access: 'exec' },
  action: { bash: 'git status' }
});

test('approvalSubjectToPermissionRule derives bash rule from command head', () => {
  const rule = approvalSubjectToPermissionRule(bashSubject, 'session');
  assert.deepEqual(rule, { channel: 'bash', pattern: 'git', source: 'session' });
});

test('approvalSubjectToPermissionRule returns null for non-tool subjects', () => {
  const txSubject: ApprovalSubject = {
    kind: 'tx-apply',
    txId: 'tx_1',
    diffSummary: {
      filesChanged: 0,
      additions: 0,
      deletions: 0,
      creates: [],
      modifies: [],
      deletes: []
    },
    validators: [],
    blockingFailures: [],
    artifactRef: 'art_1'
  };
  assert.equal(approvalSubjectToPermissionRule(txSubject, 'session'), null);
});

test('extendApprovalScope session pushes rule without touching disk', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-extend-session-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-extend-home-'));
  try {
    const ctx = await createWorkspaceTrustContext(cwd, home);
    const table: PermissionTable = { deny: [], allow: [], ask: [] };
    const result = await extendApprovalScope(ctx, table, bashSubject, 'session');
    assert.deepEqual(result, { ok: true });
    assert.equal(table.allow.length, 1);
    assert.equal(table.allow[0]?.source, 'session');
    const record = await readPersistedWorkspacePermissions(ctx);
    assert.equal(record, undefined);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('extendApprovalScope workspace persists before mutating in-memory table (PR #91)', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-extend-ws-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-extend-ws-home-'));
  try {
    const ctx = await createWorkspaceTrustContext(cwd, home);
    const table: PermissionTable = { deny: [], allow: [], ask: [] };
    const result = await extendApprovalScope(ctx, table, bashSubject, 'workspace', {
      appendPersisted: async () => {
        throw new Error('EROFS: read-only file system');
      }
    });
    assert.deepEqual(result, { ok: false, reason: 'EROFS: read-only file system' });
    assert.deepEqual(table.allow, [], 'failed workspace persist must not leave in-memory allow');
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('extendApprovalScope workspace success writes disk and pushes rule', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-extend-ws-ok-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-extend-ws-ok-home-'));
  try {
    const ctx = await createWorkspaceTrustContext(cwd, home);
    const table: PermissionTable = { deny: [], allow: [], ask: [] };
    const result = await extendApprovalScope(ctx, table, bashSubject, 'workspace');
    assert.deepEqual(result, { ok: true });
    assert.equal(table.allow.length, 1);
    const record = await readPersistedWorkspacePermissions(ctx);
    assert.ok(record?.allow.some((r) => r.channel === 'bash' && r.pattern === 'git'));
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});
