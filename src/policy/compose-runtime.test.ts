import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { composeRuntimePermissionTable } from './compose-runtime.js';
import { BUILTIN_DENY } from './decision-table.js';
import { writePersistedWorkspacePermissions } from '../session/permissions.js';
import { createWorkspaceTrustContext } from '../session/trust.js';

async function makeCtx() {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-compose-cwd-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-compose-home-'));
  const trustContext = await createWorkspaceTrustContext(cwd, home);
  return {
    trustContext,
    cleanup: async () => {
      await rm(cwd, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
    }
  };
}

test('composeRuntimePermissionTable seeds builtin deny even with no layers', async () => {
  const { trustContext, cleanup } = await makeCtx();
  try {
    const table = await composeRuntimePermissionTable({ trustContext });
    // Builtin deny rules are always present regardless of layers; their
    // exact count is owned by decision-table.ts so we just assert
    // equivalence against BUILTIN_DENY rather than a magic number.
    assert.deepEqual(table.deny, [...BUILTIN_DENY]);
    assert.deepEqual(table.allow, []);
    assert.deepEqual(table.ask, []);
  } finally {
    await cleanup();
  }
});

test('composeRuntimePermissionTable stacks workspace config above builtin deny', async () => {
  const { trustContext, cleanup } = await makeCtx();
  try {
    const table = await composeRuntimePermissionTable({
      trustContext,
      workspaceConfigPermissions: {
        preset: 'confirm-write',
        allow: [{ channel: 'bash', pattern: 'git *', source: 'workspace' }],
        deny: [{ channel: 'fs-write', pattern: '.env', source: 'workspace' }],
        ask: [{ channel: 'fs-write', pattern: 'src/*', source: 'workspace' }]
      }
    });
    assert.equal(table.deny.length, BUILTIN_DENY.length + 1);
    assert.equal(table.deny.at(-1)?.source, 'workspace');
    assert.deepEqual(table.allow, [{ channel: 'bash', pattern: 'git *', source: 'workspace' }]);
    assert.deepEqual(table.ask, [{ channel: 'fs-write', pattern: 'src/*', source: 'workspace' }]);
  } finally {
    await cleanup();
  }
});

test('composeRuntimePermissionTable pulls persisted permissions.json and tags source=persisted', async () => {
  const { trustContext, cleanup } = await makeCtx();
  try {
    await writePersistedWorkspacePermissions(trustContext, {
      allow: [{ channel: 'fs-read', pattern: 'docs/*' }],
      deny: [{ channel: 'fs-write', pattern: 'secrets/*' }]
    });

    const table = await composeRuntimePermissionTable({ trustContext });
    const persistedAllow = table.allow.find((r) => r.source === 'persisted');
    const persistedDeny = table.deny.find((r) => r.source === 'persisted');
    assert.ok(persistedAllow, 'allow layer must surface the persisted rule');
    assert.equal(persistedAllow?.pattern, 'docs/*');
    assert.ok(persistedDeny, 'deny layer must surface the persisted rule');
    assert.equal(persistedDeny?.pattern, 'secrets/*');
  } finally {
    await cleanup();
  }
});

test('composeRuntimePermissionTable layers CLI on top of workspace + persisted', async () => {
  const { trustContext, cleanup } = await makeCtx();
  try {
    await writePersistedWorkspacePermissions(trustContext, {
      allow: [{ channel: 'fs-read', pattern: 'docs/*' }],
      deny: []
    });

    const table = await composeRuntimePermissionTable({
      trustContext,
      workspaceConfigPermissions: {
        allow: [{ channel: 'bash', pattern: 'git *', source: 'workspace' }]
      },
      cliPermissions: {
        allow: [{ channel: 'bash', pattern: 'npm *', source: 'cli' }],
        deny: [],
        ask: []
      }
    });

    const sources = table.allow.map((r) => `${r.source}:${r.channel}:${r.pattern}`);
    // Source labels preserved so PolicyEngine diagnostics can name the layer.
    assert.deepEqual(sources, [
      'workspace:bash:git *',
      'persisted:fs-read:docs/*',
      'cli:bash:npm *'
    ]);
  } finally {
    await cleanup();
  }
});

test('composeRuntimePermissionTable preserves the builtin-deny-wins invariant across layers', async () => {
  const { trustContext, cleanup } = await makeCtx();
  try {
    // Even if every layer tries to allow `bash: rm`, the builtin deny rule
    // (seeded first) wins in the matcher because deny rules are walked in
    // insertion order. We assert layer ordering here; the matcher behavior
    // itself is covered by decision-table.test.ts.
    await writePersistedWorkspacePermissions(trustContext, {
      allow: [{ channel: 'bash', pattern: 'rm' }],
      deny: []
    });

    const table = await composeRuntimePermissionTable({
      trustContext,
      workspaceConfigPermissions: {
        allow: [{ channel: 'bash', pattern: 'rm', source: 'workspace' }]
      },
      cliPermissions: {
        allow: [{ channel: 'bash', pattern: 'rm', source: 'cli' }],
        deny: [],
        ask: []
      }
    });

    assert.equal(table.deny[0]?.source, 'builtin');
    assert.equal(table.deny[0]?.pattern, 'rm');
  } finally {
    await cleanup();
  }
});
