import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  appendPersistedWorkspacePermission,
  readPersistedWorkspacePermissions,
  WORKSPACE_PERMISSIONS_RECORD_VERSION,
  workspacePermissionsRecordPath,
  writePersistedWorkspacePermissions
} from './permissions.js';
import { createWorkspaceTrustContext } from './trust.js';

async function freshCtx() {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-perm-cwd-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-perm-home-'));
  const ctx = await createWorkspaceTrustContext(cwd, home);
  return {
    ctx,
    cleanup: async () => {
      await rm(cwd, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
    }
  };
}

test('readPersistedWorkspacePermissions returns undefined when no record exists', async () => {
  const { ctx, cleanup } = await freshCtx();
  try {
    assert.equal(await readPersistedWorkspacePermissions(ctx), undefined);
  } finally {
    await cleanup();
  }
});

test('writePersistedWorkspacePermissions round-trips allow/deny rules atomically', async () => {
  const { ctx, cleanup } = await freshCtx();
  try {
    const written = await writePersistedWorkspacePermissions(ctx, {
      allow: [
        { channel: 'bash', pattern: 'git *' },
        { channel: 'fs-read', pattern: 'docs/*' }
      ],
      deny: [{ channel: 'fs-write', pattern: '.env' }]
    });
    assert.equal(written.version, WORKSPACE_PERMISSIONS_RECORD_VERSION);
    assert.equal(written.workspaceId, ctx.workspaceId);
    assert.equal(written.workspaceRealPath, ctx.workspaceRealPath);
    assert.match(written.decidedAt, /^\d{4}-\d{2}-\d{2}T/);

    const read = await readPersistedWorkspacePermissions(ctx);
    assert.deepEqual(read?.allow, [
      { channel: 'bash', pattern: 'git *' },
      { channel: 'fs-read', pattern: 'docs/*' }
    ]);
    assert.deepEqual(read?.deny, [{ channel: 'fs-write', pattern: '.env' }]);

    // File should be valid JSON on disk (atomic-write contract).
    const raw = await readFile(workspacePermissionsRecordPath(ctx), 'utf8');
    assert.doesNotThrow(() => JSON.parse(raw));
  } finally {
    await cleanup();
  }
});

test('readPersistedWorkspacePermissions treats corrupted JSON as absent (fail-closed)', async () => {
  const { ctx, cleanup } = await freshCtx();
  try {
    await writePersistedWorkspacePermissions(ctx, { allow: [], deny: [] });
    await writeFile(workspacePermissionsRecordPath(ctx), '{not json', 'utf8');
    assert.equal(await readPersistedWorkspacePermissions(ctx), undefined);
  } finally {
    await cleanup();
  }
});

async function overwritePermissionsRecordRaw(target: string, contents: string) {
  // Tests reuse this to inject corrupt / schema-mismatched payloads. The
  // first legitimate write below ensures `workspaces/<id>/` exists; the raw
  // overwrite then replaces the file in place so the reader still finds
  // something to parse.
  await writeFile(target, contents);
}

test('readPersistedWorkspacePermissions rejects schema-version mismatch', async () => {
  const { ctx, cleanup } = await freshCtx();
  try {
    await writePersistedWorkspacePermissions(ctx, { allow: [], deny: [] });
    await overwritePermissionsRecordRaw(
      workspacePermissionsRecordPath(ctx),
      JSON.stringify({
        version: 999,
        workspaceId: ctx.workspaceId,
        workspaceRealPath: ctx.workspaceRealPath,
        decidedAt: new Date().toISOString(),
        allow: [],
        deny: []
      })
    );
    assert.equal(await readPersistedWorkspacePermissions(ctx), undefined);
  } finally {
    await cleanup();
  }
});

test('readPersistedWorkspacePermissions rejects workspaceId mismatch', async () => {
  // A file written by another workspace MUST NOT bleed across; the same
  // tampering attack class the trust.json reader guards against.
  const { ctx, cleanup } = await freshCtx();
  try {
    await writePersistedWorkspacePermissions(ctx, { allow: [], deny: [] });
    await overwritePermissionsRecordRaw(
      workspacePermissionsRecordPath(ctx),
      JSON.stringify({
        version: WORKSPACE_PERMISSIONS_RECORD_VERSION,
        workspaceId: 'ws_someone_else',
        workspaceRealPath: ctx.workspaceRealPath,
        decidedAt: new Date().toISOString(),
        allow: [{ channel: 'bash', pattern: '*' }],
        deny: []
      })
    );
    assert.equal(await readPersistedWorkspacePermissions(ctx), undefined);
  } finally {
    await cleanup();
  }
});

test('readPersistedWorkspacePermissions drops rules with unknown channels', async () => {
  const { ctx, cleanup } = await freshCtx();
  try {
    await writePersistedWorkspacePermissions(ctx, { allow: [], deny: [] });
    await overwritePermissionsRecordRaw(
      workspacePermissionsRecordPath(ctx),
      JSON.stringify({
        version: WORKSPACE_PERMISSIONS_RECORD_VERSION,
        workspaceId: ctx.workspaceId,
        workspaceRealPath: ctx.workspaceRealPath,
        decidedAt: new Date().toISOString(),
        allow: [
          { channel: 'bash', pattern: 'npm *' },
          { channel: 'made-up-channel', pattern: '*' },
          { channel: 'fs-read' /* missing pattern */ }
        ],
        deny: []
      })
    );
    const read = await readPersistedWorkspacePermissions(ctx);
    assert.deepEqual(read?.allow, [{ channel: 'bash', pattern: 'npm *' }]);
  } finally {
    await cleanup();
  }
});

test('appendPersistedWorkspacePermission adds rules and dedupes exact matches', async () => {
  const { ctx, cleanup } = await freshCtx();
  try {
    await appendPersistedWorkspacePermission(ctx, 'allow', { channel: 'bash', pattern: 'git *' });
    await appendPersistedWorkspacePermission(ctx, 'allow', { channel: 'bash', pattern: 'git *' });
    await appendPersistedWorkspacePermission(ctx, 'allow', { channel: 'bash', pattern: 'npm *' });
    await appendPersistedWorkspacePermission(ctx, 'deny', { channel: 'fs-write', pattern: '.env' });

    const read = await readPersistedWorkspacePermissions(ctx);
    assert.deepEqual(read?.allow, [
      { channel: 'bash', pattern: 'git *' },
      { channel: 'bash', pattern: 'npm *' }
    ]);
    assert.deepEqual(read?.deny, [{ channel: 'fs-write', pattern: '.env' }]);
  } finally {
    await cleanup();
  }
});
