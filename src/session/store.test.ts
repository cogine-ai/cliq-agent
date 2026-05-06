import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdtemp, mkdir, readdir, readFile, realpath, rm, utimes, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  createSession,
  ensureFresh,
  ensureSession,
  isSessionRecord,
  mutateSession,
  nowIso,
  resolveCliqHome,
  saveSession,
  sessionFilePath,
  sessionPath,
  workspaceIdFromRealPath,
  workspaceStatePath
} from './store.js';
import { applyRecordId, abortRecordId, openRecordId } from '../workspace/transactions/types.js';

let originalCliqHome: string | undefined;
let fileCliqHome: string | undefined;

test.beforeEach(async () => {
  originalCliqHome = process.env.CLIQ_HOME;
  fileCliqHome = await mkdtemp(path.join(os.tmpdir(), 'cliq-store-home-'));
  process.env.CLIQ_HOME = fileCliqHome;
});

test.afterEach(async () => {
  if (originalCliqHome === undefined) {
    delete process.env.CLIQ_HOME;
  } else {
    process.env.CLIQ_HOME = originalCliqHome;
  }
  if (fileCliqHome) {
    await rm(fileCliqHome, { recursive: true, force: true });
  }
  originalCliqHome = undefined;
  fileCliqHome = undefined;
});

test('createSession starts without a seeded system record', () => {
  const session = createSession('/tmp/workspace');
  assert.deepEqual(session.records, []);
  assert.equal(session.cwd, '/tmp/workspace');
});

test('createSession records structured default model identity', () => {
  const session = createSession('/tmp/workspace');
  assert.deepEqual(session.model, {
    provider: 'ollama',
    model: 'auto',
    baseUrl: 'http://localhost:11434'
  });
});

test('resolveCliqHome uses CLIQ_HOME when provided and falls back to ~/.cliq', () => {
  assert.equal(resolveCliqHome({ CLIQ_HOME: '/tmp/custom-cliq' }, '/home/alice'), path.resolve('/tmp/custom-cliq'));
  assert.equal(resolveCliqHome({}, '/home/alice'), path.resolve(path.join('/home/alice', '.cliq')));
});

test('workspaceIdFromRealPath is a stable sha256 hex digest of realpath(cwd)', () => {
  const id = workspaceIdFromRealPath('/tmp/workspace');

  assert.equal(id, workspaceIdFromRealPath('/tmp/workspace'));
  assert.match(id, /^[a-f0-9]{64}$/);
  assert.notEqual(id, workspaceIdFromRealPath('/tmp/other-workspace'));
});

test('ensureSession creates the persisted file in CLIQ_HOME when missing', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-home-'));
  const previousHome = process.env.CLIQ_HOME;

  try {
    process.env.CLIQ_HOME = home;
    const session = await ensureSession(cwd);
    const raw = JSON.parse(await readFile(sessionFilePath(session), 'utf8')) as { records: Array<{ kind: string }> };
    const workspaceState = JSON.parse(await readFile(await workspaceStatePath(cwd), 'utf8')) as { activeSessionId: string };

    assert.equal(session.id.startsWith('sess_'), true);
    assert.deepEqual(session.records, []);
    assert.deepEqual(raw.records, []);
    assert.equal(workspaceState.activeSessionId, session.id);
    await assert.rejects(() => access(sessionPath(cwd)), { code: 'ENOENT' });
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('ensureSession serializes concurrent initial session creation', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-concurrent-'));

  try {
    const sessions = await Promise.all(Array.from({ length: 16 }, () => ensureSession(cwd)));
    const sessionIds = new Set(sessions.map((session) => session.id));
    const workspaceState = JSON.parse(await readFile(await workspaceStatePath(cwd), 'utf8')) as {
      activeSessionId?: string;
      recentSessions?: Array<{ id: string }>;
    };

    assert.equal(sessionIds.size, 1);
    assert.equal(workspaceState.activeSessionId, sessions[0]?.id);
    assert.deepEqual(
      workspaceState.recentSessions?.map((session) => session.id),
      [sessions[0]?.id]
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ensureFresh creates a new active global session without deleting legacy workspace files', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-reset-global-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-home-'));
  const previousHome = process.env.CLIQ_HOME;

  try {
    process.env.CLIQ_HOME = home;
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(path.join(cwd, '.cliq', 'session.json'), JSON.stringify({ records: [] }), 'utf8');

    const first = await ensureSession(cwd);
    const fresh = await ensureFresh(cwd);
    const workspaceState = JSON.parse(await readFile(await workspaceStatePath(cwd), 'utf8')) as { activeSessionId: string };

    assert.notEqual(fresh.id, first.id);
    assert.equal(workspaceState.activeSessionId, fresh.id);
    assert.deepEqual(fresh.records, []);
    assert.equal(JSON.parse(await readFile(path.join(cwd, '.cliq', 'session.json'), 'utf8')).records.length, 0);
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('ensureSession recovers from malformed workspace state JSON', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-state-malformed-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-home-'));
  const previousHome = process.env.CLIQ_HOME;

  try {
    process.env.CLIQ_HOME = home;
    const statePath = await workspaceStatePath(cwd);
    await mkdir(path.dirname(statePath), { recursive: true });
    await writeFile(statePath, JSON.stringify({ recentSessions: 'not-an-array' }), 'utf8');

    const session = await ensureSession(cwd);
    const workspaceState = JSON.parse(await readFile(statePath, 'utf8')) as {
      activeSessionId?: string;
      recentSessions?: unknown[];
    };

    assert.equal(workspaceState.activeSessionId, session.id);
    assert.equal(Array.isArray(workspaceState.recentSessions), true);
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('ensureSession recovers from malformed workspace index JSON', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-index-malformed-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-home-'));
  const previousHome = process.env.CLIQ_HOME;

  try {
    process.env.CLIQ_HOME = home;
    await writeFile(path.join(home, 'workspace-index.json'), JSON.stringify({ workspaces: [] }), 'utf8');

    const session = await ensureSession(cwd);
    const index = JSON.parse(await readFile(path.join(home, 'workspace-index.json'), 'utf8')) as {
      workspaces?: Record<string, { activeSessionId?: string }>;
    };
    const activeSessionIds = Object.values(index.workspaces ?? {}).map((entry) => entry.activeSessionId);

    assert.ok(activeSessionIds.includes(session.id));
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('saveSession recovers from a stale session file lock', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-stale-lock-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-home-'));
  const previousHome = process.env.CLIQ_HOME;

  try {
    process.env.CLIQ_HOME = home;
    const session = createSession(cwd);
    const target = sessionFilePath(session);
    const lockPath = `${target}.lock`;
    await mkdir(lockPath, { recursive: true });
    const stale = new Date(Date.now() - 10_000);
    await utimes(lockPath, stale, stale);

    await saveSession(cwd, session);

    await assert.rejects(() => access(lockPath), { code: 'ENOENT' });
    assert.equal(JSON.parse(await readFile(target, 'utf8')).id, session.id);
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('mutateSession refuses to write after lock ownership is lost', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-lock-owner-'));

  try {
    const session = createSession(cwd);
    const target = sessionFilePath(session);
    const lockPath = `${target}.lock`;
    const otherOwnerPath = path.join(lockPath, 'owner');

    await assert.rejects(
      () =>
        mutateSession(cwd, session, async (current) => {
          await rm(lockPath, { recursive: true, force: true });
          await mkdir(lockPath, { recursive: true });
          await writeFile(otherOwnerPath, 'other-owner', 'utf8');
          current.name = 'mutated';
        }),
      /lost path lock/i
    );

    assert.equal(await readFile(otherOwnerPath, 'utf8'), 'other-owner');
    await rm(lockPath, { recursive: true, force: true });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('mutateSession serializes concurrent updates without losing records', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-lock-concurrent-'));

  try {
    const session = createSession(cwd);
    await saveSession(cwd, session);
    let releaseFirst!: () => void;
    const firstCanFinish = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstStarted!: () => void;
    const firstHasLock = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });

    const first = mutateSession(cwd, session, async (current) => {
      current.records.push({
        id: 'usr_1',
        ts: '2026-04-29T00:00:00.000Z',
        kind: 'user',
        role: 'user',
        content: 'first'
      });
      firstStarted();
      await firstCanFinish;
    });
    await firstHasLock;

    const second = mutateSession(cwd, session, (current) => {
      current.records.push({
        id: 'usr_2',
        ts: '2026-04-29T00:00:01.000Z',
        kind: 'user',
        role: 'user',
        content: 'second'
      });
    });

    releaseFirst();
    await Promise.all([first, second]);

    const persisted = JSON.parse(await readFile(sessionFilePath(session), 'utf8')) as {
      records: Array<{ id: string }>;
    };
    assert.deepEqual(
      persisted.records.map((record) => record.id),
      ['usr_1', 'usr_2']
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ensureSession does not persist normalized active global sessions by default', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-active-normalize-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-home-'));
  const previousHome = process.env.CLIQ_HOME;

  try {
    process.env.CLIQ_HOME = home;
    const session = createSession(cwd);
    const target = sessionFilePath(session);
    const rawSession = {
      ...session,
      version: 3,
      model: 'anthropic/claude-sonnet-4.6'
    };
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, JSON.stringify(rawSession, null, 2), 'utf8');

    const workspaceRealPath = await realpath(cwd);
    const statePath = await workspaceStatePath(cwd);
    await mkdir(path.dirname(statePath), { recursive: true });
    await writeFile(
      statePath,
      JSON.stringify(
        {
          version: 1,
          workspaceId: workspaceIdFromRealPath(workspaceRealPath),
          workspaceRealPath,
          activeSessionId: session.id,
          activeSessionPath: target,
          recentSessions: [],
          lastSeenAt: '2026-04-29T00:00:00.000Z'
        },
        null,
        2
      ),
      'utf8'
    );

    const loaded = await ensureSession(cwd);
    const persisted = JSON.parse(await readFile(target, 'utf8')) as { version: number; model: unknown };

    assert.equal(loaded.version, 5);
    assert.deepEqual(loaded.model, {
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4.6',
      baseUrl: 'https://openrouter.ai/api/v1'
    });
    assert.equal(persisted.version, 3);
    assert.equal(persisted.model, 'anthropic/claude-sonnet-4.6');
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('ensureSession surfaces malformed active global session JSON', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-active-malformed-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-home-'));
  const previousHome = process.env.CLIQ_HOME;

  try {
    process.env.CLIQ_HOME = home;
    const session = createSession(cwd);
    const target = sessionFilePath(session);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, '{"records":', 'utf8');

    const workspaceRealPath = await realpath(cwd);
    const statePath = await workspaceStatePath(cwd);
    await mkdir(path.dirname(statePath), { recursive: true });
    await writeFile(
      statePath,
      JSON.stringify(
        {
          version: 1,
          workspaceId: workspaceIdFromRealPath(workspaceRealPath),
          workspaceRealPath,
          activeSessionId: session.id,
          activeSessionPath: target,
          recentSessions: [],
          lastSeenAt: '2026-04-29T00:00:00.000Z'
        },
        null,
        2
      ),
      'utf8'
    );

    await assert.rejects(() => ensureSession(cwd), /invalid JSON/i);
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('ensureSession migrates legacy tool status when present', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-legacy-'));
  await import('node:fs/promises').then(({ mkdir, writeFile }) =>
    mkdir(path.join(cwd, '.cliq'), { recursive: true }).then(() =>
      writeFile(
        path.join(cwd, '.cliq', 'session.json'),
        JSON.stringify({
          createdAt: '2026-01-01T00:00:00.000Z',
          updatedAt: '2026-01-01T00:00:00.000Z',
          messages: [{ role: 'tool', name: 'bash', status: 'error', content: 'TOOL_RESULT bash ERROR' }]
        })
      )
    )
  );

  const session = await ensureSession(cwd);
  const toolRecord = session.records.find((record) => record.kind === 'tool');

  assert.equal(toolRecord?.kind, 'tool');
  assert.equal(toolRecord?.status, 'error');
});

test('ensureSession strips the legacy seeded system prompt during migration', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-migrate-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'session.json'),
      JSON.stringify({
        version: 2,
        app: 'cliq',
        model: 'anthropic/claude-sonnet-4.6',
        cwd,
        createdAt: '2026-04-01T00:00:00.000Z',
        updatedAt: '2026-04-01T00:00:00.000Z',
        lifecycle: { status: 'idle', turn: 0 },
        records: [
          {
            id: 'sys_1',
            ts: '2026-04-01T00:00:00.000Z',
            kind: 'system',
            role: 'system',
            content: 'old legacy seeded prompt literal'
          }
        ]
      }),
      'utf8'
    );

    const session = await ensureSession(cwd);
    assert.deepEqual(session.records, []);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ensureSession preserves non-system records when stripping the legacy seeded prompt', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-migrate-preserve-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'session.json'),
      JSON.stringify({
        version: 2,
        app: 'cliq',
        model: 'anthropic/claude-sonnet-4.6',
        cwd,
        createdAt: '2026-04-01T00:00:00.000Z',
        updatedAt: '2026-04-01T00:00:00.000Z',
        lifecycle: { status: 'idle', turn: 2 },
        records: [
          {
            id: 'sys_1',
            ts: '2026-04-01T00:00:00.000Z',
            kind: 'system',
            role: 'system',
            content: 'old legacy seeded prompt literal'
          },
          {
            id: 'usr_1',
            ts: '2026-04-01T00:00:01.000Z',
            kind: 'user',
            role: 'user',
            content: 'inspect the repo'
          },
          {
            id: 'ast_1',
            ts: '2026-04-01T00:00:02.000Z',
            kind: 'assistant',
            role: 'assistant',
            content: '{"message":"done"}',
            action: { message: 'done' }
          }
        ]
      }),
      'utf8'
    );

    const session = await ensureSession(cwd);
    assert.deepEqual(
      session.records.map((record) => record.kind),
      ['user', 'assistant']
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ensureSession rejects malformed sessions and recreates a valid session', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-malformed-'));
  await import('node:fs/promises').then(({ mkdir, writeFile }) =>
    mkdir(path.join(cwd, '.cliq'), { recursive: true }).then(() =>
      writeFile(path.join(cwd, '.cliq', 'session.json'), JSON.stringify({ records: [] }))
    )
  );

  const session = await ensureSession(cwd);

  assert.equal(session.version > 0, true);
  assert.equal(Array.isArray(session.records), true);
  assert.deepEqual(session.records, []);
});

test('ensureSession propagates legacy migration errors after a valid read', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-legacy-invalid-'));

  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(path.join(cwd, '.cliq', 'session.json'), JSON.stringify({ messages: {} }), 'utf8');

    await assert.rejects(() => ensureSession(cwd), /invalid legacy session: messages must be an array/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ensureSession backs up malformed legacy session JSON before starting fresh', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-legacy-corrupt-'));
  const legacyDir = path.join(cwd, '.cliq');
  const legacyPath = path.join(legacyDir, 'session.json');
  const stderrWrite = process.stderr.write;
  let stderr = '';

  process.stderr.write = ((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  }) as typeof process.stderr.write;

  try {
    await mkdir(legacyDir, { recursive: true });
    await writeFile(legacyPath, '{"records":', 'utf8');

    const session = await ensureSession(cwd);
    const legacyFiles = await readdir(legacyDir);

    assert.equal(session.records.length, 0);
    assert.equal(legacyFiles.some((file) => /^session\.corrupt-.+\.json$/.test(file)), true);
    assert.match(stderr, /legacy session JSON is malformed/i);
  } finally {
    process.stderr.write = stderrWrite;
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ensureSession keeps explicit system records for version 4 sessions', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-current-system-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'session.json'),
      JSON.stringify({
        version: 4,
        app: 'cliq',
        model: {
          provider: 'openrouter',
          model: 'anthropic/claude-sonnet-4.6',
          baseUrl: 'https://openrouter.ai/api/v1'
        },
        cwd,
        createdAt: '2026-04-01T00:00:00.000Z',
        updatedAt: '2026-04-01T00:00:00.000Z',
        lifecycle: { status: 'idle', turn: 1 },
        records: [
          {
            id: 'sys_1',
            ts: '2026-04-01T00:00:00.000Z',
            kind: 'system',
            role: 'system',
            content: 'explicit current-version system record'
          }
        ]
      }),
      'utf8'
    );

    const session = await ensureSession(cwd);
    assert.equal(session.records[0]?.kind, 'system');
    assert.equal(session.records[0]?.content, 'explicit current-version system record');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ensureSession migrates v3 string model to structured model ref', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-model-migrate-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'session.json'),
      JSON.stringify({
        version: 3,
        app: 'cliq',
        model: 'anthropic/claude-sonnet-4.6',
        cwd,
        createdAt: '2026-04-01T00:00:00.000Z',
        updatedAt: '2026-04-01T00:00:00.000Z',
        lifecycle: { status: 'idle', turn: 0 },
        records: []
      }),
      'utf8'
    );

    const session = await ensureSession(cwd);
    assert.equal(session.version, 5);
    assert.deepEqual(session.model, {
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4.6',
      baseUrl: 'https://openrouter.ai/api/v1'
    });

    const persisted = JSON.parse(await readFile(sessionFilePath(session), 'utf8')) as {
      version: number;
      model: unknown;
    };
    assert.equal(persisted.version, 5);
    assert.deepEqual(persisted.model, {
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4.6',
      baseUrl: 'https://openrouter.ai/api/v1'
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('isSessionRecord accepts tx-applied records', () => {
  const record = {
    id: applyRecordId('tx_01H'),
    ts: nowIso(),
    kind: 'tx-applied' as const,
    role: 'user' as const,
    content: 'Transaction tx_01H applied: 1 file changed (+1 -0)',
    meta: {
      txId: 'tx_01H',
      txKind: 'edit' as const,
      diffSummary: { filesChanged: 1, additions: 1, deletions: 0, creates: [], modifies: ['a.ts'], deletes: [] },
      files: { creates: [], modifies: ['a.ts'], deletes: [] },
      validators: { blocking: { pass: 1, fail: 0 }, advisory: { pass: 0, fail: 0, names: [] } },
      overrides: [],
      artifactRef: 'tx/tx_01H/'
    }
  };
  assert.equal(isSessionRecord(record), true);
});

test('isSessionRecord accepts tx-opened records', () => {
  const record = {
    id: openRecordId('tx_02H'),
    ts: nowIso(),
    kind: 'tx-opened' as const,
    role: 'user' as const,
    content: 'Transaction tx_02H opened (explicit)',
    meta: { txId: 'tx_02H', txKind: 'edit' as const, name: 'refactor', explicit: true as const }
  };
  assert.equal(isSessionRecord(record), true);
});

test('isSessionRecord accepts tx-aborted records', () => {
  const record = {
    id: abortRecordId('tx_03H'),
    ts: nowIso(),
    kind: 'tx-aborted' as const,
    role: 'user' as const,
    content: 'Transaction tx_03H aborted: validator-fail',
    meta: {
      txId: 'tx_03H',
      txKind: 'edit' as const,
      reason: 'validator-fail' as const,
      files: { wouldHaveCreated: [], wouldHaveModified: [], wouldHaveDeleted: [] },
      artifactRef: 'tx/tx_03H/'
    }
  };
  assert.equal(isSessionRecord(record), true);
});

test('Session type permits activeTxId field', () => {
  const session = createSession('/tmp/cliq-tx-types-active');
  assert.equal((session as { activeTxId?: string }).activeTxId, undefined);
});
