import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  APP_DIR,
  DEFAULT_MODEL_BASE_URL,
  DEFAULT_MODEL_PROVIDER,
  MODEL,
  OLLAMA_DEFAULT_BASE_URL,
  SESSION_FILE,
  SESSION_VERSION
} from '../config.js';
import { isProviderName } from '../model/registry.js';
import type { CompactionArtifact, Session, SessionCheckpoint, SessionModelRef, SessionRecord } from './types.js';

const execFileAsync = promisify(execFile);
const GLOBAL_STATE_VERSION = 1;
const LOCK_OWNER_FILE = 'owner';

type LegacySession = {
  createdAt?: string;
  updatedAt?: string;
  messages?: Array<{ role?: string; content?: string | null; name?: string; status?: 'ok' | 'error' }>;
};

type WorkspaceSessionRef = {
  id: string;
  path: string;
  createdAt: string;
  updatedAt: string;
};

type WorkspaceState = {
  version: 1;
  workspaceId: string;
  workspaceRealPath: string;
  gitRootRealPath?: string;
  activeSessionId?: string;
  activeSessionPath?: string;
  recentSessions: WorkspaceSessionRef[];
  migratedFrom?: {
    path: string;
    migratedAt: string;
  };
  lastSeenAt: string;
};

type WorkspaceIndex = {
  version: 1;
  workspaces: Record<
    string,
    {
      workspaceId: string;
      workspaceRealPath: string;
      gitRootRealPath?: string;
      activeSessionId?: string;
      activeSessionPath?: string;
      lastSeenAt: string;
    }
  >;
};

type WorkspaceIdentity = {
  workspaceId: string;
  workspaceRealPath: string;
  gitRootRealPath?: string;
};

type WorkspaceIndexEntry = WorkspaceIndex['workspaces'][string];
type SessionMutator<T> = (session: Session) => T | Promise<T>;
type PathLock = {
  assertCurrentOwner: () => Promise<void>;
};
type ReadJsonOptions = {
  tolerateSyntaxError?: boolean;
};

const LOCK_TIMEOUT_MS = 5000;
const LOCK_RETRY_MS = 25;
const LOCK_HEARTBEAT_MS = Math.max(LOCK_RETRY_MS, Math.floor(LOCK_TIMEOUT_MS / 3));

function isSessionRecord(value: unknown): value is SessionRecord {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const record = value as SessionRecord;
  if (typeof record.id !== 'string' || typeof record.ts !== 'string' || typeof record.kind !== 'string' || typeof record.role !== 'string') {
    return false;
  }

  if (record.kind === 'system' || record.kind === 'user') {
    return typeof record.content === 'string';
  }

  if (record.kind === 'assistant') {
    return record.role === 'assistant' && typeof record.content === 'string' && 'action' in record;
  }

  if (record.kind === 'tool') {
    return (
      record.role === 'user' &&
      typeof record.tool === 'string' &&
      (record.status === 'ok' || record.status === 'error') &&
      typeof record.content === 'string'
    );
  }

  return false;
}

function isSessionCheckpoint(value: unknown): value is SessionCheckpoint {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const checkpoint = value as SessionCheckpoint;
  return (
    typeof checkpoint.id === 'string' &&
    (checkpoint.name === undefined || typeof checkpoint.name === 'string') &&
    (checkpoint.kind === 'auto' ||
      checkpoint.kind === 'manual' ||
      checkpoint.kind === 'restore-safety' ||
      checkpoint.kind === 'handoff') &&
    typeof checkpoint.createdAt === 'string' &&
    typeof checkpoint.recordIndex === 'number' &&
    typeof checkpoint.turn === 'number' &&
    (checkpoint.workspaceCheckpointId === undefined || typeof checkpoint.workspaceCheckpointId === 'string')
  );
}

function isCompactionArtifact(value: unknown): value is CompactionArtifact {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const artifact = value as CompactionArtifact;
  return (
    typeof artifact.id === 'string' &&
    (artifact.status === 'active' || artifact.status === 'superseded') &&
    typeof artifact.createdAt === 'string' &&
    !!artifact.coveredRange &&
    typeof artifact.coveredRange === 'object' &&
    typeof artifact.coveredRange.startIndexInclusive === 'number' &&
    typeof artifact.coveredRange.endIndexExclusive === 'number' &&
    typeof artifact.firstKeptRecordId === 'string' &&
    (artifact.anchorCheckpointId === undefined || typeof artifact.anchorCheckpointId === 'string') &&
    !!artifact.createdBy &&
    typeof artifact.createdBy === 'object' &&
    typeof artifact.createdBy.provider === 'string' &&
    isProviderName(artifact.createdBy.provider) &&
    typeof artifact.createdBy.model === 'string' &&
    typeof artifact.summaryMarkdown === 'string'
  );
}

function defaultSessionModel(): SessionModelRef {
  return {
    provider: 'ollama',
    model: 'auto',
    baseUrl: OLLAMA_DEFAULT_BASE_URL
  };
}

function isSessionModelLike(value: unknown): value is string | SessionModelRef {
  if (typeof value === 'string') {
    return true;
  }

  const model = value as { provider?: unknown; model?: unknown; baseUrl?: unknown };
  return (
    !!value &&
    typeof value === 'object' &&
    typeof model.provider === 'string' &&
    isProviderName(model.provider) &&
    typeof model.model === 'string' &&
    (model.baseUrl === undefined || typeof model.baseUrl === 'string')
  );
}

function normalizeSessionModel(value: unknown): SessionModelRef {
  if (typeof value === 'string') {
    return {
      provider: DEFAULT_MODEL_PROVIDER,
      model: value,
      baseUrl: DEFAULT_MODEL_BASE_URL
    };
  }

  if (isSessionModelLike(value) && typeof value !== 'string') {
    return value;
  }

  return defaultSessionModel();
}

export function sessionPath(cwd: string) {
  return path.join(cwd, APP_DIR, SESSION_FILE);
}

export function resolveCliqHome(env: Record<string, string | undefined> = process.env, homeDir = os.homedir()) {
  const configured = env.CLIQ_HOME?.trim();
  return path.resolve(configured ? configured : path.join(homeDir, '.cliq'));
}

export function workspaceIdFromRealPath(realPath: string) {
  return crypto.createHash('sha256').update(realPath).digest('hex');
}

async function detectGitRoot(cwd: string) {
  try {
    const { stdout } = await execFileAsync('git', ['rev-parse', '--show-toplevel'], { cwd });
    const root = stdout.trim();
    return root ? await fs.realpath(root) : undefined;
  } catch {
    return undefined;
  }
}

async function resolveWorkspaceIdentity(cwd: string): Promise<WorkspaceIdentity> {
  const workspaceRealPath = await fs.realpath(cwd);
  const workspaceStat = await fs.stat(workspaceRealPath);
  if (!workspaceStat.isDirectory()) {
    throw new Error(`workspace path is not a directory: ${workspaceRealPath}`);
  }
  return {
    workspaceId: workspaceIdFromRealPath(workspaceRealPath),
    workspaceRealPath,
    gitRootRealPath: await detectGitRoot(workspaceRealPath)
  };
}

export async function workspaceStatePath(cwd: string, cliqHome = resolveCliqHome()) {
  const identity = await resolveWorkspaceIdentity(cwd);
  return path.join(cliqHome, 'workspaces', identity.workspaceId, 'state.json');
}

function sessionDateParts(session: Session) {
  const date = new Date(session.createdAt);
  const safeDate = Number.isNaN(date.getTime()) ? new Date() : date;
  return [
    String(safeDate.getUTCFullYear()),
    String(safeDate.getUTCMonth() + 1).padStart(2, '0'),
    String(safeDate.getUTCDate()).padStart(2, '0')
  ];
}

export function sessionFilePath(session: Session, cliqHome = resolveCliqHome()) {
  const [year, month, day] = sessionDateParts(session);
  return path.join(cliqHome, 'sessions', year, month, day, `${session.id}.json`);
}

export function makeId(prefix: string) {
  return `${prefix}_${crypto.randomUUID()}`;
}

export function nowIso() {
  return new Date().toISOString();
}

function sleep(ms: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function workspaceStateLockPath(cliqHome = resolveCliqHome()) {
  return path.join(cliqHome, 'workspace-state');
}

async function withPathLock<T>(target: string, callback: (lock: PathLock) => Promise<T>): Promise<T> {
  const lockPath = `${target}.lock`;
  const ownerToken = `${process.pid}:${crypto.randomUUID()}`;
  const startedAt = Date.now();
  await fs.mkdir(path.dirname(lockPath), { recursive: true });

  while (true) {
    try {
      await fs.mkdir(lockPath);
      try {
        await writeLockOwner(lockPath, ownerToken);
      } catch (error) {
        await fs.rm(lockPath, { recursive: true, force: true });
        throw error;
      }
      break;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'EEXIST') {
        throw error;
      }
      if (await removeStaleLock(lockPath)) {
        continue;
      }
      if (Date.now() - startedAt > LOCK_TIMEOUT_MS) {
        throw new Error(`timed out waiting for session store lock: ${lockPath}`);
      }
      await sleep(LOCK_RETRY_MS);
    }
  }

  const heartbeat = startLockHeartbeat(lockPath, ownerToken);
  const lock: PathLock = {
    assertCurrentOwner: async () => {
      await assertPathLockOwner(lockPath, ownerToken);
    }
  };
  try {
    return await callback(lock);
  } finally {
    clearInterval(heartbeat);
    await releasePathLock(lockPath, ownerToken);
  }
}

async function writeLockOwner(lockPath: string, ownerToken: string) {
  await fs.writeFile(path.join(lockPath, LOCK_OWNER_FILE), ownerToken, { flag: 'wx' });
}

function startLockHeartbeat(lockPath: string, ownerToken: string) {
  const heartbeat = setInterval(() => {
    void refreshLockLease(lockPath, ownerToken).catch(() => {
      // The next lock waiter will decide whether the lease is stale. Heartbeat
      // failures should not mask the protected store operation.
    });
  }, LOCK_HEARTBEAT_MS);
  heartbeat.unref?.();
  return heartbeat;
}

async function refreshLockLease(lockPath: string, ownerToken: string) {
  const ownerPath = path.join(lockPath, LOCK_OWNER_FILE);
  let handle: Awaited<ReturnType<typeof fs.open>> | undefined;
  try {
    handle = await fs.open(ownerPath, 'r+');
    const currentOwner = await handle.readFile({ encoding: 'utf8' });
    if (currentOwner !== ownerToken) {
      return false;
    }
    const now = new Date();
    await handle.utimes(now, now);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return false;
    }
    throw error;
  } finally {
    await handle?.close();
  }
}

async function releasePathLock(lockPath: string, ownerToken: string) {
  const currentOwner = await readLockOwner(lockPath);
  if (currentOwner !== ownerToken) {
    return;
  }
  await fs.rm(lockPath, { recursive: true, force: true });
}

async function assertPathLockOwner(lockPath: string, ownerToken: string) {
  const currentOwner = await readLockOwner(lockPath);
  if (currentOwner !== ownerToken) {
    throw new Error(`lost session store lock: ${lockPath}`);
  }
  if (!(await refreshLockLease(lockPath, ownerToken))) {
    throw new Error(`lost session store lock: ${lockPath}`);
  }
}

async function readLockOwner(lockPath: string) {
  try {
    return await fs.readFile(path.join(lockPath, LOCK_OWNER_FILE), 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function removeStaleLock(lockPath: string) {
  try {
    const ownerPath = path.join(lockPath, LOCK_OWNER_FILE);
    const owner = await readLockOwner(lockPath);
    const leaseStat = owner === null ? await fs.stat(lockPath) : await fs.stat(ownerPath);
    if (Date.now() - leaseStat.mtimeMs <= LOCK_TIMEOUT_MS) {
      return false;
    }
    await fs.rm(lockPath, { recursive: true, force: true });
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return true;
    }
    throw error;
  }
}

async function atomicWriteFile(target: string, content: string, beforeRename?: () => Promise<void>) {
  await fs.mkdir(path.dirname(target), { recursive: true });
  const temp = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  try {
    await fs.writeFile(temp, content);
    await beforeRename?.();
    await fs.rename(temp, target);
  } catch (error) {
    await fs.rm(temp, { force: true });
    throw error;
  }
}

async function atomicWriteJson(target: string, value: unknown, beforeRename?: () => Promise<void>) {
  await atomicWriteFile(target, JSON.stringify(value, null, 2), beforeRename);
}

export function createSession(cwd: string): Session {
  const now = nowIso();
  return {
    version: SESSION_VERSION,
    app: 'cliq',
    id: makeId('sess'),
    model: defaultSessionModel(),
    cwd,
    createdAt: now,
    updatedAt: now,
    lifecycle: { status: 'idle', turn: 0 },
    records: [],
    checkpoints: [],
    compactions: []
  };
}

function isSession(value: unknown): value is Session {
  return (
    !!value &&
    typeof value === 'object' &&
    (typeof (value as { id?: unknown }).id === 'string' || (value as { id?: unknown }).id === undefined) &&
    typeof (value as Session).version === 'number' &&
    (value as Session).app === 'cliq' &&
    isSessionModelLike((value as { model?: unknown }).model) &&
    typeof (value as Session).cwd === 'string' &&
    typeof (value as Session).createdAt === 'string' &&
    typeof (value as Session).updatedAt === 'string' &&
    !!(value as Session).lifecycle &&
    typeof (value as Session).lifecycle === 'object' &&
    ((value as Session).lifecycle.status === 'idle' || (value as Session).lifecycle.status === 'running') &&
    typeof (value as Session).lifecycle.turn === 'number' &&
    Array.isArray((value as Session).records) &&
    (value as Session).records.every((record) => isSessionRecord(record)) &&
    ((value as { checkpoints?: unknown }).checkpoints === undefined ||
      (Array.isArray((value as { checkpoints?: unknown }).checkpoints) &&
        (value as { checkpoints: unknown[] }).checkpoints.every((checkpoint) => isSessionCheckpoint(checkpoint)))) &&
    ((value as { compactions?: unknown }).compactions === undefined ||
      (Array.isArray((value as { compactions?: unknown }).compactions) &&
        (value as { compactions: unknown[] }).compactions.every((artifact) => isCompactionArtifact(artifact))))
  );
}

function stripSeededSystemPrompt(records: SessionRecord[], sourceVersion = 0) {
  if (sourceVersion > 2) {
    return records;
  }

  return records.filter((record, index) => {
    return !(
      index === 0 &&
      record.kind === 'system' &&
      record.role === 'system'
    );
  });
}

function normalizeSession(session: Session): Session {
  const records = stripSeededSystemPrompt(session.records, session.version);
  const version = Math.max(session.version, SESSION_VERSION);
  const rawModel = (session as { model: unknown }).model;
  const model = normalizeSessionModel(rawModel);
  const modelChanged = model !== rawModel;
  const id = typeof (session as { id?: unknown }).id === 'string' ? (session as { id: string }).id : makeId('sess');
  const checkpoints = Array.isArray((session as { checkpoints?: unknown }).checkpoints)
    ? session.checkpoints
    : [];
  const compactions = Array.isArray((session as { compactions?: unknown }).compactions)
    ? session.compactions
    : [];

  if (
    id === session.id &&
    version === session.version &&
    records.length === session.records.length &&
    checkpoints === session.checkpoints &&
    compactions === session.compactions &&
    !modelChanged
  ) {
    return session;
  }

  return {
    ...session,
    id,
    version,
    model,
    records,
    checkpoints,
    compactions
  };
}

function isWorkspaceSessionRef(value: unknown): value is WorkspaceSessionRef {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const ref = value as WorkspaceSessionRef;
  return (
    typeof ref.id === 'string' &&
    typeof ref.path === 'string' &&
    typeof ref.createdAt === 'string' &&
    typeof ref.updatedAt === 'string'
  );
}

function isWorkspaceIndexEntry(value: unknown): value is WorkspaceIndexEntry {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const entry = value as WorkspaceIndexEntry;
  return (
    typeof entry.workspaceId === 'string' &&
    typeof entry.workspaceRealPath === 'string' &&
    (entry.gitRootRealPath === undefined || typeof entry.gitRootRealPath === 'string') &&
    (entry.activeSessionId === undefined || typeof entry.activeSessionId === 'string') &&
    (entry.activeSessionPath === undefined || typeof entry.activeSessionPath === 'string') &&
    typeof entry.lastSeenAt === 'string'
  );
}

function normalizeWorkspaceState(value: unknown, identity: WorkspaceIdentity): WorkspaceState {
  const fallback = emptyWorkspaceState(identity);
  if (!value || typeof value !== 'object') {
    return fallback;
  }

  const state = value as Partial<WorkspaceState>;
  if (
    state.version !== GLOBAL_STATE_VERSION ||
    state.workspaceId !== identity.workspaceId ||
    state.workspaceRealPath !== identity.workspaceRealPath
  ) {
    return fallback;
  }

  const recentSessions = Array.isArray(state.recentSessions)
    ? state.recentSessions.filter((entry) => isWorkspaceSessionRef(entry))
    : [];
  const migratedFrom =
    state.migratedFrom &&
    typeof state.migratedFrom === 'object' &&
    typeof state.migratedFrom.path === 'string' &&
    typeof state.migratedFrom.migratedAt === 'string'
      ? state.migratedFrom
      : undefined;

  return {
    version: GLOBAL_STATE_VERSION,
    workspaceId: identity.workspaceId,
    workspaceRealPath: identity.workspaceRealPath,
    gitRootRealPath: identity.gitRootRealPath,
    activeSessionId: typeof state.activeSessionId === 'string' ? state.activeSessionId : undefined,
    activeSessionPath: typeof state.activeSessionPath === 'string' ? state.activeSessionPath : undefined,
    recentSessions,
    migratedFrom,
    lastSeenAt: typeof state.lastSeenAt === 'string' ? state.lastSeenAt : nowIso()
  };
}

function normalizeWorkspaceIndex(value: unknown): WorkspaceIndex {
  if (!value || typeof value !== 'object') {
    return emptyWorkspaceIndex();
  }

  const rawWorkspaces = (value as { workspaces?: unknown }).workspaces;
  if (!rawWorkspaces || typeof rawWorkspaces !== 'object' || Array.isArray(rawWorkspaces)) {
    return emptyWorkspaceIndex();
  }

  const workspaces: WorkspaceIndex['workspaces'] = {};
  for (const [workspaceId, entry] of Object.entries(rawWorkspaces)) {
    if (isWorkspaceIndexEntry(entry) && entry.workspaceId === workspaceId) {
      workspaces[workspaceId] = entry;
    }
  }

  return {
    version: GLOBAL_STATE_VERSION,
    workspaces
  };
}

async function readSessionForMutation(target: string, fallback: Session) {
  const raw = await readJson<unknown>(target);
  if (!isSession(raw)) {
    return fallback;
  }

  const normalized = normalizeSession(raw);
  return normalized.id === fallback.id ? normalized : fallback;
}

function replaceSessionContents(target: Session, source: Session) {
  if (target === source) {
    return;
  }
  // Mutate the existing Session object so callers that keep a reference observe
  // the saved state after a locked read-modify-write. This is a runtime
  // identity guarantee only; TypeScript cannot enforce it, so keep the
  // delete-and-assign shape unless all callers stop relying on object identity.
  const mutableTarget = target as unknown as Record<string, unknown>;
  for (const key of Object.keys(mutableTarget)) {
    delete mutableTarget[key];
  }
  Object.assign(target, source);
}

function migrateLegacySession(cwd: string, legacy: LegacySession): Session {
  const session = createSession(cwd);
  session.createdAt = legacy.createdAt ?? session.createdAt;
  session.updatedAt = legacy.updatedAt ?? session.updatedAt;
  session.records = [];

  const messages = legacy.messages ?? [];
  if (!Array.isArray(messages)) {
    throw new Error('invalid legacy session: messages must be an array');
  }

  for (const message of messages) {
    const ts = nowIso();
    if (message.role === 'system' && typeof message.content === 'string') {
      session.records.push({ id: makeId('sys'), ts, kind: 'system', role: 'system', content: message.content });
    } else if (message.role === 'user' && typeof message.content === 'string') {
      session.records.push({ id: makeId('usr'), ts, kind: 'user', role: 'user', content: message.content });
    } else if (message.role === 'assistant') {
      session.records.push({
        id: makeId('ast'),
        ts,
        kind: 'assistant',
        role: 'assistant',
        content: message.content ?? '',
        action: null
      });
    } else if (message.role === 'tool') {
      session.records.push({
        id: makeId('tool'),
        ts,
        kind: 'tool',
        role: 'user',
        tool: message.name === 'edit' ? 'edit' : 'bash',
        // Older sessions may not store tool status, so default only when absent.
        status: message.status ?? 'ok',
        content: message.content ?? ''
      });
    }
  }
  session.records = stripSeededSystemPrompt(session.records);
  return session;
}

export async function saveSession(cwd: string, session: Session) {
  if (!session.id) {
    session.id = makeId('sess');
  }
  const target = sessionFilePath(session);
  await withPathLock(target, async (lock) => {
    await saveSessionUnlocked(cwd, session, target, lock.assertCurrentOwner);
  });
}

async function saveSessionUnlocked(
  cwd: string,
  session: Session,
  target = sessionFilePath(session),
  beforeSessionWrite?: () => Promise<void>
) {
  session.updatedAt = nowIso();
  await atomicWriteJson(target, session, beforeSessionWrite);
  await recordWorkspaceSession(cwd, session, target);
}

export async function mutateSession<T>(cwd: string, session: Session, mutator: SessionMutator<T>): Promise<T> {
  if (!session.id) {
    session.id = makeId('sess');
  }
  const target = sessionFilePath(session);
  return await withPathLock(target, async (lock) => {
    const current = await readSessionForMutation(target, session);
    const result = await mutator(current);
    await saveSessionUnlocked(cwd, current, target, lock.assertCurrentOwner);
    replaceSessionContents(session, current);
    return result;
  });
}

export async function appendRecord(cwd: string, session: Session, record: SessionRecord) {
  session.records.push(record);
  await saveSession(cwd, session);
}

export async function ensureSession(cwd: string): Promise<Session> {
  const cliqHome = resolveCliqHome();
  return await withPathLock(workspaceStateLockPath(cliqHome), async (lock) => {
    const state = await loadWorkspaceState(cwd);
    if (state?.activeSessionPath) {
      const active = await loadSessionFromPath(state.activeSessionPath);
      if (active) {
        return active;
      }
    }

    const legacyTarget = sessionPath(cwd);
    let raw: unknown;
    try {
      raw = JSON.parse(await fs.readFile(legacyTarget, 'utf8')) as unknown;
    } catch (error) {
      if (error instanceof SyntaxError) {
        await backupMalformedLegacySession(legacyTarget, error);
      } else if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw error;
      }
      const session = createSession(cwd);
      await writeSessionAndRecordWorkspaceUnlocked(cwd, session, lock.assertCurrentOwner, undefined, cliqHome);
      return session;
    }

    const session = isSession(raw) ? normalizeSession(raw) : migrateLegacySession(cwd, raw as LegacySession);
    await writeSessionAndRecordWorkspaceUnlocked(
      cwd,
      session,
      lock.assertCurrentOwner,
      migrationMarker(legacyTarget),
      cliqHome
    );
    return session;
  });
}

export async function ensureFresh(cwd: string): Promise<Session> {
  const session = createSession(cwd);
  await saveSession(cwd, session);
  return session;
}

async function backupMalformedLegacySession(target: string, error: SyntaxError) {
  const backupPath = path.join(
    path.dirname(target),
    `session.corrupt-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
  );
  await fs.rename(target, backupPath);
  process.stderr.write(
    `[session warning] legacy session JSON is malformed; moved it to ${backupPath}: ${error.message}\n`
  );
}

async function readJson<T>(target: string, options: ReadJsonOptions = {}): Promise<T | null> {
  try {
    return JSON.parse(await fs.readFile(target, 'utf8')) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    if (error instanceof SyntaxError && options.tolerateSyntaxError) {
      return null;
    }
    if (error instanceof SyntaxError) {
      throw new Error(`invalid JSON in ${target}: ${error.message}`, { cause: error });
    }
    throw error;
  }
}

async function readRecoverableJson<T>(target: string): Promise<T | null> {
  try {
    return await readJson<T>(target, { tolerateSyntaxError: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function readSessionJson<T>(target: string): Promise<T | null> {
  try {
    return await readJson<T>(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

function emptyWorkspaceIndex(): WorkspaceIndex {
  return {
    version: GLOBAL_STATE_VERSION,
    workspaces: {}
  };
}

function emptyWorkspaceState(identity: WorkspaceIdentity): WorkspaceState {
  return {
    version: GLOBAL_STATE_VERSION,
    workspaceId: identity.workspaceId,
    workspaceRealPath: identity.workspaceRealPath,
    gitRootRealPath: identity.gitRootRealPath,
    recentSessions: [],
    lastSeenAt: nowIso()
  };
}

async function loadWorkspaceState(cwd: string) {
  const identity = await resolveWorkspaceIdentity(cwd);
  const target = await workspaceStatePath(cwd);
  return normalizeWorkspaceState(await readRecoverableJson<unknown>(target), identity);
}

async function loadSessionFromPath(target: string): Promise<Session | null> {
  const raw = await readSessionJson<unknown>(target);
  if (!isSession(raw)) {
    return null;
  }

  const normalized = normalizeSession(raw);
  return normalized;
}

function migrationMarker(migratedFromPath: string): WorkspaceState['migratedFrom'] {
  return {
    path: migratedFromPath,
    migratedAt: nowIso()
  };
}

async function writeSessionAndRecordWorkspaceUnlocked(
  cwd: string,
  session: Session,
  assertCurrentOwner: () => Promise<void>,
  migratedFrom?: WorkspaceState['migratedFrom'],
  cliqHome = resolveCliqHome()
) {
  if (!session.id) {
    session.id = makeId('sess');
  }
  session.updatedAt = nowIso();
  const target = sessionFilePath(session, cliqHome);
  await atomicWriteJson(target, session, assertCurrentOwner);
  await recordWorkspaceSessionUnlocked(cwd, session, target, assertCurrentOwner, migratedFrom, cliqHome);
}

async function recordWorkspaceSession(
  cwd: string,
  session: Session,
  sessionFile: string,
  migratedFrom?: WorkspaceState['migratedFrom']
) {
  const cliqHome = resolveCliqHome();
  const lockPath = workspaceStateLockPath(cliqHome);

  await withPathLock(lockPath, async (lock) => {
    await recordWorkspaceSessionUnlocked(cwd, session, sessionFile, lock.assertCurrentOwner, migratedFrom, cliqHome);
  });
}

async function recordWorkspaceSessionUnlocked(
  cwd: string,
  session: Session,
  sessionFile: string,
  assertCurrentOwner: () => Promise<void>,
  migratedFrom?: WorkspaceState['migratedFrom'],
  cliqHome = resolveCliqHome()
) {
  const identity = await resolveWorkspaceIdentity(cwd);
  const now = nowIso();
  const workspaceDir = path.join(cliqHome, 'workspaces', identity.workspaceId);
  const statePath = path.join(workspaceDir, 'state.json');
  const indexPath = path.join(cliqHome, 'workspace-index.json');
  const globalStatePath = path.join(cliqHome, 'state.json');

  const existingState = normalizeWorkspaceState(await readRecoverableJson<unknown>(statePath), identity);
  const recentSession: WorkspaceSessionRef = {
    id: session.id,
    path: sessionFile,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt
  };
  const recentSessions = [
    recentSession,
    ...existingState.recentSessions.filter((entry) => entry.id !== session.id)
  ].slice(0, 50);
  const nextState: WorkspaceState = {
    ...existingState,
    version: GLOBAL_STATE_VERSION,
    workspaceId: identity.workspaceId,
    workspaceRealPath: identity.workspaceRealPath,
    gitRootRealPath: identity.gitRootRealPath,
    activeSessionId: session.id,
    activeSessionPath: sessionFile,
    recentSessions,
    migratedFrom: migratedFrom ?? existingState.migratedFrom,
    lastSeenAt: now
  };

  const index = normalizeWorkspaceIndex(await readRecoverableJson<unknown>(indexPath));
  index.workspaces[identity.workspaceId] = {
    workspaceId: identity.workspaceId,
    workspaceRealPath: identity.workspaceRealPath,
    gitRootRealPath: identity.gitRootRealPath,
    activeSessionId: session.id,
    activeSessionPath: sessionFile,
    lastSeenAt: now
  };

  await fs.mkdir(workspaceDir, { recursive: true });
  await atomicWriteJson(statePath, nextState, assertCurrentOwner);
  await atomicWriteJson(indexPath, index, assertCurrentOwner);
  await atomicWriteJson(globalStatePath, { version: GLOBAL_STATE_VERSION, updatedAt: now }, assertCurrentOwner);
}
