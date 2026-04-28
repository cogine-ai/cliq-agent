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
import type { Session, SessionCheckpoint, SessionModelRef, SessionRecord } from './types.js';

const execFileAsync = promisify(execFile);
const GLOBAL_STATE_VERSION = 1;

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
    checkpoints: []
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
        (value as { checkpoints: unknown[] }).checkpoints.every((checkpoint) => isSessionCheckpoint(checkpoint))))
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

  if (
    id === session.id &&
    version === session.version &&
    records.length === session.records.length &&
    checkpoints === session.checkpoints &&
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
    checkpoints
  };
}

function migrateLegacySession(cwd: string, legacy: LegacySession): Session {
  const session = createSession(cwd);
  session.createdAt = legacy.createdAt ?? session.createdAt;
  session.updatedAt = legacy.updatedAt ?? session.updatedAt;
  session.records = [];

  for (const message of legacy.messages ?? []) {
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
  session.updatedAt = nowIso();
  const target = sessionFilePath(session);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, JSON.stringify(session, null, 2));
  await recordWorkspaceSession(cwd, session, target);
}

export async function appendRecord(cwd: string, session: Session, record: SessionRecord) {
  session.records.push(record);
  await saveSession(cwd, session);
}

export async function ensureSession(cwd: string): Promise<Session> {
  const state = await loadWorkspaceState(cwd);
  if (state?.activeSessionPath) {
    const active = await loadSessionFromPath(state.activeSessionPath);
    if (active) {
      return active;
    }
  }

  const legacyTarget = sessionPath(cwd);
  try {
    const raw = JSON.parse(await fs.readFile(legacyTarget, 'utf8')) as unknown;
    const session = isSession(raw) ? normalizeSession(raw) : migrateLegacySession(cwd, raw as LegacySession);
    await saveSessionWithMigration(cwd, session, legacyTarget);
    return session;
  } catch {
    const session = createSession(cwd);
    await saveSession(cwd, session);
    return session;
  }
}

export async function ensureFresh(cwd: string): Promise<Session> {
  const session = createSession(cwd);
  await saveSession(cwd, session);
  return session;
}

async function readJson<T>(target: string): Promise<T | null> {
  try {
    return JSON.parse(await fs.readFile(target, 'utf8')) as T;
  } catch {
    return null;
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
  const target = await workspaceStatePath(cwd);
  return await readJson<WorkspaceState>(target);
}

async function loadSessionFromPath(target: string): Promise<Session | null> {
  const raw = await readJson<unknown>(target);
  if (!isSession(raw)) {
    return null;
  }

  const normalized = normalizeSession(raw);
  if (normalized !== raw) {
    await saveSession(normalized.cwd, normalized);
  }
  return normalized;
}

async function saveSessionWithMigration(cwd: string, session: Session, migratedFromPath: string) {
  if (!session.id) {
    session.id = makeId('sess');
  }
  session.updatedAt = nowIso();
  const target = sessionFilePath(session);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, JSON.stringify(session, null, 2));
  await recordWorkspaceSession(cwd, session, target, {
    path: migratedFromPath,
    migratedAt: nowIso()
  });
}

async function recordWorkspaceSession(
  cwd: string,
  session: Session,
  sessionFile: string,
  migratedFrom?: WorkspaceState['migratedFrom']
) {
  const cliqHome = resolveCliqHome();
  const identity = await resolveWorkspaceIdentity(cwd);
  const now = nowIso();
  const workspaceDir = path.join(cliqHome, 'workspaces', identity.workspaceId);
  const statePath = path.join(workspaceDir, 'state.json');
  const indexPath = path.join(cliqHome, 'workspace-index.json');
  const globalStatePath = path.join(cliqHome, 'state.json');
  const existingState = (await readJson<WorkspaceState>(statePath)) ?? emptyWorkspaceState(identity);
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

  await fs.mkdir(workspaceDir, { recursive: true });
  await fs.mkdir(path.dirname(indexPath), { recursive: true });
  await fs.writeFile(statePath, JSON.stringify(nextState, null, 2));

  const index = (await readJson<WorkspaceIndex>(indexPath)) ?? emptyWorkspaceIndex();
  index.version = GLOBAL_STATE_VERSION;
  index.workspaces[identity.workspaceId] = {
    workspaceId: identity.workspaceId,
    workspaceRealPath: identity.workspaceRealPath,
    gitRootRealPath: identity.gitRootRealPath,
    activeSessionId: session.id,
    activeSessionPath: sessionFile,
    lastSeenAt: now
  };
  await fs.writeFile(indexPath, JSON.stringify(index, null, 2));
  await fs.writeFile(globalStatePath, JSON.stringify({ version: GLOBAL_STATE_VERSION, updatedAt: now }, null, 2));
}
