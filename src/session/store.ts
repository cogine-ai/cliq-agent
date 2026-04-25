import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

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
import type { Session, SessionModelRef, SessionRecord } from './types.js';

type LegacySession = {
  createdAt?: string;
  updatedAt?: string;
  messages?: Array<{ role?: string; content?: string | null; name?: string; status?: 'ok' | 'error' }>;
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
    model: defaultSessionModel(),
    cwd,
    createdAt: now,
    updatedAt: now,
    lifecycle: { status: 'idle', turn: 0 },
    records: []
  };
}

function isSession(value: unknown): value is Session {
  return (
    !!value &&
    typeof value === 'object' &&
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
    (value as Session).records.every((record) => isSessionRecord(record))
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

  if (version === session.version && records.length === session.records.length && !modelChanged) {
    return session;
  }

  return {
    ...session,
    version,
    model,
    records
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
  session.updatedAt = nowIso();
  const target = sessionPath(cwd);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, JSON.stringify(session, null, 2));
}

export async function appendRecord(cwd: string, session: Session, record: SessionRecord) {
  session.records.push(record);
  await saveSession(cwd, session);
}

export async function ensureSession(cwd: string): Promise<Session> {
  const target = sessionPath(cwd);
  await fs.mkdir(path.dirname(target), { recursive: true });
  try {
    const raw = JSON.parse(await fs.readFile(target, 'utf8')) as unknown;
    if (isSession(raw)) {
      const normalized = normalizeSession(raw);
      if (normalized !== raw) {
        await saveSession(cwd, normalized);
      }
      return normalized;
    }

    const migrated = migrateLegacySession(cwd, raw as LegacySession);
    await saveSession(cwd, migrated);
    return migrated;
  } catch {
    const session = createSession(cwd);
    await saveSession(cwd, session);
    return session;
  }
}

export async function ensureFresh(cwd: string): Promise<Session> {
  await fs.rm(path.join(cwd, APP_DIR), { recursive: true, force: true });
  return ensureSession(cwd);
}
