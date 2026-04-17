import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { APP_DIR, MODEL, SESSION_FILE, SESSION_VERSION } from '../config.js';
import { SYSTEM_PROMPT } from '../prompt/system.js';
import type { Session, SessionRecord } from './types.js';

type LegacySession = {
  createdAt?: string;
  updatedAt?: string;
  messages?: Array<{ role?: string; content?: string | null; name?: string; status?: 'ok' | 'error' }>;
};

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
    model: MODEL,
    cwd,
    createdAt: now,
    updatedAt: now,
    lifecycle: { status: 'idle', turn: 0 },
    records: [
      {
        id: makeId('sys'),
        ts: now,
        kind: 'system',
        role: 'system',
        content: SYSTEM_PROMPT
      }
    ]
  };
}

function isSession(value: unknown): value is Session {
  return (
    !!value &&
    typeof value === 'object' &&
    typeof (value as Session).version === 'number' &&
    !!(value as Session).lifecycle &&
    typeof (value as Session).lifecycle === 'object' &&
    Array.isArray((value as Session).records)
  );
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

  if (session.records.length === 0 || session.records[0]?.kind !== 'system') {
    session.records.unshift({
      id: makeId('sys'),
      ts: nowIso(),
      kind: 'system',
      role: 'system',
      content: SYSTEM_PROMPT
    });
  }

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
      return raw;
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
