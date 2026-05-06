import path from 'node:path';
import { promises as fs } from 'node:fs';
import crypto from 'node:crypto';

import { withPathLock } from '../../lib/path-lock.js';
import { assertValidTxId } from './types.js';
import type { Transaction, TxKind, ApplyProgress, AbortProgress, AuditEntry, Diff } from './types.js';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function makeTxId(now = Date.now()): string {
  const time = now.toString(2).padStart(48, '0');
  const rand = [...crypto.randomBytes(10)]
    .map((b) => b.toString(2).padStart(8, '0'))
    .join('')
    .slice(0, 80);
  const bits = time + rand;
  let out = 'tx_';
  for (let i = 0; i < 26; i++) {
    out += CROCKFORD[parseInt(bits.slice(i * 5, i * 5 + 5), 2)];
  }
  return out;
}

export function resolveTxRoot(cliqHome: string): string {
  return path.join(cliqHome, 'tx');
}

export function txDir(root: string, txId: string): string {
  // Defense-in-depth: validate the id shape before joining into the tx root.
  // Prevents `path.join(root, '../../somewhere')` from reaching outside the
  // tx directory when txId originates from CLI argv or other untrusted input.
  // makeTxId() always produces a value that satisfies assertValidTxId, so
  // legitimate flows pay only a regex match.
  assertValidTxId(txId);
  return path.join(root, txId);
}

export function stateJsonPath(root: string, txId: string): string {
  return path.join(txDir(root, txId), 'state.json');
}

export function applyProgressPath(root: string, txId: string): string {
  return path.join(txDir(root, txId), 'apply-progress.json');
}

export function abortProgressPath(root: string, txId: string): string {
  return path.join(txDir(root, txId), 'abort-progress.json');
}

export function auditJsonPath(root: string, txId: string): string {
  return path.join(txDir(root, txId), 'audit.json');
}

export function diffJsonPath(root: string, txId: string): string {
  return path.join(txDir(root, txId), 'diff.json');
}

export function overlayDir(root: string, txId: string): string {
  return path.join(txDir(root, txId), 'overlay');
}

export function validatorsDir(root: string, txId: string): string {
  return path.join(txDir(root, txId), 'validators');
}

/**
 * Acquire an exclusive per-tx file lock for the lifetime of `fn`. The lock
 * directory lives inside the tx directory at `<txDir>/tx.lock`, so different
 * `txId` values do not contend. Built on the shared owner-file lock primitive.
 */
export async function withTxLock<T>(root: string, txId: string, fn: () => Promise<T>): Promise<T> {
  await fs.mkdir(txDir(root, txId), { recursive: true });
  // `withPathLock(target)` creates `${target}.lock`, so passing `<txDir>/tx`
  // yields `<txDir>/tx.lock` -- keeps the lock dir scoped inside the tx dir.
  // The `tx` sentinel is never written; only the `.lock` directory is.
  const target = path.join(txDir(root, txId), 'tx');
  return withPathLock(target, () => fn());
}

export async function createTx(
  root: string,
  init: { id: string; kind: TxKind; workspaceId: string; sessionId: string; workspaceRealPath: string }
): Promise<Transaction> {
  const ts = new Date().toISOString();
  const tx: Transaction = {
    id: init.id,
    kind: init.kind,
    state: 'staging',
    workspaceId: init.workspaceId,
    sessionId: init.sessionId,
    workspaceRealPath: init.workspaceRealPath,
    createdAt: ts,
    updatedAt: ts
  };
  await fs.mkdir(txDir(root, tx.id), { recursive: true });
  await writeTxState(root, tx);
  return tx;
}

export async function readTxState(root: string, txId: string): Promise<Transaction | null> {
  try {
    const raw = await fs.readFile(stateJsonPath(root, txId), 'utf8');
    return JSON.parse(raw) as Transaction;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function writeTxState(root: string, tx: Transaction): Promise<void> {
  await fs.mkdir(txDir(root, tx.id), { recursive: true });
  const target = stateJsonPath(root, tx.id);
  const tmp = `${target}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(tx, null, 2), 'utf8');
  const fh = await fs.open(tmp, 'r+');
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
  await fs.rename(tmp, target);
}

export async function readApplyProgress(root: string, txId: string): Promise<ApplyProgress | null> {
  try {
    const raw = await fs.readFile(applyProgressPath(root, txId), 'utf8');
    return JSON.parse(raw) as ApplyProgress;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function writeApplyProgress(root: string, txId: string, progress: ApplyProgress): Promise<void> {
  await fs.mkdir(txDir(root, txId), { recursive: true });
  const target = applyProgressPath(root, txId);
  const tmp = `${target}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(progress, null, 2), 'utf8');
  const fh = await fs.open(tmp, 'r+');
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
  await fs.rename(tmp, target);
}

export async function deleteApplyProgress(root: string, txId: string): Promise<void> {
  try {
    await fs.unlink(applyProgressPath(root, txId));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
}

export async function readAbortProgress(root: string, txId: string): Promise<AbortProgress | null> {
  try {
    const raw = await fs.readFile(abortProgressPath(root, txId), 'utf8');
    return JSON.parse(raw) as AbortProgress;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function writeAbortProgress(root: string, txId: string, progress: AbortProgress): Promise<void> {
  await fs.mkdir(txDir(root, txId), { recursive: true });
  const target = abortProgressPath(root, txId);
  const tmp = `${target}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(progress, null, 2), 'utf8');
  const fh = await fs.open(tmp, 'r+');
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
  await fs.rename(tmp, target);
}

export async function deleteAbortProgress(root: string, txId: string): Promise<void> {
  try {
    await fs.unlink(abortProgressPath(root, txId));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
}

export async function readDiff(root: string, txId: string): Promise<Diff | null> {
  try {
    const raw = await fs.readFile(diffJsonPath(root, txId), 'utf8');
    return JSON.parse(raw) as Diff;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function writeDiff(root: string, txId: string, diff: Diff): Promise<void> {
  await fs.mkdir(txDir(root, txId), { recursive: true });
  const target = diffJsonPath(root, txId);
  const tmp = `${target}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(diff, null, 2), 'utf8');
  const fh = await fs.open(tmp, 'r+');
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
  await fs.rename(tmp, target);
}

export async function appendAudit(root: string, txId: string, entry: AuditEntry): Promise<void> {
  await fs.appendFile(auditJsonPath(root, txId), JSON.stringify(entry) + '\n', 'utf8');
}

export async function readAudit(root: string, txId: string): Promise<AuditEntry[]> {
  try {
    const raw = await fs.readFile(auditJsonPath(root, txId), 'utf8');
    return raw.split('\n').filter(Boolean).map((l) => JSON.parse(l) as AuditEntry);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
}
