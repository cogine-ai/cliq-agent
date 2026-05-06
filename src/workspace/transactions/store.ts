import path from 'node:path';
import { promises as fs } from 'node:fs';

import type { Transaction, TxKind, ApplyProgress, AbortProgress } from './types.js';

export function resolveTxRoot(cliqHome: string): string {
  return path.join(cliqHome, 'tx');
}

export function txDir(root: string, txId: string): string {
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
