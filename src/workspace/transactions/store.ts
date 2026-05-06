import path from 'node:path';

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
