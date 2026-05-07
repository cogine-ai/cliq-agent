import { promises as fs } from 'node:fs';
import path from 'node:path';

import { txDir } from './store.js';
import type { BashEffect } from './types.js';

export function bashEffectsPath(root: string, txId: string): string {
  return path.join(txDir(root, txId), 'bash-effects.json');
}

export async function appendBashEffect(root: string, txId: string, effect: BashEffect): Promise<void> {
  await fs.appendFile(bashEffectsPath(root, txId), JSON.stringify(effect) + '\n', 'utf8');
}

export async function readBashEffects(root: string, txId: string): Promise<BashEffect[]> {
  try {
    const raw = await fs.readFile(bashEffectsPath(root, txId), 'utf8');
    return raw.split('\n').filter(Boolean).map((l) => JSON.parse(l) as BashEffect);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
}
