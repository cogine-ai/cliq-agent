import path from 'node:path';
import { isSea } from 'node:sea';
import { fileURLToPath } from 'node:url';

/** A signed SEA Supervisor is installed at the bundle root, next to native/. */
export function runtimeNativePath(relativePath: string, sourceModuleUrl: string,
  runningSea = isSea()): string {
  if (runningSea) return path.join(path.dirname(process.execPath), relativePath);
  return fileURLToPath(new URL(`../../dist/${relativePath}`, sourceModuleUrl));
}
