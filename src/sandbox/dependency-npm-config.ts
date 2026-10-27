import { lstatSync } from 'node:fs';

/** One literal guest path only. The native dependency recipe must already
 * hold the original /work mount read-only; this check is not that proof. */
export function assertFixedNpmProjectConfigAbsent(): void {
  try { lstatSync('/work/.npmrc'); throw new TypeError('project npm config unsupported'); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
}
