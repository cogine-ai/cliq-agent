import { readFile } from 'node:fs/promises';

export type PackageUpdateNotice = {
  current: string;
  latest: string;
};

type CheckForPackageUpdateOpts = {
  packageName: string;
  currentVersion: string;
  timeoutMs?: number;
};

export async function checkForPackageUpdate({
  packageName,
  currentVersion,
  timeoutMs = 1500
}: CheckForPackageUpdateOpts): Promise<PackageUpdateNotice | null> {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;
    const response = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!response.ok) return null;
    const raw = await response.json() as { version?: unknown };
    if (typeof raw.version !== 'string') return null;
    if (!isVersionGreater(raw.version, currentVersion)) return null;
    return { current: currentVersion, latest: raw.version };
  } catch {
    return null;
  }
}

export async function readCurrentPackageVersion(): Promise<string | null> {
  try {
    const raw = await readFile(new URL('../package.json', import.meta.url), 'utf8');
    const parsed = JSON.parse(raw) as { version?: unknown };
    return typeof parsed.version === 'string' ? parsed.version : null;
  } catch {
    return null;
  }
}

export function isVersionGreater(candidate: string, current: string): boolean {
  const next = parseSemver(candidate);
  const base = parseSemver(current);
  if (!next || !base) return false;

  for (const key of ['major', 'minor', 'patch'] as const) {
    if (next[key] > base[key]) return true;
    if (next[key] < base[key]) return false;
  }

  // A stable release is newer than its prerelease with the same numeric core.
  if (base.prerelease && !next.prerelease) return true;
  if (!base.prerelease && next.prerelease) return false;
  if (base.prerelease && next.prerelease) {
    return comparePrerelease(next.prerelease, base.prerelease) > 0;
  }
  return false;
}

function parseSemver(value: string) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(value);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ?? null
  };
}

function comparePrerelease(a: string, b: string): number {
  const left = a.split('.');
  const right = b.split('.');
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const l = left[i];
    const r = right[i];
    if (l === undefined) return -1;
    if (r === undefined) return 1;
    const lNum = /^\d+$/.test(l) ? Number(l) : null;
    const rNum = /^\d+$/.test(r) ? Number(r) : null;
    if (lNum !== null && rNum !== null) {
      if (lNum !== rNum) return lNum - rNum;
      continue;
    }
    if (lNum !== null) return -1;
    if (rNum !== null) return 1;
    if (l !== r) return l < r ? -1 : 1;
  }
  return 0;
}
