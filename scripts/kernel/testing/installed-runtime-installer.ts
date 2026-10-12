// Qualification-only real installation entry, bundled for the disposable UID.
// It neither starts the installed image nor acquires database/Run authority.
import assert from 'node:assert/strict';
import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';

import { KERNEL_DATABASE_FILENAME } from '../../../src/config.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { ReleaseTrustKey } from '../../../src/policy/runtime-authority.js';
import { createInstalledRuntime } from '../../../src/state/installed-runtime.js';

assert.equal(process.platform, 'linux', 'installed fixture requires a real Linux runner');
assert.equal(process.arch, 'x64', 'no installed fixture qualified for this architecture');
assert(process.geteuid!() > 0 && process.getegid!() > 0, 'installer must run as the disposable nonroot UID');
const [packageRoot, stateRoot, releaseKeysFile, ...extra] = process.argv.slice(2);
assert(packageRoot && stateRoot && releaseKeysFile && extra.length === 0,
  'expected exactly PACKAGE STATE_ROOT RELEASE_KEYS');
assert([packageRoot, stateRoot, releaseKeysFile].every(filename => path.isAbsolute(filename)));
const releaseKeys = parseJsonStrict(await readFile(releaseKeysFile, 'utf8')) as ReleaseTrustKey[];
const selected = await createInstalledRuntime({ releaseKeys }).installInitial({ packageRoot, stateRoot });
for (const relative of [KERNEL_DATABASE_FILENAME, `${KERNEL_DATABASE_FILENAME}-wal`, `${KERNEL_DATABASE_FILENAME}-shm`,
  'runtime/state-owner.lock', 'runtime/control-v1.sock']) {
  const absent = await lstat(path.join(stateRoot, relative)).then(() => false, (error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return true;
    throw error;
  });
  assert(absent, 'installation cannot acquire StateOwner');
}
console.log(JSON.stringify({ bundleDigest: selected.bundleDigest }));
