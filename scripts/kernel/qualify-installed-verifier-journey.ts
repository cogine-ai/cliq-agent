// Fixed real Linux verifier consumer. The shared owner retains one signed
// installation, HTTPS endpoint, Secret Service and complete finally/join.
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { runInstalledNodeJourney } from './testing/installed-node-journey.js';
import { NPM_DATA_RECIPE } from '../../src/sandbox/npm-data-image.js';
import { buildInstalledNpmDataAsset } from './testing/installed-npm-package.js';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--verifier-campaign'); assert(filename);
assert(extra.length === 0 || extra.length === 2 && extra[0] === '--locked-node' && extra[1]);
let npmDependencyArchive: Buffer | undefined;
if (extra.length) {
  const name = extra[1]!, file = await open(name, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    assert(before.isFile() && before.nlink === 1n && before.size === BigInt(NPM_DATA_RECIPE.archiveBytes));
    npmDependencyArchive = await file.readFile();
    const after = await file.stat({ bigint: true }), named = await lstat(name, { bigint: true });
    for (const key of ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const) {
      assert.equal(after[key], before[key]); assert.equal(named[key], before[key]);
    }
    buildInstalledNpmDataAsset(npmDependencyArchive);
  } finally { await file.close(); }
}
await runInstalledNodeJourney(filename, 'verifier', npmDependencyArchive ? { npmDependencyArchive } : {});
