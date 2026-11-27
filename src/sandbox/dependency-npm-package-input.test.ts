import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { mkdtemp, open, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { dependencyDescriptorSequence } from '../kernel/dependency-descriptors.js';
import type { DependencyNpmInputV1 } from './dependency-npm-data.js';

const ref = canonicalSha256({ inert: 'only data' });
const descriptor = { canonicalPackagePath: '/owned/-/owned-1.0.0.tgz', endpointRegistrationRef: ref,
  integrityAlgorithm: 'sha512' as const, integrityDigest: createHash('sha512').update('inert').digest('base64'), packageName: 'owned', packageVersion: '1.0.0' };
const item = canonicalJsonBytes({ ...descriptor, blobSha256: ref, blobBytes: 2_000_000 });
const frame = (bytes: Buffer) => { const prefix = Buffer.alloc(4); prefix.writeUInt32LE(bytes.length); return Buffer.concat([prefix, bytes]); };
const root = (empty = false): DependencyNpmInputV1 => { const sequence = dependencyDescriptorSequence(empty ? [] : [descriptor]);
  return { schemaVersion: 1, format: 'cliq-dependency-npm-input-v1', dependencyPlanRef: ref, packageManifestDigest: ref,
    lockfileDigest: ref, scriptConditionsDigest: ref, bindingGyp: { kind: 'absent' }, operationGrantRef: ref, allowInstallScripts: false,
    packageCount: sequence.packageCount, packageDescriptorBytes: sequence.packageDescriptorBytes, descriptorSequenceDigest: sequence.descriptorSequenceDigest,
    maxPackageBytes: 67_108_864, maxCacheBytes: 5 * 1_073_741_824 }; };
const program = `import {fstatSync} from 'node:fs';
import {fixedDependencyNpmPackageInputs} from './src/sandbox/dependency-npm-package-input.ts';
const input=JSON.parse(process.argv[1]); let seen=0, accepted=false;
try { for(const item of fixedDependencyNpmPackageInputs(input)) { seen++; if(process.argv[2]==='consumer_failure') throw Error('owned consumer failure'); } accepted=true; } catch {}
let closed=false; try {fstatSync(4)} catch(e) {closed=e.code==='EBADF'}
console.log(JSON.stringify({seen,accepted,closed})); if(!closed) process.exitCode=1;`;

test('fixed metadata FD4 fully reads the original unlinked file and closes on EOF, malformed suffix and consumer failure', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'cliq-npm-fd4.'));
  try {
    const cases = [
      { bytes: frame(item), input: root(), accepted: true, seen: 1 },
      { bytes: Buffer.alloc(0), input: root(true), accepted: true, seen: 0 },
      { bytes: frame(item).subarray(0, -1), input: root(), accepted: false, seen: 0 },
      { bytes: Buffer.concat([frame(item), Buffer.from([0])]), input: root(), accepted: false, seen: 1 },
      { bytes: frame(Buffer.from('{}')), input: root(), accepted: false, seen: 0 },
      { bytes: frame(item), input: { ...root(), descriptorSequenceDigest: canonicalSha256({ different: true }) }, accepted: false, seen: 1 },
      { bytes: frame(item), input: root(), accepted: false, seen: 1, mode: 'consumer_failure' },
    ];
    for (let index = 0; index < cases.length; index++) {
      const selected = cases[index]!, file = path.join(directory, `${index}.owned`); await writeFile(file, selected.bytes, { mode: 0o400 });
      const held = await open(file, 'r'); await unlink(file);
      try {
        const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', program,
          JSON.stringify(selected.input), selected.mode ?? 'complete'], { cwd: process.cwd(), stdio: ['ignore', 'pipe', 'pipe', 'ignore', held.fd], timeout: 10_000 });
        assert.equal(child.error, undefined); assert.equal(child.status, 0, String(child.stderr));
        assert.deepEqual(JSON.parse(String(child.stdout)), { seen: selected.seen, accepted: selected.accepted, closed: true });
      } finally { await held.close(); }
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
