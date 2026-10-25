// Ordinary inert data only. The signed Linux Git child and real cgroup
// campaign independently establish physical verification; this test cannot.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { inflateSync } from 'node:zlib';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { workerCampaignSandboxProfile } from '../../../src/sandbox/testing/worker-campaign-fixture.js';
import { decodeSourceGitInspectionOutput } from '../../../src/workspace/source-git-output.js';
import { normalizeGitIndex } from '../../../src/workspace/git-index.js';
import { preparingGitNativeInputData } from './preparing-git-native.js';

test('native preparing campaign retains a nonempty self-consistent ordinary pack/index closure without host Git', () => {
  const repositoryIdentityDigest = 'a'.repeat(64), resources = workerCampaignSandboxProfile({ maxOpenFiles: 128 }).resources;
  const [bytes, index, pack, idx] = preparingGitNativeInputData(repositoryIdentityDigest, resources);
  const metadata = decodeSourceGitInspectionOutput(bytes, { repositoryIdentityDigest, resources });
  const sha256 = (value: Buffer) => createHash('sha256').update(value).digest('hex');
  assert.equal(metadata.index.sha256, sha256(index)); assert.equal(metadata.pack.sha256, sha256(pack));
  assert.equal(metadata.pack.indexSha256, sha256(idx)); assert.equal(metadata.index.byteCount, index.length);
  assert.equal(metadata.pack.byteCount, pack.length); assert.equal(metadata.pack.indexByteCount, idx.length);
  assert.equal(pack.subarray(0, 12).toString('hex'), '5041434b0000000200000001');
  const body = inflateSync(pack.subarray(13, pack.length - 20)); assert.deepEqual(body, Buffer.from('before\n'));
  const object = createHash('sha1').update(`blob ${body.length}\0`).update(body).digest();
  assert.deepEqual(metadata.pack.objectIds, [object.toString('hex')]); assert.equal(pack[12], 0x30 | body.length);
  assert.deepEqual(pack.subarray(-20), createHash('sha1').update(pack.subarray(0, -20)).digest());
  assert.deepEqual(idx.subarray(-40, -20), pack.subarray(-20));
  assert.deepEqual(idx.subarray(-20), createHash('sha1').update(idx.subarray(0, -20)).digest());
  assert.equal(idx.subarray(0, 8).toString('hex'), 'ff744f6300000002'); assert.equal(idx.readUInt32BE(8 + 255 * 4), 1);
  assert.deepEqual(idx.subarray(1032, 1052), object); assert.equal(idx.readUInt32BE(1056), 12);
  const normalized = normalizeGitIndex(index, 'sha1', { maxBytes: resources.maxSingleFileBytes, maxEntries: 100_000 });
  assert(normalized.canonicalBytes.equals(index)); assert.deepEqual(normalized.entries, metadata.index.entries);
  assert.equal(normalized.indexTreeObjectId, metadata.index.indexTreeObjectId);
  assert.equal(canonicalSha256(metadata), sha256(bytes));
});
