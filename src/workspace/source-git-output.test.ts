import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { classifySourceGitConfig } from './source-git-config.js';
import { decodeSourceGitInspectionOutput } from './source-git-output.js';

const repository = 'a'.repeat(64);
const expected = { repositoryIdentityDigest: repository, resources: DEFAULT_SANDBOX_RESOURCES };
function metadata() {
  return { schemaVersion: 1, format: 'cliq-source-git-inspection-output-v1', repositoryIdentityDigest: repository,
    objectFormat: 'sha1', head: { kind: 'unborn', branch: 'main' }, refs: [], index: { entries: [],
      indexTreeObjectId: createHash('sha1').update('tree 0\0').digest('hex'), byteCount: 32, sha256: 'b'.repeat(64) },
    pack: { byteCount: 32, sha256: 'c'.repeat(64), trailerObjectHash: 'd'.repeat(40), indexByteCount: 1072,
      indexSha256: 'e'.repeat(64), objectIds: [] }, sanitizedConfig: structuredClone(classifySourceGitConfig(Buffer.from('[core]\n')).config) };
}

test('sealed Git output metadata is canonical closed data, not a pack verification or native proof', () => {
  const raw = metadata(), bytes = canonicalJsonBytes(raw);
  const decoded = decodeSourceGitInspectionOutput(bytes, expected);
  assert.deepEqual(decoded, raw); assert(Object.isFrozen(decoded)); assert(Object.isFrozen(decoded.pack.objectIds));
  raw.head.branch = 'later-mutation'; assert.equal(decoded.head.kind === 'unborn' && decoded.head.branch, 'main');
  for (const bad of [Buffer.from(JSON.stringify(metadata(), null, 2)),
    Buffer.from(bytes.toString().replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1')),
    Buffer.from('{"secret":"not output"}'), Buffer.from([0xff])])
    assert.throws(() => decodeSourceGitInspectionOutput(bad, expected), TypeError);
  assert.throws(() => decodeSourceGitInspectionOutput(bytes, { ...expected, repositoryIdentityDigest: 'f'.repeat(64) }), TypeError);
});

test('sealed Git output rejects foreign fields, unordered graph data, unsupported index modes, and impossible relations', () => {
  const check = (edit: (value: any) => void) => {
    const value = metadata(); edit(value);
    assert.throws(() => decodeSourceGitInspectionOutput(canonicalJsonBytes(value), expected), TypeError);
  };
  for (const edit of [
    (v: any) => { v.rawConfig = 'inert remote is still private'; },
    (v: any) => { v.pack.rawSourcePack = true; },
    (v: any) => { v.pack.objectIds = ['f'.repeat(40), 'e'.repeat(40)]; },
    (v: any) => { v.pack.objectIds = ['f'.repeat(40), 'f'.repeat(40)]; },
    (v: any) => { v.refs = [{ name: 'refs/heads/main', objectId: 'e'.repeat(40) }]; },
    (v: any) => { v.head = { kind: 'detached', objectId: 'e'.repeat(40) }; },
    (v: any) => { v.refs = [{ name: 'refs/../bad', objectId: 'e'.repeat(40) }]; },
    (v: any) => { v.index.entries = [{ canonicalRootRelativePath: '../outside', stage: 0, mode: 33188,
      objectId: 'e'.repeat(40), assumeValid: false, skipWorktree: false }]; },
    (v: any) => { v.pack.trailerObjectHash = 'e'.repeat(64); },
    (v: any) => { v.index.byteCount = true; },
    (v: any) => { v.sanitizedConfig.core.hooksPath = '/outside'; },
    (v: any) => { v.sanitizedConfig.configDigest = 'f'.repeat(64); }
  ]) check(edit);
});

test('fixed output byte decoding does not invoke caller binary getters or Proxy traps', () => {
  const value = metadata(), bytes = new Uint8Array(canonicalJsonBytes(value)); let calls = 0;
  for (const key of ['byteLength', 'byteOffset', 'buffer']) Object.defineProperty(bytes, key, {
    get() { calls++; throw new Error('caller binary getter must remain unobserved'); } });
  Object.defineProperty(bytes, Symbol.iterator, { get() { calls++; throw new Error('caller iterator must remain unobserved'); } });
  assert.deepEqual(decodeSourceGitInspectionOutput(bytes, expected), value);
  const proxy = new Proxy(bytes, { get() { calls++; throw new Error('caller Proxy must remain unobserved'); },
    getPrototypeOf() { calls++; throw new Error('caller Proxy must remain unobserved'); } });
  assert.throws(() => decodeSourceGitInspectionOutput(proxy, expected), TypeError);
  assert.equal(calls, 0);
});
