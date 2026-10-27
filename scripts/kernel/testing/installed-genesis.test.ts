// Pure qualification data. No StateOwner, installation or execution authority is constructed.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { signedKernelSchemaProfile } from '../../../src/state/signed-schema.js';
import { expectedInstalledGenesisSeed } from './installed-genesis.js';

function fixture() {
  const values = [
    { entryId: 'kernel_schema', role: 'schema', version: '8', relativePath: 'schema/kernel-v8.json', executable: false,
      bytes: canonicalJsonBytes(signedKernelSchemaProfile()) },
    ...['policy_engine', 'trust_store', 'sandbox_root_profile'].map(role => ({ entryId: role, role, version: '1',
      relativePath: `profiles/${role}`, executable: false, bytes: Buffer.from(role) })),
    { entryId: 'worker', role: 'worker', version: '1', relativePath: 'worker', executable: true, bytes: Buffer.from('inert image data') },
  ];
  const bundle = { schemaVersion: 1, bundleVersion: 'data-only', stateSchemaRange: { min: 8, max: 8 },
    entries: values.map(({ bytes, ...entry }) => ({ ...entry, digest: sha256Bytes(bytes), byteCount: bytes.length }))
  } as RuntimeBundleManifest;
  return { bundle, contents: values };
}

test('installed genesis audit includes the complete signed schema seed rather than the old four-object count', () => {
  const { bundle, contents } = fixture();
  const expected = [canonicalJsonBytes(bundle), ...contents.filter(entry => !entry.executable).map(entry => entry.bytes)]
    .map(bytes => ({ artifactRef: sha256Bytes(bytes), byteCount: bytes.length }))
    .sort((a, b) => a.artifactRef < b.artifactRef ? -1 : a.artifactRef > b.artifactRef ? 1 : 0);
  assert.equal(expected.length, 5);
  assert.deepEqual(expectedInstalledGenesisSeed({ bundle, contents }), expected);
  assert(expected.some(entry => entry.artifactRef === canonicalSha256(signedKernelSchemaProfile())));
});

test('genesis audit rejects missing, extra, duplicate and substituted signed input data', () => {
  const { bundle, contents } = fixture();
  for (const changed of [contents.slice(1), [...contents, contents[0]!],
    [...contents, { ...contents[0]!, entryId: 'extra' }],
    contents.map((entry, index) => index === 0 ? { ...entry, bytes: Buffer.from('substituted') } : entry),
    contents.map((entry, index) => index === 0 ? { ...entry, executable: true } : entry),
  ]) assert.throws(() => expectedInstalledGenesisSeed({ bundle, contents: changed }));
  const missingSchema = { ...bundle, entries: bundle.entries.filter(entry => entry.entryId !== 'kernel_schema') };
  assert.throws(() => expectedInstalledGenesisSeed({ bundle: missingSchema, contents: contents.slice(1) }));
});

test('the audit validates every typed signed use while the CAS seed coalesces equal bytes', () => {
  const { bundle, contents } = fixture();
  const original = contents[1]!, alias = { ...original, entryId: 'tool_schema', role: 'schema', relativePath: 'tools/read.json' };
  const entry = { ...bundle.entries[1]!, entryId: alias.entryId, role: alias.role, relativePath: alias.relativePath };
  const expected = expectedInstalledGenesisSeed({ bundle: { ...bundle, entries: [...bundle.entries, entry] }, contents: [...contents, alias] });
  assert.equal(expected.length, 5, 'one manifest replaces the prior manifest; the equal raw bytes stay one CAS object');
  assert.throws(() => expectedInstalledGenesisSeed({ bundle: { ...bundle, entries: [...bundle.entries, entry] },
    contents: [...contents, { ...alias, bytes: Buffer.from('different raw schema bytes') }] }));
});
