import assert from 'node:assert/strict';
import { test } from 'node:test';
import { rootCertificates } from 'node:tls';
import { canonicalSha256 } from '../../src/kernel/canonical.js';
import { sha256Bytes } from '../../src/kernel/identity.js';
import { projectCompactionPrompt } from '../../src/model/request.js';
import { buildInstalledModelPackageEntries } from './model-package.js';
import { installedModelPackageEntries, type InstalledModelPackageFixture } from './testing/installed-model-package.js';

const broker = Buffer.from('inert broker bytes for build-data regression');
const edit = Buffer.from('inert edit bytes for build-data regression');
const selected = { provider: 'openai-compatible' as const, model: 'deepseek-flash' };

test('real-provider build material preserves the existing fixed tools and complete compaction byte closure', () => {
  const material = buildInstalledModelPackageEntries(selected, broker, edit);
  const objects = new Map(material.entries.map(entry => [sha256Bytes(entry.bytes), entry.bytes]));
  const adapter = material.entries.find(entry => entry.role === 'provider_adapter')!;
  assert.equal(adapter.entryId, 'openai-compatible-broker-v1');
  assert.deepEqual(adapter.bytes, broker);
  assert.equal(material.tools.value.entries.length, 1);
  const tool = material.tools.value.entries[0]!;
  assert.equal(tool.name, 'edit');
  assert.deepEqual(tool.execution, { kind: 'builtin', adapterId: 'edit', adapterVersion: '1', adapterCodeDigest: sha256Bytes(edit) });
  assert.equal(material.toolContractDigest, canonicalSha256(tool));
  assert.equal(material.inputSchemaRef, tool.inputSchemaRef);
  assert.equal(sha256Bytes(objects.get(material.inputSchemaRef)!), material.inputSchemaRef);
  for (const declaration of material.structuredArtifacts) {
    assert.equal(declaration.provider, selected.provider);
    assert.equal(declaration.model, selected.model);
    assert(objects.has(declaration.artifactRef));
    for (const ref of declaration.memberRefs) assert(objects.has(ref));
  }
  const prompt = projectCompactionPrompt(material.compaction, 'Original objective and unresolved checks.');
  assert.equal(prompt.tools.length, 0);
  assert(JSON.stringify(prompt).includes('Original objective and unresolved checks.'));
  assert.deepEqual(buildInstalledModelPackageEntries(selected, broker, edit), material);
});

test('owned endpoint fixture delegates identical bytes and keeps its loopback and TLS restrictions', () => {
  const fixture: InstalledModelPackageFixture = { ...selected,
    target: { hostAscii: '127.0.0.1', port: 443, basePath: '/v1' },
    tls: { serverNameAscii: 'owned-fixture.test', caPem: Buffer.from(rootCertificates[0]!), spkiSha256Pins: ['a'.repeat(64)] },
    claims: { nativeToolCalling: true, streaming: true, trustedUsageEvidence: false, contextLimitTokens: 32768, maxOutputTokens: 8192 },
    requestTokenCeiling: { inputTokens: 32768, outputTokens: 8192, cacheReadTokens: 32768, cacheWriteTokens: 0 },
    validFrom: '2026-10-30T00:00:00.000Z', validThrough: '2026-10-31T00:00:00.000Z' };
  assert.deepEqual(installedModelPackageEntries(fixture, broker, edit),
    buildInstalledModelPackageEntries(selected, broker, edit));
  assert.throws(() => installedModelPackageEntries({ ...fixture,
    target: { ...fixture.target, hostAscii: 'api.deepseek.com' as '127.0.0.1' } }, broker, edit), /loopback/);
  assert.throws(() => installedModelPackageEntries({ ...fixture,
    tls: { ...fixture.tls, caPem: Buffer.from('invalid certificate') } }, broker, edit));
  assert.throws(() => installedModelPackageEntries({ ...fixture,
    tls: { ...fixture.tls, spkiSha256Pins: ['a'.repeat(64), 'a'.repeat(64)] } }, broker, edit));
});

test('unsupported provider, altered model name and missing executable bytes cannot produce package material', () => {
  assert.throws(() => buildInstalledModelPackageEntries({ ...selected, provider: 'anthropic' as 'openai-compatible' }, broker, edit));
  assert.throws(() => buildInstalledModelPackageEntries({ ...selected, model: 'noncanonical\u0000model' }, broker, edit));
  assert.throws(() => buildInstalledModelPackageEntries(selected, Buffer.alloc(0), edit));
  assert.throws(() => buildInstalledModelPackageEntries(selected, broker, Buffer.alloc(0)));
});
