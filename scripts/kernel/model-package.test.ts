import assert from 'node:assert/strict';
import { test } from 'node:test';
import { rootCertificates } from 'node:tls';
import { canonicalSha256 } from '../../src/kernel/canonical.js';
import { sha256Bytes } from '../../src/kernel/identity.js';
import { projectCompactionPrompt } from '../../src/model/request.js';
import { buildInstalledModelPackageEntries, buildInstalledModelPrompts } from './model-package.js';
import { installedModelPackageEntries, type InstalledModelPackageFixture } from './testing/installed-model-package.js';

const broker = Buffer.from('inert broker bytes for build-data regression');
const edit = Buffer.from('inert edit bytes for build-data regression');
const selected = { provider: 'openai-compatible' as const, model: 'deepseek-flash' };

test('signed script-capable prompts explain the actual tools, candidate checks and separate application boundary', () => {
  for (const provider of ['openai-compatible', 'ollama'] as const) {
    const material = buildInstalledModelPrompts({ provider, model: 'inert-prompt-contract' }, true);
    const system = material.system;
    assert(system.value.utf8.includes('/usr/bin/node'));
    assert(system.value.utf8.includes('Do not assume host utilities or package managers are available.'));
    assert(system.value.utf8.includes('Your final response submits a candidate for the configured checks.'));
    assert(system.value.utf8.includes('If verifier feedback returns, fix the reported failure within the original task and budget.'));
    assert(system.value.utf8.includes('The user reviews the result and explicitly applies it to the original workspace.'));
    assert.equal(system.value.byteCount, Buffer.byteLength(system.value.utf8));
    assert.equal(system.ref, sha256Bytes(system.bytes));
    const entry = material.entries.find(entry => entry.role === 'system_prompt')!;
    assert.deepEqual(entry.bytes, system.bytes);
    const root = material.structuredArtifacts.find(root => root.kind === 'system_prompt')!;
    assert.equal(root.artifactRef, system.ref);
    assert.equal(root.semanticDigest, system.value.textDigest);
  }
  const editOnly = buildInstalledModelPrompts(selected, false);
  assert(!editOnly.system.value.utf8.includes('/usr/bin/node'));
});

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

test('local-only model material uses the fixed native broker and exclusively local prompts', () => {
  const local = { provider: 'ollama' as const, model: 'functiongemma-cliq:270m-q4-k-m' };
  const material = buildInstalledModelPackageEntries(local, broker, edit);
  const remote = buildInstalledModelPackageEntries(selected, broker, edit);
  assert.deepEqual(material.tools, remote.tools);
  assert.deepEqual(material.entries.filter(entry => entry.role === 'provider_adapter'),
    remote.entries.filter(entry => entry.role === 'provider_adapter'));
  assert.equal(material.structuredArtifacts.length, 2);
  assert(material.structuredArtifacts.every(root => 'provider' in root && root.provider === 'ollama' && root.model === local.model));
  assert(material.entries.every(entry => !entry.relativePath.startsWith('model-objects/') && entry.relativePath !== 'model-authority.json'));
});
