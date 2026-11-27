// Qualification-only extension of the actual installed package recipe. Its
// signed claims describe an owned HTTPS fixture, never a production provider.
import assert from 'node:assert/strict';
import { X509Certificate, type KeyObject } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import type { EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { assertArtifactRef, normalizeBoundedText, parseCanonicalTime } from '../../../src/kernel/identity.js';
import type { NormalizedModelCapabilityClaimsV1 } from '../../../src/model/capabilities.js';
import type { ModelTokenComponents } from '../../../src/model/pricing.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { buildInstalledModelAuthority } from '../model-authority-publisher.js';
import { buildInstalledModelPackageEntries, type InstalledModelScriptMaterial } from '../model-package.js';

export type InstalledModelPackageFixture = Readonly<{
  provider: 'openai-compatible'; model: string;
  target: Readonly<{ hostAscii: '127.0.0.1'; port: number; basePath: string }>;
  tls: Readonly<{ serverNameAscii: string; caPem: Buffer; spkiSha256Pins: readonly string[] }>;
  claims: NormalizedModelCapabilityClaimsV1;
  requestTokenCeiling: ModelTokenComponents;
  validFrom: string; validThrough: string;
}>;
export type { InstalledModelPackageEntry } from '../model-package.js';

/** The owned HTTPS fixture keeps its original loopback/TLS restrictions;
 * production package material has no fixture endpoint or zero-price default. */
export function installedModelPackageEntries(fixture: InstalledModelPackageFixture, brokerBytes: Buffer, editBytes: Buffer,
  scripts?: InstalledModelScriptMaterial) {
  assert.equal(fixture.provider, 'openai-compatible');
  assert.equal(fixture.target.hostAscii, '127.0.0.1', 'model fixture may contact only its owned loopback HTTPS server');
  assert(Number.isSafeInteger(fixture.target.port) && fixture.target.port >= 1 && fixture.target.port <= 65535);
  assert.equal(normalizeBoundedText(fixture.model, 1, 512), fixture.model);
  assert.equal(normalizeBoundedText(fixture.tls.serverNameAscii, 1, 512), fixture.tls.serverNameAscii);
  assert(Buffer.isBuffer(fixture.tls.caPem) && fixture.tls.caPem.byteLength <= 1024 * 1024);
  new X509Certificate(fixture.tls.caPem);
  assert(fixture.tls.spkiSha256Pins.length > 0);
  fixture.tls.spkiSha256Pins.forEach(assertArtifactRef);
  assert.equal(new Set(fixture.tls.spkiSha256Pins).size, fixture.tls.spkiSha256Pins.length);
  assert(parseCanonicalTime(fixture.validFrom) < parseCanonicalTime(fixture.validThrough));
  return buildInstalledModelPackageEntries(fixture, brokerBytes, editBytes, scripts);
}

/** Sign only after the complete Bundle ref and endpoint TLS identity exist.
 * The caller supplies its same ephemeral package-signing key, not runtime keys. */
export async function writeInstalledModelAuthority(input: {
  packageRoot: string; bundle: RuntimeBundleManifest; privateKey: KeyObject;
  fixture: InstalledModelPackageFixture; material: ReturnType<typeof installedModelPackageEntries>;
}) {
  const { bundle, fixture } = input;
  const runtimeBundleRef = canonicalSha256(bundle);
  const trust = bundle.entries.find(entry => entry.entryId === 'default_https_trust_store');
  const adapter = bundle.entries.find(entry => entry.entryId === 'openai-compatible-broker-v1');
  assert(trust && !trust.executable && trust.role === 'trust_store');
  assert(adapter && adapter.executable && adapter.role === 'provider_adapter');
  const target: EndpointRegistrationV1['target'] = { scheme: 'https', ...fixture.target, redirectPolicy: 'reject_all' };
  const tls: EndpointRegistrationV1['tls'] = { serverNameAscii: fixture.tls.serverNameAscii, minimumVersion: 'TLSv1.3',
    trustStoreRuntimeBundleRef: runtimeBundleRef, trustStoreRuntimeBundleManifestDigest: bundle.manifestDigest,
    trustStoreEntryId: 'default_https_trust_store', trustStoreRef: trust.digest, trustStoreDigest: trust.digest,
    spkiSha256Pins: [...fixture.tls.spkiSha256Pins].sort() };
  const tlsPolicyDigest = canonicalSha256(tls), endpointIdentityDigest = canonicalSha256({ target, tlsPolicyDigest });
  // This owned fixture server has no billing mechanism. The signed full token
  // vector is substantiated by its actual bounded request/response contract;
  // these rates and claims confer no actual-provider qualification.
  const { closure, objects, models } = buildInstalledModelAuthority({ bundle, privateKey: input.privateKey,
    models: [{ provider: fixture.provider, model: fixture.model, endpointIdentityDigest, adapterEntryId: adapter.entryId,
      claims: fixture.claims, prices: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      requestTokenCeiling: fixture.requestTokenCeiling, validFrom: fixture.validFrom, validThrough: fixture.validThrough }] });
  const { catalog, priceTable } = models[0]!;
  await writeFile(path.join(input.packageRoot, 'model-authority.json'), canonicalJsonBytes(closure), { flag: 'wx', mode: 0o400 });
  for (const [ref, object] of objects) {
    const directory = path.join(input.packageRoot, 'model-objects/sha256', ref.slice(0, 2));
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(path.join(directory, ref), object.bytes, { flag: 'wx', mode: 0o400 });
  }
  return { diagnosticOnly: true as const, actualProviderQualified: false as const, actualProviderCostQualified: false as const,
    endpoint: { target, tls, tlsPolicyDigest, endpointIdentityDigest },
    catalog, priceTable,
    closure: { ref: canonicalSha256(closure), value: closure },
    system: { ref: input.material.system.ref, value: input.material.system.value }, compaction: input.material.compaction,
    tools: input.material.tools, inputSchemaRef: input.material.inputSchemaRef, toolContractDigest: input.material.toolContractDigest };
}
