// Controlled package-build input for a real, billable compatible provider.
// It never registers an endpoint, stores a credential or qualifies a provider.
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { domainToASCII } from 'node:url';
import type { KeyObject } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import type { EndpointRegistrationV1 } from '../../src/kernel/credential-authority.js';
import { assertArtifactRef, normalizeBoundedText, parseCanonicalTime } from '../../src/kernel/identity.js';
import { immutableSnapshot } from '../../src/model/immutable.js';
import { exactKeys, type RuntimeBundleManifest } from '../../src/policy/runtime-authority.js';
import { buildInstalledModelAuthority, type PublishedModelDefinition } from './model-authority-publisher.js';
import type { buildInstalledModelPackageEntries } from './model-package.js';

export type InstalledProviderModelDefinition = Readonly<Omit<PublishedModelDefinition,
  'endpointIdentityDigest' | 'adapterEntryId' | 'provider'> & {
  provider: 'openai-compatible';
  target: Readonly<{ hostAscii: string; port: number; basePath: string }>;
  tls: Readonly<{ serverNameAscii: string; spkiSha256Pins: readonly string[] }>;
}>;

/** Fail before building images for malformed billable-package input. The
 * ordinary native registration, grant, TLS, catalog and pricing checks remain
 * independent; this closed build data is never execution authority. */
export function providerModelDefinition(value: InstalledProviderModelDefinition): InstalledProviderModelDefinition {
  if (!value || !exactKeys(value, ['provider', 'model', 'target', 'tls', 'claims', 'prices',
    'requestTokenCeiling', 'validFrom', 'validThrough']) || value.provider !== 'openai-compatible' ||
    normalizeBoundedText(value.model, 1, 512) !== value.model)
    throw new TypeError('provider package requires an explicit compatible model definition');
  const host = (value: string) => {
    if (typeof value !== 'string' || value !== value.toLowerCase() || domainToASCII(value) !== value || value.length > 253 ||
        value.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label)))
      throw new TypeError('provider package requires canonical DNS endpoint identities');
  };
  if (!value.target || !exactKeys(value.target, ['hostAscii', 'port', 'basePath']) ||
      !Number.isSafeInteger(value.target.port) || value.target.port < 1 || value.target.port > 65535)
    throw new TypeError('provider package target is not closed');
  host(value.target.hostAscii);
  const base = value.target.basePath;
  if (typeof base !== 'string' || !base.startsWith('/') || /[?#\\]/u.test(base) || /%(?:2f|5c)/iu.test(base) ||
      new URL(base, 'https://endpoint.invalid').pathname !== base)
    throw new TypeError('provider package base path is not canonical');
  for (const part of base.split('/')) {
    const decoded = decodeURIComponent(part);
    if (decoded === '.' || decoded === '..' || decoded.normalize('NFC') !== decoded)
      throw new TypeError('provider package base path contains a forbidden segment');
  }
  if (!value.tls || !exactKeys(value.tls, ['serverNameAscii', 'spkiSha256Pins']))
    throw new TypeError('provider package TLS selection is not closed');
  host(value.tls.serverNameAscii);
  const pins = value.tls.spkiSha256Pins;
  if (!Array.isArray(pins) || !pins.length || new Set(pins).size !== pins.length)
    throw new TypeError('provider package requires explicit unique TLS pins');
  pins.forEach(assertArtifactRef);
  if (!value.prices || !exactKeys(value.prices, ['input', 'output', 'cacheRead', 'cacheWrite']) ||
      Object.values(value.prices).some(rate => !Number.isSafeInteger(rate) || rate < 0) ||
      value.prices.input <= 0 || value.prices.output <= 0)
    throw new TypeError('billable provider package requires explicit nonzero input and output prices');
  if (parseCanonicalTime(value.validFrom) >= parseCanonicalTime(value.validThrough))
    throw new TypeError('provider package validity must be a nonempty fixed interval');
  return immutableSnapshot(value);
}

/** The caller retains the same original package-signing session. This writes
 * only the existing companion namespace, using the bundle's actual public CA
 * entry; it accepts no CA, runtime-root or credential override. */
export async function writeInstalledProviderModelAuthority(input: {
  packageRoot: string; bundle: RuntimeBundleManifest; privateKey: KeyObject;
  definition: InstalledProviderModelDefinition;
  material: ReturnType<typeof buildInstalledModelPackageEntries>;
}) {
  const definition = providerModelDefinition(input.definition), { bundle } = input;
  const runtimeBundleRef = canonicalSha256(bundle);
  const trust = bundle.entries.find(entry => entry.entryId === 'default_https_trust_store');
  if (!trust || trust.executable || trust.role !== 'trust_store')
    throw new TypeError('provider package has no signed default trust store');
  const target: EndpointRegistrationV1['target'] = { scheme: 'https', ...definition.target, redirectPolicy: 'reject_all' };
  const tls: EndpointRegistrationV1['tls'] = { serverNameAscii: definition.tls.serverNameAscii, minimumVersion: 'TLSv1.3',
    trustStoreRuntimeBundleRef: runtimeBundleRef, trustStoreRuntimeBundleManifestDigest: bundle.manifestDigest,
    trustStoreEntryId: 'default_https_trust_store', trustStoreRef: trust.digest, trustStoreDigest: trust.digest,
    spkiSha256Pins: [...definition.tls.spkiSha256Pins].sort() };
  const tlsPolicyDigest = canonicalSha256(tls), endpointIdentityDigest = canonicalSha256({ target, tlsPolicyDigest });
  const { closure, objects, models } = buildInstalledModelAuthority({ bundle, privateKey: input.privateKey,
    models: [{ provider: definition.provider, model: definition.model, endpointIdentityDigest,
      adapterEntryId: 'openai-compatible-broker-v1', claims: definition.claims, prices: definition.prices,
      requestTokenCeiling: definition.requestTokenCeiling, validFrom: definition.validFrom, validThrough: definition.validThrough }] });
  await writeFile(path.join(input.packageRoot, 'model-authority.json'), canonicalJsonBytes(closure), { flag: 'wx', mode: 0o400 });
  for (const [ref, object] of objects) {
    const directory = path.join(input.packageRoot, 'model-objects/sha256', ref.slice(0, 2));
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(path.join(directory, ref), object.bytes, { flag: 'wx', mode: 0o400 });
  }
  return { diagnosticOnly: true as const, actualProviderQualified: false as const, actualProviderCostQualified: false as const,
    officialReleaseQualified: false as const, endpoint: { target, tls, tlsPolicyDigest, endpointIdentityDigest },
    catalog: models[0]!.catalog, priceTable: models[0]!.priceTable, closure: { ref: canonicalSha256(closure), value: closure },
    system: { ref: input.material.system.ref, value: input.material.system.value }, compaction: input.material.compaction,
    tools: input.material.tools, inputSchemaRef: input.material.inputSchemaRef, toolContractDigest: input.material.toolContractDigest };
}
