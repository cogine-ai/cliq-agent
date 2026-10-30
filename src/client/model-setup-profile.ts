// Public build data only. A profile cannot establish endpoint, model, pricing,
// credential or execution authority. Its derived identity must still match the
// genuine held installation's verified catalog/price pair before registration.
import { domainToASCII } from 'node:url';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef } from '../kernel/identity.js';
import { assertControlWireJson, controlWireRecord as record, controlWireText as text } from '../kernel/control-wire-data.js';
import type { EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';

export const MODEL_SETUP_PROFILES_ASSET = 'model-setup-profiles.json';
export type ModelSetupProfileV1 = Readonly<{
  schemaVersion: 1; id: string; provider: 'openai-compatible'; model: string;
  target: Readonly<{ hostAscii: string; port: number; basePath: string }>;
  tls: Readonly<{ serverNameAscii: string; spkiSha256Pins: readonly string[] }>;
}>;
export type ModelSetupProfilesV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-model-setup-profiles-v1'; profiles: readonly ModelSetupProfileV1[];
}>;

function array(value: unknown, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximum)
    throw new TypeError('model setup array is outside its bound');
  return value;
}
function host(value: unknown): string {
  const result = text(value, 253);
  if (result !== result.toLowerCase() || domainToASCII(result) !== result ||
      result.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label)))
    throw new TypeError('model setup host must be canonical DNS ASCII');
  return result;
}
function basePath(value: unknown): string {
  const result = text(value, 4096);
  if (!result.startsWith('/') || /[?#\\]/u.test(result) || /%(?:2f|5c)/iu.test(result) ||
      new URL(result, 'https://endpoint.invalid').pathname !== result)
    throw new TypeError('model setup base path must be canonical');
  for (const part of result.split('/')) {
    const decoded = decodeURIComponent(part);
    if (decoded === '.' || decoded === '..' || decoded.normalize('NFC') !== decoded)
      throw new TypeError('model setup base path has a forbidden segment');
  }
  return result;
}

export function decodeModelSetupProfile(value: unknown): ModelSetupProfileV1 {
  assertControlWireJson(value);
  const data = record(value, ['schemaVersion', 'id', 'provider', 'model', 'target', 'tls']);
  if (data.schemaVersion !== 1 || data.provider !== 'openai-compatible') throw new TypeError('unsupported model setup profile');
  const target = record(data.target, ['hostAscii', 'port', 'basePath']);
  const tls = record(data.tls, ['serverNameAscii', 'spkiSha256Pins']);
  if (!Number.isSafeInteger(target.port) || (target.port as number) < 1 || (target.port as number) > 65535)
    throw new TypeError('model setup port is outside its bound');
  const rawPins = array(tls.spkiSha256Pins, 64);
  if (!rawPins.length)
    throw new TypeError('model setup pin list is outside the fixed native bound');
  const pins = rawPins.map(value => { assertArtifactRef(value as string); return value as string; });
  if (new Set(pins).size !== pins.length) throw new TypeError('model setup pins must be unique');
  return immutableSnapshot({ schemaVersion: 1, id: text(data.id, 128), provider: 'openai-compatible', model: text(data.model, 512),
    target: { hostAscii: host(target.hostAscii), port: target.port as number, basePath: basePath(target.basePath) },
    tls: { serverNameAscii: host(tls.serverNameAscii), spkiSha256Pins: pins.sort() } });
}

export function decodeModelSetupProfiles(value: unknown): ModelSetupProfilesV1 {
  assertControlWireJson(value);
  const data = record(value, ['schemaVersion', 'format', 'profiles']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-model-setup-profiles-v1')
    throw new TypeError('model setup profiles are outside their closed format');
  const profiles = array(data.profiles, 32).map(decodeModelSetupProfile);
  if (new Set(profiles.map(profile => profile.id)).size !== profiles.length)
    throw new TypeError('model setup profile ids must be unique');
  return immutableSnapshot({ schemaVersion: 1, format: 'cliq-model-setup-profiles-v1', profiles });
}

export function encodeModelSetupProfiles(profiles: readonly ModelSetupProfileV1[]): Buffer {
  return canonicalJsonBytes(decodeModelSetupProfiles({ schemaVersion: 1, format: 'cliq-model-setup-profiles-v1', profiles }));
}

/** Derivation only: callers must obtain the bundle from the genuine held
 * installation and independently match the resulting tuple against its verified
 * catalog/price pair. This return value is never a registration or authority. */
export function modelSetupEndpointCandidate(value: ModelSetupProfileV1, bundle: RuntimeBundleManifest) {
  const profile = decodeModelSetupProfile(value);
  const trust = bundle.entries.find(entry => entry.entryId === 'default_https_trust_store');
  if (!trust || trust.executable || trust.role !== 'trust_store') throw new TypeError('model setup has no signed default trust store');
  assertArtifactRef(trust.digest); assertArtifactRef(bundle.manifestDigest);
  const target: EndpointRegistrationV1['target'] = { scheme: 'https', ...profile.target, redirectPolicy: 'reject_all' };
  const tls: EndpointRegistrationV1['tls'] = { serverNameAscii: profile.tls.serverNameAscii, minimumVersion: 'TLSv1.3',
    trustStoreRuntimeBundleRef: canonicalSha256(bundle), trustStoreRuntimeBundleManifestDigest: bundle.manifestDigest,
    trustStoreEntryId: 'default_https_trust_store', trustStoreRef: trust.digest, trustStoreDigest: trust.digest,
    spkiSha256Pins: [...profile.tls.spkiSha256Pins] };
  const tlsPolicyDigest = canonicalSha256(tls), endpointIdentityDigest = canonicalSha256({ target, tlsPolicyDigest });
  return immutableSnapshot({ target, tls, tlsPolicyDigest, endpointIdentityDigest });
}
