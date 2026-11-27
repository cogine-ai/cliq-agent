import { assertControlWireJson } from '../kernel/control-wire-data.js';
import { KERNEL_SQLITE_APPLICATION_ID } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { SignedKernelSchemaV1, SignedSchemaConversionV1 } from '../kernel/runtime-upgrade.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type RuntimeBundleManifest, type ReleaseTrustKey } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { checkCanonicalBytes } from './installed-artifacts.js';
import { kernelSchemaDefinition, kernelSchemaManifest, KERNEL_SCHEMA_V8_SQL } from './schema.js';

function mismatch(): never { throw new KernelStorageError('ARTIFACT_MISMATCH', 'signed schema source differs from its fixed full recipe'); }

/** Fixed SQL purposes only. The generic schema role also carries tool-input
 * JSON schemas; their signed bytes never become database DDL authority. */
export function kernelSchemaEntries(bundle: RuntimeBundleManifest): RuntimeBundleManifest['entries'] {
  const entries = bundle.entries.filter(entry => entry.entryId === 'kernel_schema' || entry.entryId === 'schema_conversion');
  for (const entry of entries) {
    const [version, relativePath] = entry.entryId === 'kernel_schema'
      ? ['8', 'schema/kernel-v8.json'] : ['7-to-8', 'schema/convert-v7-to-v8.json'];
    if (entry.role !== 'schema' || entry.executable || entry.version !== version || entry.relativePath !== relativePath) mismatch();
  }
  return entries;
}

export function signedKernelSchemaProfile(): SignedKernelSchemaV1 {
  const definition = kernelSchemaDefinition(8);
  const core = { schemaVersion: 1 as const, format: 'cliq-signed-kernel-schema-v1' as const,
    applicationId: KERNEL_SQLITE_APPLICATION_ID, stateSchemaVersion: 8 as const,
    schemaManifest: kernelSchemaManifest(8), ...definition };
  return { ...core, profileDigest: canonicalSha256(core) };
}

/** Fixed full equality also rejects missing, unknown and substituted fields. */
export function decodeSignedKernelSchema(value: unknown): SignedKernelSchemaV1 {
  assertControlWireJson(value);
  const expected = signedKernelSchemaProfile();
  if (!canonicalJsonBytes(value).equals(canonicalJsonBytes(expected))) mismatch();
  return immutableSnapshot(expected);
}

export function schemaConversionProfile(source: RuntimeBundleManifest): SignedSchemaConversionV1 {
  const supervisor = source.entries.filter(entry => entry.role === 'supervisor');
  if (supervisor.length !== 1 || !supervisor[0]!.executable || kernelSchemaEntries(source).length !== 0 ||
      source.stateSchemaRange.min > 7 || source.stateSchemaRange.max < 7) mismatch();
  const original = kernelSchemaManifest(7), target = signedKernelSchemaProfile();
  const core = { schemaVersion: 1 as const, format: 'cliq-signed-schema-conversion-v1' as const,
    conversion: 'retired_signed_7_to_8' as const,
    source: { kind: 'recognized_generated_schema_v1' as const,
      runtimeBundleRef: canonicalSha256(source), runtimeBundleManifestDigest: source.manifestDigest,
      supervisorEntryId: supervisor[0]!.entryId, supervisorEntryVersion: supervisor[0]!.version,
      supervisorExecutableDigest: supervisor[0]!.digest, schemaManifestRef: canonicalSha256(original),
      schemaManifestDigest: original.manifestDigest, schemaDigest: original.schemaDigest,
      catalogDigest: kernelSchemaDefinition(7).catalogDigest },
    targetSchemaRef: canonicalSha256(target), targetSchemaDigest: target.profileDigest,
    statements: KERNEL_SCHEMA_V8_SQL, statementsDigest: sha256Bytes(Buffer.from(KERNEL_SCHEMA_V8_SQL)) };
  return { ...core, profileDigest: canonicalSha256(core) };
}

export function decodeSchemaConversion(value: unknown, source: RuntimeBundleManifest): SignedSchemaConversionV1 {
  assertControlWireJson(value);
  const expected = schemaConversionProfile(source);
  if (!canonicalJsonBytes(value).equals(canonicalJsonBytes(expected))) mismatch();
  return immutableSnapshot(expected);
}

/** Exact signed entry for the current complete schema. This does not attest
 * installation; the held-package producer still verifies every actual file. */
export function assertSignedKernelSchemaEntry(bundle: RuntimeBundleManifest): void {
  const expected = signedKernelSchemaProfile();
  const entries = kernelSchemaEntries(bundle);
  const entry = entries.find(item => item.entryId === 'kernel_schema');
  if (!entry || entry.version !== '8' || entry.executable || entry.relativePath !== 'schema/kernel-v8.json' ||
      entry.digest !== canonicalSha256(expected) || entry.byteCount !== canonicalJsonBytes(expected).length ||
      bundle.stateSchemaRange.min > 8 || bundle.stateSchemaRange.max < 8) mismatch();
}

async function readSignedDataEntry(artifacts: ArtifactCatalog, entry: RuntimeBundleManifest['entries'][number]): Promise<unknown> {
  if (!Number.isSafeInteger(entry.byteCount) || entry.byteCount < 1 || entry.byteCount > 1_048_576) mismatch();
  const chunks: Buffer[] = [];
  for await (const chunk of artifacts.readChunks(entry.digest, entry.byteCount)) chunks.push(Buffer.from(chunk));
  const bytes = Buffer.concat(chunks);
  if (bytes.length !== entry.byteCount || sha256Bytes(bytes) !== entry.digest) mismatch();
  return checkCanonicalBytes(bytes);
}

export async function readSignedKernelSchema(artifacts: ArtifactCatalog, bundle: RuntimeBundleManifest,
  releaseKeys: readonly ReleaseTrustKey[]): Promise<SignedKernelSchemaV1> {
  verifyRuntimeBundle(bundle, releaseKeys);
  assertSignedKernelSchemaEntry(bundle);
  const entries = kernelSchemaEntries(bundle);
  const schema = entries.find(entry => entry.entryId === 'kernel_schema');
  if (!schema || schema.version !== '8' || schema.executable || schema.relativePath !== 'schema/kernel-v8.json' ||
      schema.byteCount > 1_048_576) mismatch();
  const value = await readSignedDataEntry(artifacts, schema);
  const decoded = decodeSignedKernelSchema(value);
  if (canonicalSha256(decoded) !== schema.digest || canonicalJsonBytes(decoded).length !== schema.byteCount ||
      bundle.stateSchemaRange.min > 8 || bundle.stateSchemaRange.max < 8) mismatch();
  return decoded;
}

export async function readSignedSchemaConversion(artifacts: ArtifactCatalog, source: RuntimeBundleManifest,
  target: RuntimeBundleManifest, releaseKeys: readonly ReleaseTrustKey[]): Promise<SignedSchemaConversionV1> {
  verifyRuntimeBundle(source, releaseKeys); verifyRuntimeBundle(target, releaseKeys);
  // Verification uses independently supplied roots. Equal publisher labels do
  // not substitute a matching actual public key.
  if (source.publisherKeyId !== target.publisherKeyId) mismatch();
  const schema = await readSignedKernelSchema(artifacts, target, releaseKeys);
  const entries = target.entries.filter(entry => entry.entryId === 'schema_conversion');
  const entry = entries[0];
  if (entries.length !== 1 || !entry || entry.role !== 'schema' || entry.version !== '7-to-8' ||
      entry.relativePath !== 'schema/convert-v7-to-v8.json' || entry.executable || entry.byteCount > 1_048_576) mismatch();
  const expected = schemaConversionProfile(source);
  if (entry.digest !== canonicalSha256(expected) || entry.byteCount !== canonicalJsonBytes(expected).length) mismatch();
  const conversion = decodeSchemaConversion(await readSignedDataEntry(artifacts, entry), source);
  if (canonicalSha256(conversion) !== entry.digest || canonicalJsonBytes(conversion).length !== entry.byteCount ||
      conversion.targetSchemaRef !== canonicalSha256(schema) || conversion.targetSchemaDigest !== schema.profileDigest ||
      conversion.profileDigest !== digestOmitting(conversion, 'profileDigest')) mismatch();
  return conversion;
}
