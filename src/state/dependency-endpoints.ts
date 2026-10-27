import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeEndpointAuthorityRecord, decodeEndpointRegistration, type EndpointAuthorityRecordV1 } from '../kernel/credential-authority.js';
import { normalizeBoundedText } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeStateRootIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { withCredentialAuthorityLock, withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { readEndpointAuthoritySource } from './store.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';

/** Pure current-selection equality, not proof of registration, a held lock,
 * admission or a release. Historical v7 readability never supplies this v8
 * network decision; the owning release repeats it under the real scope. */
export function assertCurrentPublicDependencyEndpoint(record: EndpointAuthorityRecordV1, principalId: string, bundle: RuntimeBundleManifest): void {
  record = decodeEndpointAuthorityRecord(record);
  const registration = decodeEndpointRegistration(record.registration), tls = registration.tls;
  const trust = bundle.entries.find(entry => entry.entryId === 'default_https_trust_store');
  if (record.state !== 'active' || record.ownerPrincipalId !== principalId || registration.ownerPrincipalId !== principalId ||
      record.expectedRegistrationArtifactRef !== canonicalSha256(registration) || !registration.purposes.includes('dependency_registry') ||
      tls.trustStoreRuntimeBundleRef !== canonicalSha256(bundle) || tls.trustStoreRuntimeBundleManifestDigest !== bundle.manifestDigest ||
      !trust || trust.executable || trust.role !== 'trust_store' || trust.digest !== tls.trustStoreRef || trust.digest !== tls.trustStoreDigest ||
      trust.byteCount < 1 || trust.byteCount > 16_777_216 || tls.spkiSha256Pins.length > 64)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'dependency registry is not active for this exact current signed public profile');
  const base = registration.target.basePath;
  if (base.length > 4096 || !/^\/[A-Za-z0-9._~+/-]*$/u.test(base) || base.split('/').some((part, index, all) => index > 0 &&
      (part === '.' || part === '..' || !part && index !== all.length - 1)))
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'dependency registry base path is outside the fixed native profile');
}

/** Registered data selection only. The scope and all of its real handles
 * close before returning; these bytes cannot be used as a later live release
 * observation. CONNECT/GET release must reacquire and compare the whole record. */
export async function readInstalledDependencyEndpoints(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  selected: HeldInstalledRuntime, input: { principalId: string; endpointIds: readonly string[] }, signal?: AbortSignal) {
  input = immutableSnapshot(input);
  if (typeof input.principalId !== 'string' || normalizeBoundedText(input.principalId, 1, 128) !== input.principalId ||
      !Array.isArray(input.endpointIds) || !input.endpointIds.length || input.endpointIds.length > 128 || new Set(input.endpointIds).size !== input.endpointIds.length ||
      input.endpointIds.some(id => typeof id !== 'string' || normalizeBoundedText(id, 1, 128) !== id)) throw new TypeError('dependency registry selectors are invalid');
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const active = assertActiveStateOwner(driver, owner);
  const root = decodeStateRootIdentity(await readCanonicalArtifact(reads, owner.stateRootIdentityRef));
  if (root.identityDigest !== owner.stateRootIdentityDigest) throw new KernelStorageError('ARTIFACT_MISMATCH', 'dependency owner root differs');
  return withHeldInstalledRuntime(selected, async installed => {
    await installed.revalidate(signal); reads.assertReadActive();
    if (active.runtimeBundleRef !== installed.bundleDigest || active.runtimeBundleManifestDigest !== installed.bundle.manifestDigest ||
        installed.stateRoot.canonicalPath !== root.canonicalAbsolutePath || installed.stateRoot.deviceId !== root.deviceId ||
        installed.stateRoot.fileId !== root.directoryFileId || installed.stateRoot.ownerUid !== root.ownerUid)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'dependency registry lookup differs from its current selected root and owner');
    const result = await withCredentialAuthorityLock(selected, async token => {
      token.assertHeld(); reads.assertReadActive(); assertActiveStateOwner(driver, owner);
      const objects = new Map<string, Readonly<{ artifactRef: string; bytes: Buffer }>>();
      const records = input.endpointIds.map(id => {
        const source = readEndpointAuthoritySource(token, id);
        if (!source) throw new KernelStorageError('NOT_FOUND', 'dependency registry is not registered');
        assertCurrentPublicDependencyEndpoint(source.record, input.principalId, installed.bundle);
        const shared = source.objects.map(object => {
          const previous = objects.get(object.artifactRef);
          if (previous) {
            if (!previous.bytes.equals(object.bytes)) throw new KernelStorageError('ARTIFACT_MISMATCH', 'dependency registry source aliases different complete bytes');
            return previous;
          }
          objects.set(object.artifactRef, object); return object;
        });
        // All original per-endpoint history/signature/full-byte checks above
        // still run. Only these already verified snapshots share storage in
        // this operation; no cross-cut observation or hash result is cached.
        return Object.freeze({ ...source, objects: Object.freeze(shared) });
      });
      token.assertHeld(); reads.assertReadActive();
      // Preserve raw CA/signed object bytes as independent streams, never
      // base64 in the 1MiB dependency JSON root or as native authority.
      return Object.freeze(records);
    });
    await installed.revalidate(signal); assertActiveStateOwner(driver, owner); reads.assertReadActive();
    return result;
  }, signal);
}
