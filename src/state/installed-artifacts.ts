// Pure signed-artifact decoding shared by installation and its private
// credential repository. These functions never mint a physical/SQL/time owner.
import { X509Certificate } from 'node:crypto';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { KernelStorageError } from './errors.js';

function mismatch(message: string, cause?: unknown): never {
  throw new KernelStorageError('ARTIFACT_MISMATCH', message, cause === undefined ? undefined : { cause });
}

export function checkCanonicalBytes(bytes: Buffer): unknown {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
    let count = 0;
    while (pending.length) {
      const item = pending.pop()!;
      if (++count > 10_000 || item.depth > 32) mismatch('installed runtime canonical graph exceeds its decoding bound');
      if (item.value && typeof item.value === 'object') for (const child of Object.values(item.value)) pending.push({ value: child, depth: item.depth + 1 });
    }
    if (!canonicalJsonBytes(value).equals(bytes)) mismatch('installed runtime JSON bytes are not canonical');
    return value;
  } catch (cause) { if (cause instanceof KernelStorageError) throw cause; mismatch('installed runtime canonical data cannot be decoded', cause); }
}
export function validateBundle(value: unknown, releaseKeys: readonly ReleaseTrustKey[]): RuntimeBundleManifest {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) mismatch('installed runtime manifest must be an object');
    const bundle = value as RuntimeBundleManifest;
    if (!Array.isArray(bundle.entries) || !Array.isArray(bundle.structuredArtifacts) || !Array.isArray(bundle.guestToolchainManifestRefs)) mismatch('installed runtime manifest graph must contain arrays');
    verifyRuntimeBundle(bundle, releaseKeys);
    if (bundle.guestToolchainManifestRefs.length || bundle.structuredArtifacts.length !== 1) mismatch('installed runtime contains unsupported structured roots');
    for (const entry of bundle.entries) {
      if (entry.relativePath.normalize('NFC') !== entry.relativePath || Buffer.byteLength(entry.relativePath) > 4096 ||
          entry.relativePath === 'manifest.json' || entry.relativePath.startsWith('manifest.json/') ||
          (entry.executable && entry.byteCount === 0) ||
          (['supervisor', 'worker', 'provider_adapter', 'tool_adapter', 'platform_helper', 'mcp_server', 'mcp_recovery_adapter', 'local_inference'].includes(entry.role) && !entry.executable) ||
          ['guest_toolchain', 'skill_bundle', 'mcp_recovery_profile', 'bundle_object', 'system_prompt', 'compaction_prompt'].includes(entry.role)) {
        mismatch('installed runtime entry path or role is unsupported');
      }
    }
    return immutableSnapshot(bundle);
  } catch (cause) { if (cause instanceof KernelStorageError) throw cause; mismatch('installed runtime release manifest failed validation', cause); }
}
export function validateTrustStore(bytes: Buffer): void {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const certificates = text.match(/-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu);
    if (!certificates?.length || text.replace(/-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu, '').trim()) mismatch('signed HTTPS trust store must contain only PEM certificates');
    for (const certificate of certificates) new X509Certificate(certificate);
  } catch (cause) { if (cause instanceof KernelStorageError) throw cause; mismatch('signed HTTPS trust store is invalid', cause); }
}
