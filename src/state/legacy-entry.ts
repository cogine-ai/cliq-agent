import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { normalizeAbsolutePath } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeLegacyMigrationRendezvous, type LegacyMigrationRendezvous } from '../kernel/migration-control.js';
import { acquireHeldKernelGlobalShared, inspectHeldLegacyEntry, type HeldKernelGlobalGate,
  type NativeStateOwner } from './native-owner.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

export type HeldLegacyStateEntry = Readonly<{ assertHeld(): void; close(): void }>;
const unretired = new Set<Readonly<{ gate: HeldKernelGlobalGate; failure: ResourceRetirementError }>>();

/** Fixed data decoder only. Bad marker bytes never appear in a diagnostic or
 * become a locator/authority by matching a timestamp or a subset of fields. */
export function decodeLegacyEntryRendezvous(bytes: Uint8Array, digest: string): Readonly<LegacyMigrationRendezvous> {
  try {
    if (bytes.byteLength < 1 || bytes.byteLength > 1_048_576) throw new TypeError('size');
    const value: unknown = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (!canonicalJsonBytes(value).equals(bytes) || canonicalSha256(value) !== digest) throw new TypeError('bytes');
    return decodeLegacyMigrationRendezvous(value);
  } catch {
    // Untrusted malformed control text is not a useful public exception cause.
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Legacy migration rendezvous is invalid; the original state requires recovery');
  }
}

/** Supported Linux compatibility entry only. Acquire before auth/config/
 * Session/runtime loading and hold until the original complete CLI lifecycle
 * joins. This SH is the same NSS account domain as the original credential
 * guard and installed Store; CLIQ_HOME selects no lock domain. */
export function holdLegacyStateEntry(native: NativeStateOwner, legacyRoot: string): HeldLegacyStateEntry {
  if (normalizeAbsolutePath(legacyRoot) !== legacyRoot) throw new TypeError('Legacy entry root must be its original canonical locator');
  const gate = acquireHeldKernelGlobalShared(native); let closed = false;
  let failure: ResourceRetirementError | undefined;
  const close = () => {
    if (failure) throw failure; if (closed) return;
    // An actual success consumes the native close. A failed native close is
    // retained forever instead of retried or represented as unlock success.
    try { gate.close(); closed = true; }
    catch (error) { failure = error instanceof ResourceRetirementError ? error : new ResourceRetirementError('Legacy account entry did not retire', error);
      unretired.add({ gate, failure }); throw failure; }
  };
  try {
    const observed = inspectHeldLegacyEntry(native, gate, legacyRoot);
    if (observed.kind === 'rendezvous_present') {
      const data = decodeLegacyEntryRendezvous(observed.bytes, observed.contentDigest);
      if (data.format === 'cliq-migration-control-v1')
        throw new KernelStorageError('RECOVERY_REQUIRED', 'Legacy state is fenced by an incomplete Kernel migration; resume the same migration');
      if (data.authority === 'kernel')
        throw new KernelStorageError('RECOVERY_REQUIRED', 'Legacy execution is disabled for this migrated state; use the installed Kernel client');
      // Matching plain markers are not physical proof of a completed restore.
      // Until the full original Legacy-generation/receipt reader joins this
      // branch, it remains an explicit recovery boundary, never a bool bypass.
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Legacy rollback requires its complete retained generation and receipt verification');
    }
    gate.assertHeld();
    const held: HeldLegacyStateEntry = Object.freeze({
      assertHeld(...args: unknown[]) {
        if (this !== held || args.length || closed) throw new TypeError('Legacy entry requires its original live receiver');
        if (failure) throw failure; gate.assertHeld();
      },
      close(...args: unknown[]) { if (this !== held || args.length) throw new TypeError('Legacy entry requires its original receiver'); close(); }
    });
    return held;
  } catch (error) { close(); throw error; }
}
