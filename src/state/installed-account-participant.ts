// One real account participant for a genuine installed Store's entire resource
// cohort. Logical draining never substitutes for an actual native SH/EX gate.
import { acquireHeldKernelGlobalShared, acquireHeldKernelGlobalExclusive, bindHeldMigrationCredentialGate,
  inspectHeldLegacyEntry, verifyHeldLegacyMigratedAuth, type LegacyEntryObservation,
  type HeldKernelGlobalGate, type HeldMigrationCredentialGate, type HeldStateOwnerLock, type NativeStateOwner } from './native-owner.js';
import { inspectInstalledBorrowMigrationEntry, type InstalledRuntimeBorrow } from './installed-runtime.js';
import type { KernelMigrationEntryObservation } from './native-owner.js';
import type { LegacyAuthMigratedMarkerV1 } from '../kernel/migration-auth-data.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

export type HeldInstalledAccountParticipant = Readonly<{
  assertShared(): void;
  isShared(): boolean;
  assertRetirable(): void;
  readLegacyRendezvous(legacyRoot: string): LegacyEntryObservation;
  verifyLegacyAuth(legacyRoot: string, marker: LegacyAuthMigratedMarkerV1): Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
  /** Called only after Store has synchronously fenced new producers and joined
   * every prior resource. Native binds EX to that original Owner and root. */
  enterExclusive(owner: HeldStateOwnerLock): HeldMigrationCredentialGate;
  /** Every original child must have actually closed before this transition. */
  restoreShared(): void;
  close(): void;
}>;
const beforeOwnerReaders = new WeakMap<HeldInstalledAccountParticipant,
  (borrow: InstalledRuntimeBorrow, signal?: AbortSignal) => Promise<KernelMigrationEntryObservation>>();
/** Both private issuers must agree: a genuine account SH and a genuine live
 * installed borrow. No public callback, descriptor or structural proof enters. */
export function inspectInstalledAccountBeforeOwner(participant: HeldInstalledAccountParticipant, borrow: InstalledRuntimeBorrow,
  signal?: AbortSignal): Promise<KernelMigrationEntryObservation> {
  const reader = beforeOwnerReaders.get(participant);
  if (!reader) throw new TypeError('pre-Owner migration entry requires its original account participant');
  return reader(borrow, signal);
}
const participants = new WeakSet<HeldInstalledAccountParticipant>();
const unretired = new Set<Readonly<{ gate?: HeldKernelGlobalGate; binding?: HeldMigrationCredentialGate; failure: ResourceRetirementError }>>();

export function assertInstalledAccountParticipant(participant: HeldInstalledAccountParticipant): void {
  if (!participants.has(participant)) throw new TypeError('installed account participation requires its original holder');
}

export function holdInstalledAccountParticipant(native: NativeStateOwner): HeldInstalledAccountParticipant {
  let gate: HeldKernelGlobalGate | undefined = acquireHeldKernelGlobalShared(native);
  let binding: HeldMigrationCredentialGate | undefined;
  let phase: 'shared' | 'exclusive' | 'fenced_without_gate' | 'closed' = 'shared';
  let failure: ResourceRetirementError | undefined;
  const poison = (message: string, cause: unknown): never => {
    failure ??= cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError(message, cause);
    unretired.add({ gate, binding, failure }); throw failure;
  };
  const receiver = (actual: unknown, count: number) => {
    if (actual !== participant || count !== 0) throw new TypeError('account participant requires its original receiver');
    if (failure) throw failure;
  };
  const restore = () => {
    // A successful close is consumed exactly once. An uncertain close retains
    // the original object instead of retrying a possibly reused FD number.
    if (binding) { try { binding.close(); } catch (error) { return poison('migration binding did not actually retire', error); } binding = undefined; }
    if (gate) { try { gate.close(); } catch (error) { return poison('exclusive account participant did not actually retire', error); } gate = undefined; }
    phase = 'fenced_without_gate';
    gate = acquireHeldKernelGlobalShared(native); gate.assertHeld(); phase = 'shared';
  };
  const participant: HeldInstalledAccountParticipant = Object.freeze({
    readLegacyRendezvous(legacyRoot, ...args: unknown[]) {
      receiver(this, args.length); participant.assertShared();
      return inspectHeldLegacyEntry(native, gate!, legacyRoot);
    },
    verifyLegacyAuth(legacyRoot, marker, ...args: unknown[]) {
      receiver(this, args.length); participant.assertShared();
      return verifyHeldLegacyMigratedAuth(native, gate!, legacyRoot, marker);
    },
    assertRetirable(...args: unknown[]) {
      receiver(this, args.length);
      if (binding || phase === 'exclusive') throw new ResourceRetirementError('exclusive account resource cohort is still held', undefined);
      // A known successful SH close followed by a busy EX/SH acquisition owns
      // no account resource. It authorizes no productive action, but must not
      // prevent final original Owner/driver retirement after the Store's real
      // independent producer joins. Reacquiring SH is never invented here.
      if (gate) gate.assertHeld();
    },
    isShared(...args: unknown[]) {
      receiver(this, args.length);
      if (phase !== 'shared' || !gate || binding) return false;
      gate.assertHeld(); return true;
    },
    assertShared(...args: unknown[]) {
      receiver(this, args.length);
      if (phase !== 'shared' || !gate || binding) throw new KernelStorageError('RECOVERY_REQUIRED', 'installed productive account participation is fenced');
      gate.assertHeld();
    },
    enterExclusive(owner, ...args: unknown[]) {
      receiver(this, args.length);
      if (phase !== 'shared' || !gate || binding) throw new KernelStorageError('RECOVERY_REQUIRED', 'account participant cannot enter a second cutover');
      owner.assertHeld(); gate.assertHeld();
      phase = 'fenced_without_gate';
      try { gate.close(); } catch (error) { return poison('original shared account participant did not actually retire', error); }
      gate = undefined;
      try {
        // Ordinary nonblocking acquisition, never Linux flock SH->EX upgrade.
        // No protected source/SQL cut may be retained across this interval.
        gate = acquireHeldKernelGlobalExclusive(native);
        binding = bindHeldMigrationCredentialGate(native, owner, gate); binding.assertHeld(); phase = 'exclusive'; return binding;
      } catch (error) {
        if (error instanceof ResourceRetirementError) return poison('exclusive account acquisition retained uncertain resources', error);
        try { restore(); }
        catch (restoration) {
          if (restoration instanceof ResourceRetirementError) throw restoration;
          throw new KernelStorageError('RECOVERY_REQUIRED', 'exclusive acquisition failed and the genuine shared participant is still unavailable',
            { cause: new AggregateError([error, restoration]) });
        }
        throw error;
      }
    },
    restoreShared(...args: unknown[]) {
      receiver(this, args.length);
      if (phase === 'shared') { gate!.assertHeld(); return; }
      if (phase === 'closed') throw new TypeError('closed account participant cannot reacquire a lock');
      restore();
    },
    close(...args: unknown[]) {
      receiver(this, args.length); if (phase === 'closed') return;
      // Actual original Owner/Store shutdown requires exclusive children to
      // join first. This method never abandons that binding or reacquires SH.
      if (binding || phase === 'exclusive') throw new ResourceRetirementError('exclusive account resource cohort is still held', undefined);
      if (gate) { try { gate.close(); } catch (error) { return poison('shared account participant did not actually retire', error); } gate = undefined; }
      phase = 'closed';
    }
  });
  beforeOwnerReaders.set(participant, (borrow, signal) => {
    participant.assertShared(); return inspectInstalledBorrowMigrationEntry(borrow, gate!, signal);
  });
  participants.add(participant); participant.assertShared(); return participant;
}
