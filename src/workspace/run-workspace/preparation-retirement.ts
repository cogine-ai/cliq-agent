import { canonicalSha256 } from '../../kernel/canonical.js';
import type { WorkspaceGenerationIdentityV1 } from '../../kernel/types.js';
import { immutableSnapshot } from '../../model/immutable.js';
import { requireEqual } from '../../policy/runtime-authority.js';
import { readNativeRetainedPreparingGitRetirement, type NativeRetainedPreparingGitRetirement } from '../../sandbox/linux-worker.js';
import { decodeWorkspaceGenerationIdentity } from '../../state/decoders.js';
import { KernelStorageError, ResourceRetirementError } from '../../state/errors.js';
import { assertRetainedPreparingGitInputOwner, assertRetiredGenerationTree,
  type HeldGenerationTree, type HeldStateOwnerLock } from '../../state/native-owner.js';

declare const preparationGenerationRetirementBrand: unique symbol;
export type RetainedPreparingGenerationRetirement = Readonly<{ [preparationGenerationRetirementBrand]: true }>;
export type RetainedPreparingGenerationRetirementData = Readonly<{ generationRef: string; generationIdentityDigest: string;
  runId: string; generationId: string; sourceRowVersion: number;
  directoryIdentity: HeldGenerationTree['identity']; observedState: Readonly<{ kind: 'unverified_preparation' }>; observedAt: string }>;
const observations = new WeakMap<RetainedPreparingGenerationRetirement, { filesystem: HeldStateOwnerLock;
  receipt: NativeRetainedPreparingGitRetirement; tree: HeldGenerationTree; data: RetainedPreparingGenerationRetirementData }>();

/** The old process domain is already genuinely gone. Inspect/close only its
 * exact registered directory object; an unfinished .git/tree is never sealed
 * or lent to execution. Missing/replaced births remain recovery failures. */
export function observeRetainedPreparingGeneration(filesystem: HeldStateOwnerLock, value: WorkspaceGenerationIdentityV1,
  sourceRowVersion: number, receipt: NativeRetainedPreparingGitRetirement): RetainedPreparingGenerationRetirement {
  const native = readNativeRetainedPreparingGitRetirement(receipt), identity = decodeWorkspaceGenerationIdentity(immutableSnapshot(value));
  assertRetainedPreparingGitInputOwner(filesystem, native.input);
  if (!Number.isSafeInteger(sourceRowVersion) || sourceRowVersion < 1 || identity.locator.kind !== 'linux_directory' ||
      native.observation.origin !== 'original_birth_current_checker' || native.observation.completed !== 0 ||
      identity.runId !== native.input.identity.runId || identity.generationId !== native.input.identity.generationId ||
      identity.creationNonceDigest !== native.input.identity.generationCreationNonceDigest || canonicalSha256(identity) !== native.input.identity.generationRef)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'preparing generation has no exact native original birth and joined process domain');
  const expected = { deviceId: identity.locator.deviceId, fileId: identity.locator.directoryFileId, ownerUid: identity.locator.ownerUid };
  requireEqual(native.input.identity.generation, expected, 'preparing generation exact original native directory birth');
  const tree = filesystem.openGenerationTree(identity, sourceRowVersion); let primary: { error: unknown } | undefined;
  try { tree.assertHeld(); requireEqual(tree.identity, expected, 'preparing generation current held original directory'); }
  catch (error) { primary = { error }; throw error; }
  finally {
    try { tree.close(); } catch (error) {
      throw new ResourceRetirementError('preparing generation current descriptor did not join', primary ? new AggregateError([primary.error, error]) : error);
    }
  }
  const observed = assertRetiredGenerationTree(tree);
  if (!Number.isSafeInteger(observed) || observed < 1) throw new KernelStorageError('RECOVERY_REQUIRED', 'preparing generation has no actual native close time');
  const result = Object.freeze({}) as RetainedPreparingGenerationRetirement;
  observations.set(result, { filesystem, receipt, tree, data: immutableSnapshot({ generationRef: canonicalSha256(identity),
    generationIdentityDigest: identity.identityDigest, runId: identity.runId, generationId: identity.generationId, sourceRowVersion,
    directoryIdentity: expected, observedState: { kind: 'unverified_preparation' as const }, observedAt: new Date(observed).toISOString() }) });
  return result;
}

export function readRetainedPreparingGenerationRetirement(filesystem: HeldStateOwnerLock,
  observation: RetainedPreparingGenerationRetirement, receipt: NativeRetainedPreparingGitRetirement): RetainedPreparingGenerationRetirementData {
  const held = observations.get(observation), native = readNativeRetainedPreparingGitRetirement(receipt);
  if (!held || held.filesystem !== filesystem || held.receipt !== receipt) throw new TypeError('preparing generation retirement has no same-owner genuine observer');
  assertRetainedPreparingGitInputOwner(filesystem, native.input);
  if (new Date(assertRetiredGenerationTree(held.tree)).toISOString() !== held.data.observedAt)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'preparing generation original close observation changed');
  return held.data;
}
