import { parseCanonicalTime, requiredSafeInteger } from '../kernel/identity.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeStateOwnerAcquisitionEvidence, decodeStateOwnerTransitionEvidence } from './decoders.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';

/** Retained positive process-death evidence for one exact owning lifetime.
 * This closes that owner's local resources, never its child containment. */
export async function readStateOwnerDeath(artifacts: ArtifactCatalog, driver: SqliteDriver,
  input: { supervisorInstanceId: string; ownedAt: string }) {
  parseCanonicalTime(input.ownedAt);
  const rows = driver.prepare('SELECT owner_epoch FROM state_owners WHERE supervisor_instance_id = ? LIMIT 2')
    .all<{ owner_epoch: unknown }>(input.supervisorInstanceId);
  if (rows.length !== 1) throw new TypeError('owning process has no unique retained StateOwner');
  const prior = readStateOwner(driver, requiredSafeInteger(rows[0]!.owner_epoch, 'owning StateOwner epoch'));
  if (!prior || prior.state !== 'terminal' || prior.terminalReason !== 'superseded_after_owner_death')
    throw new TypeError('owning process has no observed death closure');
  if (input.ownedAt < prior.acquiredAt || input.ownedAt > prior.releasedAt)
    throw new TypeError('owned task does not belong to its retained owner lifetime');
  const successor = readStateOwner(driver, prior.ownerEpoch + 1);
  if (!successor) throw new TypeError('owning process has no retained death acquisition');
  const acquisition = decodeStateOwnerAcquisitionEvidence(await readCanonicalArtifact(artifacts, successor.acquisitionEvidenceRef));
  const transition = decodeStateOwnerTransitionEvidence(await readCanonicalArtifact(artifacts, prior.transitionEvidenceRef));
  if (acquisition.kind !== 'takeover_after_owner_death' || acquisition.ownerEpoch !== successor.ownerEpoch ||
      acquisition.supervisorInstanceId !== successor.supervisorInstanceId || acquisition.evidenceDigest !== successor.acquisitionEvidenceDigest ||
      acquisition.priorOwnerEpoch !== prior.ownerEpoch || acquisition.priorTerminalRowDigest !== prior.rowDigest ||
      acquisition.priorTransitionEvidenceRef !== prior.transitionEvidenceRef || acquisition.priorTransitionEvidenceDigest !== prior.transitionEvidenceDigest ||
      transition.kind !== 'superseded_after_owner_death' || transition.evidenceDigest !== prior.transitionEvidenceDigest ||
      transition.priorOwnerEpoch !== prior.ownerEpoch || transition.priorSupervisorInstanceId !== prior.supervisorInstanceId ||
      transition.priorProcessIdentityRef !== prior.processIdentityRef || transition.priorProcessIdentityDigest !== prior.processIdentityDigest ||
      transition.stateLockIdentityRef !== prior.stateLockIdentityRef || transition.stateLockIdentityDigest !== prior.stateLockIdentityDigest ||
      transition.successorOwnerEpoch !== successor.ownerEpoch || transition.successorSupervisorInstanceId !== successor.supervisorInstanceId ||
      transition.successorProcessIdentityRef !== successor.processIdentityRef || transition.successorProcessIdentityDigest !== successor.processIdentityDigest ||
      transition.successorRuntimeBundleRef !== successor.runtimeBundleRef || transition.successorRuntimeBundleManifestDigest !== successor.runtimeBundleManifestDigest ||
      transition.successorInstanceNonceDigest !== successor.instanceNonceDigest || acquisition.acquiredAt !== successor.acquiredAt ||
      transition.observedAt !== successor.acquiredAt) throw new TypeError('death acquisition substitutes its exact owning process');
  for (const key of ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'processIdentityRef', 'processIdentityDigest',
    'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest'] as const)
    requireEqual(acquisition[key], successor[key], `owner death acquisition ${key}`);
  return { priorOwner: prior, successorOwner: successor,
    acquisitionEvidenceRef: successor.acquisitionEvidenceRef, acquisitionEvidenceDigest: successor.acquisitionEvidenceDigest };
}
