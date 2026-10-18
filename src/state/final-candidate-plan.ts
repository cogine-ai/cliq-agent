import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { RunSpec, VerifierPlan } from '../kernel/types.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeVerifierSpec } from './decoders.js';
import { decodeVerifierPlan } from './result-artifacts.js';
import { KernelStorageError } from './errors.js';

export const finalCandidateItemId = (runId: string, producerItemId: string) =>
  identityHash('cliq-final-candidate-item-v1', runId, producerItemId);
export const finalCandidateCheckpointId = (runId: string, producerItemId: string) =>
  identityHash('cliq-final-candidate-checkpoint-v1', runId, producerItemId);

/** Deterministic retained-data projection, not permission to launch a verifier. */
export async function readCandidateVerifierPlan(artifacts: ArtifactCatalog, spec: RunSpec, input: {
  runId: string; candidateItemId: string; resultSourceRef: string;
}): Promise<VerifierPlan> {
  if (spec.dependencyPolicyRef !== undefined) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate dependencies require their acquisition and settlement reducer');
  }
  const frozen = decodeVerifierSpec(await readCanonicalArtifact(artifacts, spec.verifierSpecRef));
  if (!exactKeys(frozen, ['schemaVersion', 'format', 'verifiers', 'specDigest']) ||
      !Array.isArray(frozen.verifiers) || frozen.verifiers.length > 32) {
    throw new TypeError('candidate verifier spec has invalid closed fields');
  }
  if (frozen.verifiers.length !== 0) {
    // Nonempty plans require the complete command/environment authorization
    // and trusted verifier lifecycle. A rehashed JSON bag is not that closure.
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate verifiers require their complete authorized execution reducer');
  }
  const plan: VerifierPlan = { schemaVersion: 1, ...input, verifierSpecRef: spec.verifierSpecRef,
    verifierSpecDigest: frozen.specDigest, entries: [], planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  return decodeVerifierPlan(plan);
}
