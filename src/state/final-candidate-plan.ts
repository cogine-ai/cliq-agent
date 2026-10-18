import { digestOmitting, identityHash } from '../kernel/identity.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { RunSpec, VerifierPlan } from '../kernel/types.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeVerifierSpec } from './decoders.js';
import { decodeVerifierPlan } from './result-artifacts.js';
import { KernelStorageError } from './errors.js';
import { decodeVerifierCommand, decodeVerifierEnvironment } from './verifier-artifacts.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';

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
  if (frozen.verifiers.length) {
    const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef));
    for (const entry of frozen.verifiers) {
      const command = decodeVerifierCommand(await readCanonicalArtifact(artifacts, entry.commandRef));
      const environment = decodeVerifierEnvironment(await readCanonicalArtifact(artifacts, entry.environmentRef));
      if (command.commandDigest !== entry.commandDigest || command.verifierId !== entry.id || command.verifierVersion !== entry.version ||
          environment.environmentDigest !== entry.environmentDigest || environment.verifierId !== entry.id || environment.verifierVersion !== entry.version ||
          environment.commandRef !== entry.commandRef || environment.commandDigest !== entry.commandDigest || environment.sourceProjectionRef !== spec.sourceProjectionRef ||
          environment.runtimeBundleRef !== assembly.runtime.runtimeBundleRef || environment.runtimeBundleManifestDigest !== assembly.runtime.runtimeBundleManifestDigest ||
          environment.guestToolchainManifestRef !== assembly.runtime.guestToolchainManifestRef || environment.guestToolchainManifestDigest !== assembly.runtime.guestToolchainManifestDigest ||
          canonicalSha256(command) !== entry.commandRef || canonicalSha256(environment) !== entry.environmentRef)
        throw new TypeError('candidate plan substitutes its frozen verifier command or environment');
    }
  }
  const plan: VerifierPlan = { schemaVersion: 1, ...input, verifierSpecRef: spec.verifierSpecRef,
    verifierSpecDigest: frozen.specDigest, entries: frozen.verifiers.map(entry => ({ index: entry.index, verifierId: entry.id,
      verifierSpecDigest: frozen.specDigest, verifierEntryDigest: entry.entryDigest, commandRef: entry.commandRef, commandDigest: entry.commandDigest,
      environmentRef: entry.environmentRef, environmentDigest: entry.environmentDigest, required: entry.gate === 'required', maxAttempts: entry.retries + 1 })), planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  return decodeVerifierPlan(plan);
}
