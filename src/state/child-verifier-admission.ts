// Historical child-bound provenance, never an inherited execution permit or
// another consumption of a parent's identity-reading authorization.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeDerivedChildUnverifiedConsent } from '../kernel/child-verifier.js';
import { decodeEndpointCredentialGrantBinding } from '../kernel/credential-authority.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { Run, RunAssemblyV1, RunSpec } from '../kernel/types.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { verifyRuntimeBundle } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { AuthorizationRuntime } from './authorization.js';
import { readChildAdmission, type ChildAdmissionData } from './child-admission.js';
import { KernelStorageError } from './errors.js';
import { readModelTargetData } from './model-grant.js';
import { readRun } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { decodeVerifierSpec } from './verifier-artifacts.js';

const same = (a: unknown, b: unknown) => canonicalJsonBytes(a).equals(canonicalJsonBytes(b));
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'child verifier provenance differs from its complete original admission'); }
const immutableRun = (run: Run) => ({ id: run.id, sessionId: run.sessionId, parentRunId: run.parentRunId ?? null,
  specRef: run.specRef, createdAt: run.createdAt, deadlineAt: run.deadlineAt });

/** Fixed data preflight shared by the original writer and historical audit.
 * It reads only the selected original target/bindings. The returned interval
 * neither samples a clock nor authenticates a principal or releases a call. */
export async function readChildCredentialLifetime(artifacts: ArtifactCatalog, input: {
  principalId: string; createdAt: string; deadlineAt: string; spec: RunSpec; assembly: RunAssemblyV1;
}): Promise<Readonly<{ createdAt: string; expiresAt: string }>> {
  const { createdAt, deadlineAt, spec, assembly } = input;
  parseCanonicalTime(createdAt); parseCanonicalTime(deadlineAt);
  if (!same(spec.credentialGrantRefs, assembly.provider.credentialGrantRefs)) invalid();
  await readModelTargetData(artifacts, { principalId: input.principalId, run: { createdAt, deadlineAt }, spec, assembly });
  let expiresAt = deadlineAt;
  for (const ref of spec.credentialGrantRefs) {
    const binding = decodeEndpointCredentialGrantBinding(await readCanonicalArtifact(artifacts, ref));
    if (binding.createdAt > createdAt) invalid();
    if (binding.expiresAt !== undefined && binding.expiresAt < expiresAt) expiresAt = binding.expiresAt;
  }
  return Object.freeze({ createdAt, expiresAt });
}

type ChildAdmissionEdge = ChildAdmissionData['ancestors'][number];
async function readMaterial(artifacts: ArtifactCatalog, original: ChildAdmissionEdge) {
  const { run, spec, parent, parentSpec, capabilityGrant: capability, delegated, request, grant, originalOwner, localCommittedAt: committed } = original;
  const prepared = request.preparedAt;
  for (const at of [prepared, committed, grant.issuedAt, grant.expiresAt, run.deadlineAt, parent.deadlineAt, originalOwner.acquiredAt]) parseCanonicalTime(at);
  if (spec.operation !== 'agent' || run.parentRunId !== parent.id || prepared !== run.createdAt ||
      prepared < grant.issuedAt || committed < prepared || committed >= grant.expiresAt || committed >= run.deadlineAt ||
      committed >= parent.deadlineAt || prepared < originalOwner.acquiredAt ||
      originalOwner.state === 'terminal' && committed > originalOwner.releasedAt ||
      spec.sourceProjectionRef !== parentSpec.sourceProjectionRef || spec.sandboxProfileRef !== parentSpec.sandboxProfileRef)
    invalid();
  if (spec.dependencyPolicyRef !== capability.childDependencyPolicyRef || spec.dependencyPolicyRef !==
      (delegated.verifierMode === 'inherit_parent' ? parentSpec.dependencyPolicyRef : undefined)) invalid();
  if (spec.dependencyPolicyRef) (await import('../kernel/dependency.js')).decodeDependencyPolicy(
    await readCanonicalArtifact(artifacts, spec.dependencyPolicyRef));
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef));
  if (!same(assembly.runtime, original.assembly.runtime) || assembly.mcpServers.length ||
      !same(spec.credentialGrantRefs, assembly.provider.credentialGrantRefs) ||
      !same(capability.childCredentialGrantRefs, spec.credentialGrantRefs) ||
      spec.credentialGrantRefs.some(ref => !parentSpec.credentialGrantRefs.includes(ref))) invalid();
  const credentialLifetime = await readChildCredentialLifetime(artifacts,
    { principalId: original.principalId, createdAt: prepared, deadlineAt: run.deadlineAt, spec, assembly });
  if (committed < credentialLifetime.createdAt || committed >= credentialLifetime.expiresAt) invalid();
  const verifier = decodeVerifierSpec(await readCanonicalArtifact(artifacts, spec.verifierSpecRef));
  if (capability.verifierMode !== delegated.verifierMode || capability.childVerifierSpecRef !== spec.verifierSpecRef) invalid();
  if (delegated.verifierMode === 'inherit_parent') {
    if (spec.verifierSpecRef !== parentSpec.verifierSpecRef || !verifier.verifiers.some(entry => entry.gate === 'required') ||
        spec.unverifiedConsentRef !== undefined || capability.derivedUnverifiedConsentRef !== undefined) invalid();
  } else {
    const empty = { schemaVersion: 1 as const, format: 'cliq-verifier-spec-v1' as const, verifiers: [], specDigest: '' };
    empty.specDigest = digestOmitting(empty, 'specDigest');
    if (!same(verifier, empty) || !delegated.allowUnverifiedHelper || !spec.unverifiedConsentRef ||
        spec.unverifiedConsentRef !== capability.derivedUnverifiedConsentRef) invalid();
    const consent = decodeDerivedChildUnverifiedConsent(await readCanonicalArtifact(artifacts, spec.unverifiedConsentRef));
    const { unverifiedConsentRef: _consent, ...specCore } = spec;
    if (consent.parentRunId !== parent.id || consent.childRunId !== run.id ||
        consent.delegateBatchItemId !== original.allocation.delegateBatchItemId ||
        consent.delegateCallId !== original.allocation.delegateCallId || consent.delegateCallIndex !== original.allocation.delegateCallIndex ||
        consent.delegateOpId !== original.allocation.delegateOpId || consent.delegateOperationGrantRef !== request.delegateOperationGrantRef ||
        consent.childCapabilityGrantCoreDigest !== capability.grantCoreDigest || consent.childRunSpecCoreDigest !== canonicalSha256(specCore) ||
        consent.createdAt !== prepared) invalid();
  }
}

/** Data-only friend for the complete core admission reader, including empty
 * verifier children. This calls neither readChildAdmission nor the root signed
 * authorization resolver, and returns no grant, permit or native evidence. */
export async function validateChildVerifierData(artifacts: ArtifactCatalog, admitted: ChildAdmissionData): Promise<void> {
  const chain = [admitted, ...admitted.ancestors], seen = new Set<string>();
  if (chain.length > 8) invalid();
  for (const [index, original] of chain.entries()) {
    artifacts.assertReadActive();
    if (seen.has(original.run.id)) invalid();
    seen.add(original.run.id);
    const next = chain[index + 1];
    if (next ? !same(immutableRun(next.run), immutableRun(original.parent)) || !same(next.spec, original.parentSpec)
      : !same(immutableRun(admitted.rootOrigin.run), immutableRun(original.parent)) || !same(admitted.rootOrigin.spec, original.parentSpec)) invalid();
    await readMaterial(artifacts, original);
  }
}

/** The core reader has audited every original child edge and empty-verifier
 * consent through the friend above. Re-read the root's original signed
 * verifier/command/environment authorization exactly once, under the actual
 * current owner. Its consumed receipt never becomes a child consumption. */
export async function readChildVerifierAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, runId: string, signal?: AbortSignal): Promise<{ authorizationReceiptRefs: string[] }> {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const current = () => { signal?.throwIfAborted(); assertActiveStateOwner(driver, owner); };
  current(); verifyRuntimeBundle(runtime.bundle, runtime.releaseKeys);
  const bundleRef = canonicalSha256(runtime.bundle);
  const admitted = await readChildAdmission(driver, reads, runId, { signal });
  const chain = [admitted, ...admitted.ancestors];
  if (chain.some(original => original.assembly.runtime.runtimeBundleRef !== bundleRef ||
      original.assembly.runtime.runtimeBundleManifestDigest !== runtime.bundle.manifestDigest)) invalid();
  const { validateVerifierRunAdmission } = await import('./verifier-admission.js');
  await validateVerifierRunAdmission(driver, reads, owner, runtime, admitted.rootOrigin.run.id, signal);
  admitted.rootOrigin.assertUnchanged(driver);
  current();
  for (const original of chain) {
    original.ownerHistory.assertUnchanged(driver);
    if (!same(immutableRun(readRun(driver, original.run.id)), immutableRun(original.run)) ||
        !same(immutableRun(readRun(driver, original.parent.id)), immutableRun(original.parent))) invalid();
  }
  return { authorizationReceiptRefs: [] };
}
