import { decodeDependencyInstallScriptsTemplate } from '../kernel/dependency.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { DependencyCandidateData } from './dependency-candidate.js';
import { readDependencyScriptsTemplateHistoryData } from './dependency-script-history.js';
import { readDeliveryRunAdmission } from './reducers/delivery-admission.js';
import type { SqliteDriver } from './sqlite-driver.js';

/** A Delivery inherits its frozen policy's historical source, never the
 * source Run's script permission. Only a template belonging to this actual
 * Run can satisfy an execution gate; Delivery otherwise needs its own consent. */
export async function readInitialDependencyScriptsConsent(driver: SqliteDriver, artifacts: ArtifactCatalog,
  source: DependencyCandidateData, signal?: AbortSignal) {
  const templateRef = source.policy.installScriptsGrantRef;
  if (!templateRef) throw new TypeError('exact dependency script policy has no original template');
  const header = decodeDependencyInstallScriptsTemplate(await readCanonicalArtifact(artifacts, templateRef));
  if (header.provenance.kind !== 'run_admission') throw new TypeError('initial dependency consent has another provenance');
  if (header.runId !== source.run.id) {
    if (source.spec.operation !== 'delivery' || source.run.parentRunId)
      throw new TypeError('dependency initial consent belongs to another Run');
    const admission = await readDeliveryRunAdmission(driver, artifacts, source.run.id, { signal });
    requireEqual(admission.run, source.run, 'dependency Delivery actual original admission');
    if (admission.spec.dependencyPolicyRef !== source.spec.dependencyPolicyRef ||
        admission.source.spec.dependencyPolicyRef !== source.spec.dependencyPolicyRef)
      throw new TypeError('Delivery dependency policy lost its exact verified source');
  }
  const original = await readDependencyScriptsTemplateHistoryData(driver, artifacts,
    { bundle: source.bundle, releaseKeys: artifacts.releaseTrustRoots() }, { runId: header.runId, templateRef }, signal);
  if (canonicalSha256(original.template) !== templateRef || original.template.ownerPrincipalId !== source.principalId ||
      original.template.workspaceIdentityDigest !== source.workspaceIdentity.identityDigest)
    throw new TypeError('dependency initial historical consent has another principal or workspace');
  return Object.freeze({ ...original, assertUnchanged(connection: Parameters<typeof original.assertUnchanged>[0]) {
    source.assertUnchanged(connection); original.assertUnchanged(connection);
  } });
}
