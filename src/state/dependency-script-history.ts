import { readRetainedControlRoot, type RetainedControlRootContext } from './control-channel.js';
// Read the original logical admission and its script template. No native
// resource, endpoint release, grant, replay or mutable recovery is created.
import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { AuthorizationGrantV1 } from '../kernel/authorization.js';
import { decodeDependencyInstallScriptsTemplate } from '../kernel/dependency.js';
import { immutableSnapshot } from '../model/immutable.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeAuthorizationConsumptionReceipt } from './authorization-artifacts.js';
import type { AuthorizationRuntime } from './authorization.js';
import { readDependencyScriptCaptureData } from './dependency-script-capture.js';
import { sameDependencyScriptInputs } from './dependency-script-source.js';
import { KernelStorageError } from './errors.js';
import { readRootRunAdmissionOrigin } from './run-admission-origin.js';
import { readAuthorizationGrant } from './repositories/authorization-grants.js';
import { normalizeRunSubmitRequest } from './source-target.js';
import { readSourceInspectionAttempt } from './source-inspection.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'dependency script template has no complete original authorization provenance'); }

/** Leaf of authorization history: never calls the authorization reader or
 * template reader, so a complete original root admission has no read cycle. */
export async function readDependencyScriptGrantConsumption(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: RetainedControlRootContext,
  runtime: AuthorizationRuntime, grant: AuthorizationGrantV1, signal?: AbortSignal) {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  reads.assertReadActive();
  if (grant.state !== 'consumed' || grant.target.kind !== 'dependency_install_scripts') invalid();
  const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(reads, grant.consumptionReceiptRef));
  if (receipt.grantId !== grant.grantId || receipt.ownerPrincipalId !== grant.ownerPrincipalId || receipt.targetDigest !== grant.targetDigest ||
      receipt.consumedAt !== grant.consumedAt || receipt.consumer.kind !== 'run_admission' ||
      grant.consumedAt < grant.createdAt || grant.consumedAt >= grant.expiresAt) invalid();
  const origin = await readRootRunAdmissionOrigin(driver, reads, receipt.consumer.runId, { signal });
  const template = origin.dependencyTemplate;
  if (!origin.dependencyPolicy || !template || template.provenance.kind !== 'run_admission' || origin.principalId !== grant.ownerPrincipalId ||
      origin.run.createdAt !== receipt.consumedAt || origin.admissionIntentDigest !== receipt.consumer.admissionIntentDigest ||
      template.provenance.sourceAuthorizationGrantId !== grant.grantId || template.provenance.sourceConsumptionReceiptRef !== grant.consumptionReceiptRef ||
      !sameDependencyScriptInputs(grant.target.conditions, template.scriptConditions)) invalid();
  const normalized = normalizeRunSubmitRequest({ ...origin.requestCore, requestDigest: origin.control.requestDigest });
  const source = readSourceInspectionAttempt(driver, { principalId: origin.principalId, method: 'run.submit',
    admissionKey: normalized.request.admissionKey, admissionIntentDigest: origin.admissionIntentDigest });
  if (!source || source.phase !== 'retired' || source.outcome.kind !== 'captured' || source.admissionErrorResponseRef !== undefined) invalid();
  const capture = await readDependencyScriptCaptureData(driver, reads, owner, runtime, {
    sourceInspectionId: source.inspectionId, principalId: origin.principalId, sessionId: origin.run.sessionId,
    conditions: template.scriptConditions }, signal);
  if (!capture.admission || capture.admission.id !== origin.run.id || capture.intent ||
      capture.row.retiredAt > origin.run.createdAt || !same(capture.original, normalized.request)) invalid();
  function assertUnchanged(connection: SqliteConnection | SqliteDriver) {
    origin.assertUnchanged(connection); capture.assertUnchanged(connection);
    if (!same(readAuthorizationGrant(connection, grant.grantId), grant)) invalid();
  }
  assertUnchanged(driver); reads.assertReadActive();
  return Object.freeze({ ...immutableSnapshot({ receipt, template, templateRef: origin.dependencyPolicy.installScriptsGrantRef! }), origin, capture, assertUnchanged });
}

/** A template's data shape never supplies its own authority. Both provenance
 * branches must be read through their specific original owning transaction. */
export async function readDependencyScriptsTemplateHistoryData(driver: SqliteDriver, artifacts: ArtifactCatalog,
  runtime: AuthorizationRuntime, input: { runId: string; templateRef: string }, signal?: AbortSignal) {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  reads.assertReadActive();
  const owner = await readRetainedControlRoot(driver, reads);
  const template = decodeDependencyInstallScriptsTemplate(await readCanonicalArtifact(reads, input.templateRef));
  if (template.runId !== input.runId) invalid();
  if (template.provenance.kind === 'candidate_approval') {
    const { readDependencyScriptApproval } = await import('./dependency-script-approval.js');
    const original = await readDependencyScriptApproval(driver, reads, runtime, input.runId, template.provenance.decisionRef);
    if (original.templateRef !== input.templateRef || !same(original.template, template)) invalid();
    original.assertUnchanged(driver); reads.assertReadActive();
    return Object.freeze({ template, templateRef: input.templateRef, assertUnchanged: original.assertUnchanged });
  }
  const grant = readAuthorizationGrant(driver, template.provenance.sourceAuthorizationGrantId);
  if (!grant || grant.state !== 'consumed' || grant.consumptionReceiptRef !== template.provenance.sourceConsumptionReceiptRef) invalid();
  const { readDependencyScriptsAuthorizationHistory } = await import('./authorization.js');
  const history = await readDependencyScriptsAuthorizationHistory(driver, reads, owner, grant, runtime.releaseKeys, signal);
  const consumption = history.consumption;
  if (!consumption || consumption.templateRef !== input.templateRef || !same(consumption.template, template)) invalid();
  consumption.assertUnchanged(driver); reads.assertReadActive();
  return Object.freeze({ template, templateRef: input.templateRef, assertUnchanged: consumption.assertUnchanged });
}

/** Execution preparation still requires its genuine current owner. Data-only
 * recovery uses the explicit retained helper and never casts an owner shape. */
export async function readDependencyScriptsTemplateHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, input: { runId: string; templateRef: string }, signal?: AbortSignal) {
  assertActiveStateOwner(driver, owner);
  const result = await readDependencyScriptsTemplateHistoryData(driver, artifacts, runtime, input, signal);
  assertActiveStateOwner(driver, owner); return result;
}
