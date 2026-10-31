import { canonicalSha256 } from '../kernel/canonical.js';
import type { AuthorizationGrantV1 } from '../kernel/authorization.js';
import type { VerifierRequest } from '../kernel/control-submit.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { Run, RunSpec, VerifierSpec } from '../kernel/types.js';
import type { VerifierAuthorizationTemplateV1, VerifierTemplateRootV1 } from '../kernel/verifier-invocation.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { controlWireInteger, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeAuthorizationConsumptionReceipt, VerifierAuthorizationError } from './authorization-artifacts.js';
import { readAuthorizationGrant } from './repositories/authorization-grants.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readControlRequest, readRun } from './rows.js';
import { decodeVerifierSpec } from './verifier-artifacts.js';
import { readVerifierExecutionAuthorizationHistory } from './authorization.js';
import { readRetainedControlRoot } from './control-channel.js';
import { composeVerifierSpec } from './verifier-admission.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';

export function verifierRequestCoreDigest(request: VerifierRequest): string {
  const { executionGrantId: _execution, ...core } = request;
  return canonicalSha256(core);
}

/** A deterministic artifact relation, never a grant consumer or a live permit. */
export function composeVerifierTemplate(input: {
  runId: string; deadlineAt: string; sourceProjectionRef: string; spec: VerifierSpec; verifierIndex: number;
  request: VerifierRequest; grant: AuthorizationGrantV1; receiptRef: string; maxCandidateGenerations: number;
}): VerifierAuthorizationTemplateV1 {
  const { spec, request, grant, verifierIndex } = input, entry = spec.verifiers[verifierIndex], target = grant.target;
  if (!entry || target.kind !== 'verifier_execution' || request.executionGrantId !== grant.grantId || request.id !== entry.id ||
      request.version !== entry.version || request.required !== (entry.gate === 'required') || target.verifierId !== entry.id ||
      target.executionIdentityGrantId !== request.identityReadGrantId || target.verifierRequestCoreDigest !== verifierRequestCoreDigest(request) ||
      target.maxCandidateGenerations !== input.maxCandidateGenerations || target.maxAttemptsPerCandidate !== entry.retries + 1)
    throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
  const template: VerifierAuthorizationTemplateV1 = { schemaVersion: 1, format: 'cliq-verifier-authorization-template-v1',
    runId: input.runId, verifierSpecRef: canonicalSha256(spec), verifierSpecDigest: spec.specDigest, verifierIndex,
    verifierId: entry.id, verifierVersion: entry.version, verifierEntryDigest: entry.entryDigest,
    commandRef: entry.commandRef, commandDigest: entry.commandDigest, environmentRef: entry.environmentRef,
    environmentDigest: entry.environmentDigest, sourceProjectionRef: input.sourceProjectionRef,
    maxCandidateGenerations: input.maxCandidateGenerations, maxAttempts: entry.retries + 1,
    expiresAt: input.deadlineAt, decisionRef: input.receiptRef, templateDigest: '' };
  template.templateDigest = digestOmitting(template, 'templateDigest');
  return decodeVerifierAuthorizationTemplate(template);
}

export function decodeVerifierAuthorizationTemplate(value: unknown): VerifierAuthorizationTemplateV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !exactKeys(value, ['schemaVersion', 'format', 'runId',
    'verifierSpecRef', 'verifierSpecDigest', 'verifierIndex', 'verifierId', 'verifierVersion', 'verifierEntryDigest',
    'commandRef', 'commandDigest', 'environmentRef', 'environmentDigest', 'sourceProjectionRef', 'maxCandidateGenerations',
    'maxAttempts', 'expiresAt', 'decisionRef', 'templateDigest'])) throw new TypeError('invalid closed verifier template');
  const data = value as VerifierAuthorizationTemplateV1;
  if (data.schemaVersion !== 1 || data.format !== 'cliq-verifier-authorization-template-v1') throw new TypeError('invalid verifier template kind');
  for (const key of ['runId', 'verifierId', 'verifierVersion'] as const) controlWireText(data[key]);
  for (const key of ['verifierSpecRef', 'verifierSpecDigest', 'verifierEntryDigest', 'commandRef', 'commandDigest',
    'environmentRef', 'environmentDigest', 'sourceProjectionRef', 'decisionRef', 'templateDigest'] as const) controlWireRef(data[key]);
  controlWireInteger(data.verifierIndex, 0, 31); controlWireInteger(data.maxCandidateGenerations, 1, 6); controlWireInteger(data.maxAttempts, 1, 4);
  parseCanonicalTime(data.expiresAt);
  if (data.templateDigest !== digestOmitting(data, 'templateDigest')) throw new TypeError('verifier template digest differs');
  return data;
}

export function verifierTemplateRoots(templates: readonly VerifierAuthorizationTemplateV1[]): VerifierTemplateRootV1[] {
  const roots = templates.map(template => ({ verifierIndex: template.verifierIndex, templateRef: canonicalSha256(template), templateDigest: template.templateDigest }));
  if (roots.some((root, index) => index > 0 && root.verifierIndex <= roots[index - 1]!.verifierIndex))
    throw new TypeError('verifier template roots must have unique original verifier order');
  return roots;
}

/** Rebuild the original root set from its one real admission consumer. No
 * missing template is regenerated or substituted with a policy grant. */
export async function readAdmittedVerifierTemplates(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  run: Run; spec: RunSpec; requests: readonly { verifierIndex: number; request: VerifierRequest }[];
  admissionIntentDigest: string; principalId: string;
}) {
  if (!input.requests.some(({ request }) => request.executionGrantId !== undefined)) return { templates: [], roots: [] };
  const spec = decodeVerifierSpec(await readCanonicalArtifact(artifacts, input.spec.verifierSpecRef));
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, input.spec.assemblyRef));
  const templates: VerifierAuthorizationTemplateV1[] = [];
  for (const { verifierIndex, request } of input.requests) {
    if (request.executionGrantId === undefined) continue;
    const grant = readAuthorizationGrant(driver, request.executionGrantId);
    if (!grant || grant.state !== 'consumed' || grant.ownerPrincipalId !== input.principalId || grant.target.kind !== 'verifier_execution')
      throw new TypeError('verifier template lost its original consumed execution grant');
    const history = await readVerifierExecutionAuthorizationHistory(driver, artifacts, await readRetainedControlRoot(driver, artifacts), grant, artifacts.releaseTrustRoots());
    const original = composeVerifierSpec({ requests: [request], toolchain: history.selected, assembly, sourceProjectionRef: input.spec.sourceProjectionRef });
    const entry = { ...original.spec.verifiers[0]!, index: verifierIndex, entryDigest: '' };
    entry.entryDigest = digestOmitting(entry, 'entryDigest');
    requireEqual(entry, spec.verifiers[verifierIndex], 'verifier template exact original signed command, environment and frozen resources');
    const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(artifacts, grant.consumptionReceiptRef));
    requireEqual(receipt.consumer, { kind: 'run_admission', runId: input.run.id, admissionIntentDigest: input.admissionIntentDigest }, 'verifier template exact original consumer');
    if (receipt.grantId !== grant.grantId || receipt.ownerPrincipalId !== input.principalId || receipt.targetDigest !== grant.targetDigest ||
        receipt.consumedAt !== input.run.createdAt || grant.consumedAt !== receipt.consumedAt)
      throw new TypeError('verifier template differs from its actual one-use receipt');
    const expected = composeVerifierTemplate({ runId: input.run.id, deadlineAt: input.run.deadlineAt, sourceProjectionRef: input.spec.sourceProjectionRef,
      spec, verifierIndex, request, grant, receiptRef: grant.consumptionReceiptRef, maxCandidateGenerations: input.spec.budgets.repairAttempts + 1 });
    const actual = decodeVerifierAuthorizationTemplate(await readCanonicalArtifact(artifacts, canonicalSha256(expected)));
    requireEqual(actual, expected, 'verifier original complete template'); templates.push(actual);
  }
  return { templates, roots: verifierTemplateRoots(templates) };
}

/** Source lineage only; original grants are never inherited as execution
 * permission. The existing complete child/Delivery readers close each edge. */
export async function readOriginalVerifierRequests(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string,
  signal?: AbortSignal, seen = new Set<string>()): Promise<VerifierRequest[]> {
  signal?.throwIfAborted();
  if (seen.has(runId)) throw new TypeError('verifier request source lineage is cyclic');
  seen.add(runId);
  const run = readRun(driver, runId);
  if (run.parentRunId) {
    const child = await (await import('./child-admission.js')).readChildAdmission(driver, artifacts, runId, { signal });
    return child.rootOrigin.verifierRequests;
  }
  const row = driver.prepare('SELECT admission_method,admission_request_id,principal_id FROM runs WHERE id=?')
    .get<{ admission_method: string; admission_request_id: string; principal_id: string }>(runId);
  if (row?.admission_method === 'run.apply') {
    const original = readControlRequest(driver, row.principal_id, 'run.apply', row.admission_request_id);
    if (!original) throw new TypeError('Delivery verifier lineage lost its original request');
    const core = await readCanonicalArtifact<Record<string, unknown>>(artifacts, original.requestDigest);
    const { normalizeRunApplyRequest } = await import('../kernel/control-apply.js');
    const request = normalizeRunApplyRequest({ ...core, requestDigest: original.requestDigest }).request;
    // The enclosing original Delivery admission/source reader validates this
    // edge; this helper follows only its already-pinned immutable request.
    return readOriginalVerifierRequests(driver, artifacts, request.sourceRunId, signal, seen);
  }
  return (await (await import('./run-admission-origin.js')).readRootRunAdmissionOrigin(driver, artifacts, runId, { signal })).verifierRequests;
}

/** Closed one-to-one mapping from a fresh grant to the exact inherited
 * request. Only the explicit identity locator and execution grant are rebound. */
export async function mapDeliveryVerifierRequests(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  sourceRunId: string; spec: RunSpec; grantIds: readonly string[]; principalId: string;
}, signal?: AbortSignal) {
  if (!input.grantIds.length) return [];
  const spec = decodeVerifierSpec(await readCanonicalArtifact(artifacts, input.spec.verifierSpecRef));
  const originals = await readOriginalVerifierRequests(driver, artifacts, input.sourceRunId, signal), mapped: Array<{ verifierIndex: number; request: VerifierRequest }> = [];
  for (const grantId of input.grantIds) {
    signal?.throwIfAborted(); const grant = readAuthorizationGrant(driver, grantId), target = grant?.target;
    if (!grant || grant.ownerPrincipalId !== input.principalId || target?.kind !== 'verifier_execution')
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const matches = originals.map((request, verifierIndex) => ({ request, verifierIndex })).filter(({ request }) => request.id === target.verifierId);
    if (matches.length !== 1) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const { request: original, verifierIndex } = matches[0]!, entry = spec.verifiers[verifierIndex];
    if (!entry || entry.id !== original.id || entry.version !== original.version || entry.gate !== (original.required ? 'required' : 'advisory') ||
        mapped.some(value => value.verifierIndex === verifierIndex)) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const request = { ...original, identityReadGrantId: target.executionIdentityGrantId, executionGrantId: grant.grantId };
    if (verifierRequestCoreDigest(request) !== target.verifierRequestCoreDigest) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    mapped.push({ verifierIndex, request });
  }
  return mapped.sort((left, right) => left.verifierIndex - right.verifierIndex);
}
