// The original signed profile is the only status contract. This reader
// cannot create a probe, native handle, new grant or effect resolution.
import { canonicalSha256 } from '../kernel/canonical.js';
import { planArtifactBytes, planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { identityHash } from '../kernel/identity.js';
import { decodeMcpRecoveryAdapterManifest, decodeMcpRecoveryPredicate, decodeMcpRecoveryStatusRequestTemplate,
  injectMcpIdempotencyKey, mcpServerExecutionIdentityDigest, mcpProfileSigningIdentityDigest } from '../kernel/mcp-recovery.js';
import { decodeMcpReconciliationSubject, type McpReconciliationSubject, type McpInvocationWaitV1 } from '../kernel/mcp-status.js';
import { mcpToolsCallRequestData } from '../kernel/mcp-wire.js';
import type { InvocationJournalEntry, RecoveryClosureV1, RunAssemblyV1 } from '../kernel/types.js';
import { verifyMcpRecoveryAdapterAuthority } from '../policy/mcp-recovery-authority.js';
import { requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { compileInputSchema, compileOutputSchema } from '../tools/input-schema.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { readMcpAmbiguityHistory } from './mcp-execution.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import type { SqliteDriver } from './sqlite-driver.js';

function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
export async function readMcpReconcileSource(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'journal'>, opId: string, attempt: number) {
  const entries = cut.journal.filter(entry => entry.opId === opId && entry.attempt === attempt), [prepared, claim, unknown] = entries;
  if (cut.runSpec.operation !== 'agent' || entries.length !== 3 || prepared?.opKind !== 'mcp' || prepared.replayClass !== 'reconcile' ||
      prepared.phase !== 'prepared' || claim?.phase !== 'dispatch_claimed' || unknown?.phase !== 'unknown' ||
      entries.some(entry => entry.opKind !== 'mcp' || entry.replayClass !== 'reconcile') ||
      cut.journal.some(entry => entry.opId === opId && entry.attempt !== attempt && entry.phase === 'dispatch_claimed'))
    fail('MCP read-only status has no sole original permanently claimed and wholly settled reconcile UNKNOWN');
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, cut.runSpec.assemblyRef);
  const original = await readMcpAmbiguityHistory(driver, artifacts, { prepared, claim, unknown, assembly });
  const transport = original.registry.registry.transport, recovery = original.toolContract.recovery;
  if (transport.kind !== 'stdio' || transport.executable.kind !== 'runtime_bundle' || !original.stdioInstance || !original.stdioClosed ||
      recovery.kind !== 'reconcile' || original.retryPolicy.replayClass !== 'reconcile' || original.retryPolicy.maxDispatchedAttempts !== 1 ||
      original.retryPolicy.postAttemptDelaysMs.length !== 0)
    fail('MCP read-only recovery cannot borrow HTTP, retry, manual or a non-retired original server');
  const executable = transport.executable;
  const workers = readWorkerLaunchesForRun(driver, cut.run.id).filter(worker => worker.leaseEpoch === claim.leaseEpoch);
  if (workers.length !== 1 || workers[0]!.phase !== 'retired' || !workers[0]!.retirementEvidenceRef || !workers[0]!.retiredAt ||
      workers[0]!.retiredAt < unknown.timestamp || cut.run.activeWorkerLaunchId === workers[0]!.launchId)
    fail('MCP status recovery cannot overtake its original effect worker physical retirement');
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
  const template = decodeMcpRecoveryStatusRequestTemplate(await readCanonicalArtifact(artifacts, recovery.statusRequestTemplateRef));
  const rawManifest = decodeMcpRecoveryAdapterManifest(await readCanonicalArtifact(artifacts, recovery.adapterRef));
  const manifest = verifyMcpRecoveryAdapterAuthority({ bundle, releaseKeys: artifacts.releaseTrustRoots(), adapterId: rawManifest.adapterId,
    adapterRef: recovery.adapterRef, manifest: rawManifest });
  const profiles = manifest.profiles.filter(profile => profile.profileId === recovery.profileId && profile.profileDigest === recovery.profileDigest), profile = profiles[0];
  if (profiles.length !== 1 || !profile || manifest.adapterDigest !== recovery.adapterDigest ||
      template.adapterRef !== recovery.adapterRef || template.adapterDigest !== recovery.adapterDigest ||
      template.profileId !== recovery.profileId || template.profileDigest !== recovery.profileDigest || template.templateDigest !== recovery.statusRequestTemplateDigest ||
      template.registrationId !== original.registry.registry.registrationId || template.registryRevision !== original.registry.registry.registryRevision ||
      template.serverToolName !== original.execution.serverToolName || template.serverExecutionIdentityDigest !== mcpServerExecutionIdentityDigest(transport) ||
      template.profileSigningIdentityDigest !== mcpProfileSigningIdentityDigest(transport) || template.profileSigningIdentityDigest !== profile.profileSigningIdentityDigest ||
      template.initializeDigest !== original.registry.registry.initializeDigest || template.capabilityDigest !== original.registry.registry.capabilityDigest ||
      template.probedToolsListDigest !== original.registry.registry.probedToolsListDigest || template.effectToolInterfaceDigest !== original.toolContract.interfaceDigest ||
      template.idempotencyKeyJsonPointer !== recovery.idempotencyKeyInjection.jsonPointer)
    fail('MCP status recovery changed its exact original signed executable/profile/template/registration closure');
  for (const name of ['statusOperationName', 'statusOperationSemantics', 'statusToolInterfaceDigest', 'statusInputSchemaDigest', 'statusOutputSchemaDigest',
    'staticArgumentsRef', 'staticArgumentsDigest'] as const) requireEqual(template[name], profile[name], `MCP signed original status ${name}`);
  const completed = decodeMcpRecoveryPredicate(await readCanonicalArtifact(artifacts, recovery.completedPredicateRef));
  const failed = decodeMcpRecoveryPredicate(await readCanonicalArtifact(artifacts, recovery.failedPredicateRef));
  if (completed.predicateDigest !== recovery.completedPredicateDigest || failed.predicateDigest !== recovery.failedPredicateDigest ||
      recovery.completedPredicateRef !== profile.completedPredicateRef || recovery.completedPredicateDigest !== profile.completedPredicateDigest ||
      recovery.failedPredicateRef !== profile.failedPredicateRef || recovery.failedPredicateDigest !== profile.failedPredicateDigest)
    fail('MCP status recovery substitutes unsigned or mismatching completion/failure predicates');
  const staticArguments = await readCanonicalArtifact(artifacts, template.staticArgumentsRef);
  if (canonicalSha256(staticArguments) !== template.staticArgumentsDigest) fail('MCP status static arguments lost their exact complete-byte identity');
  const key = identityHash('cliq-mcp-tool-idempotency-v1', cut.run.id, opId, original.registry.ref, original.execution.serverToolName);
  if (original.request.idempotencyKey !== key || prepared.idempotencyKey !== key) fail('MCP status changes the original frozen logical call key');
  const argumentsValue = injectMcpIdempotencyKey(staticArguments, template.idempotencyKeyJsonPointer, key);
  const statusInputSchema = await readCanonicalArtifact(artifacts, template.statusInputSchemaDigest);
  const statusOutputSchema = await readCanonicalArtifact(artifacts, template.statusOutputSchemaDigest);
  if (!compileInputSchema(statusInputSchema)(argumentsValue)) fail('MCP signed status arguments fail their exact registered input schema');
  const validateOutput = compileOutputSchema(statusOutputSchema);
  const statusRequest = mcpToolsCallRequestData(3, template.statusOperationName, argumentsValue);
  const subject: McpReconciliationSubject = decodeMcpReconciliationSubject({ kind: 'invocation', recovery: 'mcp_reconcile', opKind: 'mcp', opId, attempt,
    registryRevisionRef: original.registry.ref, registryManifestDigest: original.registry.registry.manifestDigest, serverToolName: original.execution.serverToolName,
    profileId: profile.profileId, profileDigest: profile.profileDigest, statusRequestTemplateRef: recovery.statusRequestTemplateRef,
    statusRequestTemplateDigest: recovery.statusRequestTemplateDigest, completedPredicateRef: recovery.completedPredicateRef,
    completedPredicateDigest: recovery.completedPredicateDigest, failedPredicateRef: recovery.failedPredicateRef, failedPredicateDigest: recovery.failedPredicateDigest });
  return { prepared, claim, unknown, entries: entries as readonly InvocationJournalEntry[], spec: cut.runSpec, assembly, original, registry: original.registry, bundle, transport, executable,
    recovery, template, manifest, profile, subject, statusRequest, argumentsValue, statusInputSchema, statusOutputSchema, validateOutput, completed, failed, oldWorker: workers[0]! };
}

/** Acyclic original source data. Only its producer may register a nonce;
 * these inert artifacts contain no later in-flight wait or dispatch digest. */
export function mcpReadonlyStatusRequestData(source: Awaited<ReturnType<typeof readMcpReconcileSource>>, input: Readonly<{
  previousWaitingSubjectRef: string; wait: McpInvocationWaitV1; probeKind: 'automatic' | 'user_requested'; probeOrdinal: number;
  probeNonceDigest: string; probeStartedAt: string; probeDeadlineAt: string; supervisorInstanceId: string; stateOwnerEpoch: number;
}>) {
  requireEqual(input.wait.subject, source.subject, 'MCP status exact original pending subject');
  const statusRequest = planArtifactBytes(Buffer.from(source.statusRequest.json), 'application/json', 'cliq-mcp-status-request-frame-v1');
  if (statusRequest.ref !== source.statusRequest.digest || input.previousWaitingSubjectRef !== canonicalSha256(input.wait))
    fail('MCP status request lost its complete exact fixed frame or original pending wait bytes');
  const targetCore = { schemaVersion: 1 as const, format: 'cliq-mcp-readonly-status-target-v1' as const, runId: source.prepared.runId,
    principalId: source.original.principalId, previousWaitingSubjectRef: input.previousWaitingSubjectRef,
    reconciliationSubjectDigest: canonicalSha256(source.subject), originalOpId: source.claim.opId, originalAttempt: source.claim.attempt,
    preparedJournalSeq: source.prepared.seq, dispatchJournalSeq: source.claim.seq, unknownJournalSeq: source.unknown.seq,
    originalDispatchId: source.claim.dispatchId!, originalRequestRef: source.prepared.requestRef, originalTargetRef: source.prepared.target,
    originalGrantRef: source.prepared.grantRef!, originalInstanceIdentityRef: source.claim.evidenceRef!, originalInstanceIdentityDigest: source.claim.evidenceDigest!,
    registryRevisionRef: source.registry.ref, registryManifestDigest: source.registry.registry.manifestDigest, transport: source.transport,
    effectServerToolName: source.original.execution.serverToolName, adapterRef: source.recovery.adapterRef, adapterDigest: source.recovery.adapterDigest,
    adapterExecutableId: source.manifest.entryId, adapterExecutableDigest: source.manifest.executableDigest, profileId: source.profile.profileId,
    profileDigest: source.profile.profileDigest, statusRequestTemplateRef: source.recovery.statusRequestTemplateRef,
    statusRequestTemplateDigest: source.recovery.statusRequestTemplateDigest, statusOperationName: source.template.statusOperationName,
    statusRequestRef: statusRequest.ref, statusRequestDigest: source.statusRequest.digest };
  const target = { ...targetCore, targetDigest: canonicalSha256(targetCore) }, targetArtifact = planCanonicalArtifact(target, target.format);
  const requestCore = { schemaVersion: 1 as const, format: 'cliq-mcp-readonly-status-request-v1' as const, runId: source.prepared.runId,
    principalId: source.original.principalId, previousWaitingSubjectRef: input.previousWaitingSubjectRef,
    reconciliationSubjectDigest: canonicalSha256(source.subject), targetRef: targetArtifact.ref, targetDigest: target.targetDigest,
    probeKind: input.probeKind, probeOrdinal: input.probeOrdinal, probeNonceDigest: input.probeNonceDigest,
    probeStartedAt: input.probeStartedAt, probeDeadlineAt: input.probeDeadlineAt,
    supervisorInstanceId: input.supervisorInstanceId, stateOwnerEpoch: input.stateOwnerEpoch,
    statusRequestRef: statusRequest.ref, statusRequestDigest: source.statusRequest.digest };
  const request = { ...requestCore, requestDigest: canonicalSha256(requestCore) }, requestArtifact = planCanonicalArtifact(request, request.format);
  return { statusRequest, target, targetArtifact, request, requestArtifact };
}
