// Recorded data closure only. A decoded artifact never proves a physical
// failed release: only the private installed Store owns that native producer.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeBrokerInvocationAmbiguity, type BrokerInvocationAmbiguityEvidenceV1 } from '../kernel/broker-ambiguity.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { decodeModelOperationGrant } from '../kernel/model-grant.js';
import type { InvocationJournalEntry, Run, RunAssemblyV1, RunFrontier, RunSpec } from '../kernel/types.js';
import type { ModelCapabilityEvidenceV1 } from '../model/capabilities.js';
import type { SignedModelCatalogEntryV1 } from '../model/installed-authority.js';
import type { ModelRequestV1 } from '../model/request.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { exactKeys, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeRunSpec } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { readModelGrantData } from './model-grant.js';
import { MODEL_BROKER_ENTRY_ID, MODEL_BROKER_RELATIVE_PATH } from './model-broker-native.js';
import { readHighestPreparedAttempt, readInvocationAttempt } from './repositories/journal.js';
import { readRun, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';

const same = (left: unknown, right: unknown) => canonicalSha256(left) === canonicalSha256(right);
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'installed broker ambiguity does not close its original permanent claim'); }
function isInstalledBroker(assembly: RunAssemblyV1): boolean { return assembly.provider.adapter.adapterId === MODEL_BROKER_ENTRY_ID; }

/** Reproduce the original admission's immutable model catalog/Bundle links.
 * Publisher authentication remains the installed admission/release gate; this
 * reader has no trust roots and never treats a catalog's own key as authority. */
async function retainedRecipe(artifacts: ArtifactCatalog, run: Run, spec: RunSpec, assembly: RunAssemblyV1) {
  if (spec.operation !== 'agent' || canonicalSha256(spec) !== run.specRef || canonicalSha256(assembly) !== spec.assemblyRef ||
      assembly.provider.name !== 'openai-compatible' || assembly.provider.endpoint.kind !== 'registered' ||
      assembly.provider.adapter.version !== '1' || assembly.provider.negotiation.streaming) invalid();
  const capability = await readCanonicalArtifact<ModelCapabilityEvidenceV1>(artifacts, assembly.provider.negotiation.capabilityEvidenceRef);
  if (!exactKeys(capability, ['schemaVersion', 'format', 'provider', 'model', 'endpointIdentityDigest', 'adapter', 'source',
    'nativeToolCalling', 'streaming', 'trustedUsageEvidence', 'contextLimitTokens', 'maxOutputTokens', 'observedAt', 'validThrough', 'evidenceDigest']) ||
      capability.schemaVersion !== 1 || capability.format !== 'cliq-model-capability-evidence-v1' ||
      capability.source?.kind !== 'signed_catalog' || !exactKeys(capability.source, ['kind', 'runtimeBundleRef', 'catalogEntryRef', 'catalogEntryDigest']) ||
      capability.evidenceDigest !== assembly.provider.negotiation.capabilityDigest || capability.evidenceDigest !== digestOmitting(capability, 'evidenceDigest') ||
      capability.provider !== assembly.provider.name || capability.model !== assembly.provider.model ||
      capability.endpointIdentityDigest !== assembly.provider.endpoint.endpointIdentityDigest || !same(capability.adapter, assembly.provider.adapter) ||
      capability.source.runtimeBundleRef !== assembly.runtime.runtimeBundleRef) invalid();
  const catalog = await readCanonicalArtifact<SignedModelCatalogEntryV1>(artifacts, capability.source.catalogEntryRef);
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
  const adapter = bundle.entries.filter(entry => entry.entryId === MODEL_BROKER_ENTRY_ID);
  if (!exactKeys(catalog, ['schemaVersion', 'format', 'signerKeyId', 'signatureAlgorithm', 'signatureRef', 'runtimeBundleRef',
    'runtimeBundleManifestDigest', 'provider', 'model', 'endpointIdentityDigest', 'adapter', 'claims', 'validFrom', 'validThrough', 'catalogEntryDigest']) ||
      catalog.schemaVersion !== 1 || catalog.format !== 'cliq-signed-model-catalog-entry-v1' || catalog.signatureAlgorithm !== 'ed25519' ||
      catalog.signerKeyId !== bundle.publisherKeyId || catalog.runtimeBundleRef !== assembly.runtime.runtimeBundleRef ||
      catalog.runtimeBundleManifestDigest !== assembly.runtime.runtimeBundleManifestDigest || bundle.manifestDigest !== assembly.runtime.runtimeBundleManifestDigest ||
      catalog.catalogEntryDigest !== capability.source.catalogEntryDigest || catalog.provider !== capability.provider || catalog.model !== capability.model ||
      catalog.endpointIdentityDigest !== capability.endpointIdentityDigest || !same(catalog.adapter, capability.adapter) ||
      adapter.length !== 1 || !adapter[0]!.executable || adapter[0]!.role !== 'provider_adapter' ||
      adapter[0]!.relativePath !== MODEL_BROKER_RELATIVE_PATH || adapter[0]!.version !== assembly.provider.adapter.version ||
      adapter[0]!.digest !== assembly.provider.adapter.codeDigest) invalid();
  const { signatureRef: _signature, catalogEntryDigest: _digest, ...core } = catalog;
  if (canonicalSha256(core) !== catalog.catalogEntryDigest || (await artifacts.readBytes(catalog.signatureRef)).length !== 64 ||
      !exactKeys(catalog.claims, ['nativeToolCalling', 'streaming', 'trustedUsageEvidence', 'contextLimitTokens', 'maxOutputTokens'])) invalid();
  for (const key of ['nativeToolCalling', 'streaming', 'trustedUsageEvidence', 'contextLimitTokens', 'maxOutputTokens'] as const)
    if (catalog.claims[key] !== capability[key] || capability[key] !== assembly.provider.negotiation[key]) invalid();
  for (const time of [capability.observedAt, capability.validThrough, catalog.validFrom, catalog.validThrough]) parseCanonicalTime(time);
  if (catalog.validFrom > capability.observedAt || capability.observedAt > run.createdAt ||
      catalog.validThrough !== capability.validThrough || capability.validThrough < run.deadlineAt) invalid();
}

type Frame = { run: Run; spec: RunSpec; assembly: RunAssemblyV1; principalId: string;
  prepared: InvocationJournalEntry; claim: InvocationJournalEntry; evidence: BrokerInvocationAmbiguityEvidenceV1 };

async function validateOriginalFrame(driver: SqliteDriver, artifacts: ArtifactCatalog, frame: Frame, timestamp: string) {
  const { run, spec, assembly, principalId, prepared, claim, evidence } = frame;
  if (!principalId || readSessionPrincipalId(driver, run.sessionId) !== principalId ||
      driver.prepare('SELECT principal_id FROM runs WHERE id=?').get<{ principal_id: string }>(run.id)?.principal_id !== principalId ||
      prepared.phase !== 'prepared' || claim.phase !== 'dispatch_claimed' || prepared.opKind !== 'model' || claim.opKind !== 'model' ||
      claim.runId !== run.id || prepared.runId !== run.id || claim.opId !== prepared.opId || claim.attempt !== prepared.attempt ||
      !prepared.grantRef || claim.grantRef !== prepared.grantRef || claim.requestRef !== prepared.requestRef || claim.target !== prepared.target ||
      claim.leaseEpoch !== prepared.leaseEpoch || claim.seq <= prepared.seq || claim.timestamp < prepared.timestamp ||
      !claim.brokerFenceTokenDigest || claim.sandboxLaunchSpecRef !== undefined ||
      evidence.runId !== run.id || evidence.opId !== prepared.opId || evidence.opKind !== 'model' || evidence.attempt !== prepared.attempt ||
      evidence.dispatchId !== claim.dispatchId || evidence.dispatchJournalSeq !== claim.seq ||
      evidence.claimingSupervisorInstanceId !== claim.supervisorInstanceId || evidence.claimingStateOwnerEpoch !== claim.stateOwnerEpoch ||
      evidence.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest || evidence.operationRequestRef !== prepared.requestRef ||
      evidence.operationTargetRef !== prepared.target || evidence.observedAt !== timestamp || evidence.observedAt < claim.timestamp) invalid();
  const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, prepared.requestRef);
  if (request.schemaVersion !== 1 || request.format !== 'cliq-model-request-v1' || request.attempt !== prepared.attempt ||
      !same(prepared.budgetDelta, { modelTokens: request.reservation.modelTokens, costMicros: request.reservation.costMicros,
        toolCalls: 0, repairAttempts: 0 })) invalid();
  const original = decodeModelOperationGrant(await readCanonicalArtifact(artifacts, prepared.grantRef));
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, original.frontierRef);
  if (frontier.kind !== 'agent') invalid();
  const authority = await readModelGrantData(artifacts, { principalId, run, spec, assembly, frontier,
    frontierRef: original.frontierRef, request, requestRef: prepared.requestRef, grantRef: prepared.grantRef });
  if (evidence.frontierRef !== authority.grant.frontierRef || evidence.operationRequestDigest !== request.requestDigest ||
      evidence.operationTargetRef !== authority.targetRef || evidence.operationTargetDigest !== authority.targetDigest ||
      prepared.timestamp < authority.grant.issuedAt || claim.timestamp >= authority.grant.expiresAt || claim.timestamp >= run.deadlineAt) invalid();
  const claiming = readStateOwner(driver, evidence.claimingStateOwnerEpoch);
  if (!claiming || claiming.supervisorInstanceId !== evidence.claimingSupervisorInstanceId ||
      claiming.acquiredAt > claim.timestamp || (claiming.state === 'terminal' && claiming.releasedAt < timestamp)) invalid();
  const inspector = await readSupervisorInspector(artifacts, claiming, assembly, evidence);
  if (!same(inspector, supervisorInspectorIdentity(claiming))) invalid();
  return { authority, claiming };
}

export type InstalledBrokerAmbiguityPlan = {
  metadata: PublishedArtifact[]; unknownEvidence: { evidenceRef: string; evidenceDigest: string };
  validate(connection: SqliteConnection, currentRun: Run, committedAt: string): void;
};

/** Restage an actual private producer's prototype at the settlement's canonical
 * time. No caller-selected clock or physical observation can enter this plan. */
export async function prepareInstalledBrokerAmbiguity(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { run: Run; prepared: InvocationJournalEntry; claim: InvocationJournalEntry | undefined;
    evidenceRef: string; evidenceDigest: string; settledAt: string }): Promise<InstalledBrokerAmbiguityPlan | undefined> {
  if (input.prepared.opKind !== 'model') return undefined;
  const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, input.run.specRef));
  const raw = await readCanonicalArtifact<{ format?: string }>(artifacts, spec.assemblyRef);
  if (raw.format !== 'cliq-run-assembly-v1') return undefined;
  const assembly = decodeRetainedRunAssembly(raw);
  if (!isInstalledBroker(assembly)) return undefined;
  if (!input.claim) invalid();
  await retainedRecipe(artifacts, input.run, spec, assembly);
  const prototype = decodeBrokerInvocationAmbiguity(await readCanonicalArtifact(artifacts, input.evidenceRef));
  if (prototype.evidenceDigest !== input.evidenceDigest || prototype.observedAt > input.settledAt) invalid();
  const principalId = readSessionPrincipalId(driver, input.run.sessionId);
  const frame: Frame = { run: input.run, spec, assembly, principalId, prepared: input.prepared, claim: input.claim, evidence: prototype };
  const original = await validateOriginalFrame(driver, artifacts, frame, prototype.observedAt);
  const evidence: BrokerInvocationAmbiguityEvidenceV1 = { ...prototype, observedAt: input.settledAt, evidenceDigest: '' };
  evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); decodeBrokerInvocationAmbiguity(evidence);
  const active = assertActiveStateOwner(driver, owner);
  if (original.claiming.state !== 'active' || !same(original.claiming, active) || input.run.frontierRef !== original.authority.grant.frontierRef ||
      input.run.nextStep !== 'agent') invalid();
  const artifact = await artifacts.publishCanonical(evidence, evidence.format);
  const inspector = await artifacts.describe(evidence.inspectorIdentityRef, 'application/json', 'cliq-supervisor-inspector-identity-v1');
  return { metadata: [artifact, inspector], unknownEvidence: { evidenceRef: artifact.ref, evidenceDigest: evidence.evidenceDigest },
    validate(connection, currentRun, committedAt) {
      const liveOwner = assertActiveStateOwner(connection, owner);
      const live = readRun(connection, currentRun.id), entries = readInvocationAttempt(connection, currentRun.id, input.prepared.opId, input.prepared.attempt);
      if (!same(liveOwner, active) || !same(live, input.run) || !same(currentRun, input.run) ||
          currentRun.specRef !== canonicalSha256(spec) || currentRun.frontierRef !== evidence.frontierRef || currentRun.nextStep !== 'agent' ||
          readSessionPrincipalId(connection, currentRun.sessionId) !== principalId ||
          connection.prepare('SELECT principal_id FROM runs WHERE id=?').get<{ principal_id: string }>(currentRun.id)?.principal_id !== principalId ||
          entries.length !== 2 || !same(entries[0], input.prepared) || !same(entries[1], input.claim) ||
          readHighestPreparedAttempt(connection, currentRun.id, input.prepared.opId)?.seq !== input.prepared.seq ||
          evidence.observedAt !== input.settledAt || committedAt < evidence.observedAt) invalid();
    } };
}

/** Historical unknowns bind their original grant/frontier and claiming owner,
 * not the current continuation or whichever Supervisor later opens the Run. */
export async function validateInstalledBrokerAmbiguityHistory(input: { driver: SqliteDriver; artifacts: ArtifactCatalog;
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; journal: readonly InvocationJournalEntry[]; principalId: string }): Promise<void> {
  if (!isInstalledBroker(input.assembly)) return;
  await retainedRecipe(input.artifacts, input.run, input.spec, input.assembly);
  for (const unknown of input.journal.filter(entry => entry.opKind === 'model' && entry.phase === 'unknown')) {
    if (!unknown.evidenceRef || !unknown.evidenceDigest) invalid();
    const before = input.journal.filter(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt && entry.seq < unknown.seq);
    if (before.length !== 2 || !same(unknown.budgetDelta, before[0]!.budgetDelta)) invalid();
    const evidence = decodeBrokerInvocationAmbiguity(await readCanonicalArtifact(input.artifacts, unknown.evidenceRef));
    if (evidence.evidenceDigest !== unknown.evidenceDigest || unknown.dispatchId !== before[1]!.dispatchId ||
        unknown.supervisorInstanceId !== before[1]!.supervisorInstanceId || unknown.stateOwnerEpoch !== before[1]!.stateOwnerEpoch ||
        unknown.brokerFenceTokenDigest !== before[1]!.brokerFenceTokenDigest || unknown.requestRef !== before[0]!.requestRef ||
        unknown.target !== before[0]!.target || unknown.grantRef !== before[0]!.grantRef || unknown.leaseEpoch !== before[0]!.leaseEpoch) invalid();
    await validateOriginalFrame(input.driver, input.artifacts, { ...input, prepared: before[0]!, claim: before[1]!, evidence }, unknown.timestamp);
  }
}
