// Retained broker closure and its installed owning producer. Decoded data alone
// never proves a failed release, process death or a live installation.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeBrokerInvocationAmbiguity, type BrokerInvocationAmbiguityEvidenceV1 } from '../kernel/broker-ambiguity.js';
import { decodeBrokerProcessDomainDeath, decodeBrokerProcessDomainDeathDispatchClosure,
  type BrokerProcessDomainDeathEvidenceV1, type BrokerProcessDomainDeathDispatchClosureV1 } from '../kernel/broker-process-domain-death.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { decodeModelOperationGrant } from '../kernel/model-grant.js';
import type { InvocationJournalEntry, RecoveryClosureV1, Run, RunAssemblyV1, RunFrontier, RunSpec, TerminalDetail } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ModelCapabilityEvidenceV1 } from '../model/capabilities.js';
import type { SignedModelCatalogEntryV1 } from '../model/installed-authority.js';
import type { ModelRequestV1 } from '../model/request.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { exactKeys, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeBudgetSettlement, decodeRunSpec } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { readModelGrantData } from './model-grant.js';
import { MODEL_BROKER_ENTRY_ID, MODEL_BROKER_RELATIVE_PATH } from './model-broker-native.js';
import { readHighestPreparedAttempt, readInvocationAttempt, readInvocationJournal } from './repositories/journal.js';
import { readRun, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';
import { assertInstalledModelBrokerProcess, withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { stateRootIdentityForLock } from './native-owner.js';
import { readRetainedStateOwnerHistory, type RetainedStateOwnerHistory } from './state-owner-history.js';
import { stopInvocationHistory } from '../runtime/stop.js';
import { assertDeliveryModelFreeCut } from './run-model-free.js';

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

/** Shared immutable recipe closure; neither a live native token nor permission to release. */
export { retainedRecipe as validateRetainedInstalledBrokerRecipe };

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

type Abandonments = TerminalDetail['abandonedRetryInvocations'];
type TerminalFrame = Frame & { unknown: InvocationJournalEntry; entries: InvocationJournalEntry[] };

function terminalFailure(): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', 'terminal broker closure lacks its exact installed claim, owner and process-death graph');
}

/** Only still-unused model unknowns. Tool ambiguity belongs to its owning
 * rollback/reconciliation path, never a broker process-death proof. Positive
 * resolutions retain their ordinary result closure and immutable charges. */
function unusedUnknowns(journal: readonly InvocationJournalEntry[]): InvocationJournalEntry[] {
  return [...stopInvocationHistory(journal).values()].map(({ entry }) => entry)
    .filter(entry => entry.opKind === 'model' && entry.phase === 'unknown').sort((a, b) => a.seq - b.seq);
}

async function terminalFrames(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1): Promise<TerminalFrame[]> {
  if (cut.runSpec.operation === 'delivery') assertDeliveryModelFreeCut(cut);
  const unknowns = unusedUnknowns(cut.journal);
  if (!unknowns.length) return [];
  const { run, runSpec: spec } = cut;
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef));
  if (!isInstalledBroker(assembly) || assembly.runtime.sandboxBackend !== 'linux_namespace') terminalFailure();
  await retainedRecipe(artifacts, run, spec, assembly);
  const principalId = readSessionPrincipalId(driver, run.sessionId);
  const frames: TerminalFrame[] = [];
  for (const unknown of unknowns) {
    const entries = cut.journal.filter(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt);
    if (entries.length !== 3 || entries[0]!.phase !== 'prepared' || entries[1]!.phase !== 'dispatch_claimed' ||
        entries[2]!.seq !== unknown.seq || !unknown.evidenceRef || !unknown.budgetSettlementRef ||
        entries.some(entry => entry.runId !== run.id || entry.opKind !== 'model' || entry.replayClass !== 'retry')) terminalFailure();
    const [prepared, claim] = entries as [InvocationJournalEntry, InvocationJournalEntry, InvocationJournalEntry];
    const evidence = decodeBrokerInvocationAmbiguity(await readCanonicalArtifact(artifacts, unknown.evidenceRef));
    if (evidence.evidenceDigest !== unknown.evidenceDigest || !same(unknown.budgetDelta, prepared.budgetDelta)) terminalFailure();
    for (const key of ['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch', 'brokerFenceTokenDigest',
      'requestRef', 'target', 'grantRef', 'leaseEpoch', 'sandboxLaunchSpecRef'] as const)
      if (unknown[key] !== claim[key]) terminalFailure();
    const frame: TerminalFrame = { run, spec, assembly, principalId, prepared, claim, evidence, unknown, entries };
    // This is the ORIGINAL ambiguity/inspector and original unknown time, not
    // the newer process-death inspector masquerading as the claiming owner.
    await validateOriginalFrame(driver, artifacts, frame, unknown.timestamp);
    const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, unknown.budgetSettlementRef));
    if (settlement.runId !== run.id || settlement.opId !== unknown.opId || settlement.attempt !== unknown.attempt ||
        settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== unknown.seq ||
        settlement.terminalPhase !== 'unknown' || settlement.settledAt !== unknown.timestamp ||
        !same(settlement.reserved, prepared.budgetDelta) || !same(settlement.released, prepared.budgetDelta) ||
        !same(settlement.consumed, prepared.budgetDelta)) terminalFailure();
    frames.push(frame);
  }
  return frames;
}

function ownerFrame(history: RetainedStateOwnerHistory, epoch: number) {
  const entry = history.entries.find(entry => entry.owner.ownerEpoch === epoch);
  if (!entry) terminalFailure();
  return entry;
}

function terminalRecipe(history: RetainedStateOwnerHistory, frame: TerminalFrame) {
  const claiming = ownerFrame(history, frame.claim.stateOwnerEpoch!);
  if (history.rootIdentity.platform !== 'linux' || claiming.process.platform !== 'linux' ||
      claiming.owner.supervisorInstanceId !== frame.claim.supervisorInstanceId) terminalFailure();
  for (const { owner, process } of history.entries) {
    if (owner.runtimeBundleRef !== frame.assembly.runtime.runtimeBundleRef ||
        owner.runtimeBundleManifestDigest !== frame.assembly.runtime.runtimeBundleManifestDigest ||
        owner.supervisorEntryId !== claiming.owner.supervisorEntryId || owner.supervisorEntryVersion !== claiming.owner.supervisorEntryVersion ||
        owner.supervisorExecutableDigest !== claiming.owner.supervisorExecutableDigest || process.platform !== 'linux' ||
        process.ownerUid !== history.rootIdentity.ownerUid) terminalFailure();
  }
  return claiming;
}

function abandonment(frame: TerminalFrame, closureRef: string): Abandonments[number] {
  return { opId: frame.unknown.opId, attempt: frame.unknown.attempt, unknownJournalSeq: frame.unknown.seq,
    budgetSettlementRef: frame.unknown.budgetSettlementRef!, dispatchFenceOrDeathEvidenceRef: closureRef };
}

export type InstalledBrokerTerminalClosurePlan = Readonly<{
  metadata: PublishedArtifact[]; abandonedRetryInvocations: Abandonments;
  /** Repeats genuine observations; must precede the transaction's one clock sample. */
  reobserve(connection: SqliteConnection): void;
  validate(connection: SqliteConnection, currentRun: Run, committedAt: string): void;
}>;

/** The callback consumes the plan while its actual verified installation stays
 * borrowed through the terminal transaction. It supplies no observation, PID,
 * clock, credential, or proof. Generic loaded Runs cannot mint this branch. */
export async function withInstalledBrokerTerminalClosure<T>(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, selected: HeldInstalledRuntime | undefined, cut: RecoveryClosureV1,
  operation: (plan: InstalledBrokerTerminalClosurePlan) => Promise<T>): Promise<T> {
  if (cut.runSpec.operation === 'delivery') {
    assertDeliveryModelFreeCut(cut);
    assertActiveStateOwner(driver, owner);
    const unchanged = (connection: SqliteConnection, current = readRun(connection, cut.run.id)) => {
      assertActiveStateOwner(connection, owner);
      if (!same(current, cut.run) || !same(readRun(connection, cut.run.id), cut.run) ||
          !same(readInvocationJournal(connection, cut.run.id), cut.journal))
        terminalFailure();
    };
    // This is absence of any model invocation in an independently verified
    // model-free Run, not a claim that a token/process was killed or revoked.
    // Publisher/verifier retirement remains a separate required closure.
    unchanged(driver);
    return operation(Object.freeze({ metadata: [], abandonedRetryInvocations: [],
      reobserve(connection) { unchanged(connection); },
      validate(connection, currentRun) { unchanged(connection, currentRun); }
    }));
  }
  if (!unusedUnknowns(cut.journal).length) return operation(Object.freeze({
    metadata: [], abandonedRetryInvocations: [], reobserve() {}, validate() {}
  }));
  if (!selected || process.platform !== 'linux' || !cut.run.stopIntentRef) terminalFailure();
  return withHeldInstalledRuntime(selected, async installed => {
    assertInstalledModelBrokerProcess();
    // Brand lookup precedes caller properties. The native lock has its own
    // existing private brand, independently of the structural owner context.
    const root = stateRootIdentityForLock(owner.filesystem);
    const active = assertActiveStateOwner(driver, owner);
    const frames = await terminalFrames(driver, artifacts, cut);
    const history = await readRetainedStateOwnerHistory(driver, artifacts, active.ownerEpoch);
    const inspecting = ownerFrame(history, active.ownerEpoch);
    if (!same(inspecting.owner, active) || !same(root, history.rootIdentity) ||
        canonicalSha256(root) !== owner.stateRootIdentityRef || root.identityDigest !== owner.stateRootIdentityDigest ||
        root.canonicalAbsolutePath !== installed.stateRoot.canonicalPath || root.deviceId !== installed.stateRoot.deviceId ||
        root.directoryFileId !== installed.stateRoot.fileId || root.ownerUid !== installed.stateRoot.ownerUid ||
        installed.bundleDigest !== active.runtimeBundleRef || installed.bundle.manifestDigest !== active.runtimeBundleManifestDigest)
      terminalFailure();
    await installed.revalidate();
    const processIdentity = await (await installed.loadStateOwner()).observeCurrentProcess();
    if (processIdentity.pid !== process.pid || processIdentity.pid !== inspecting.process.pid ||
        processIdentity.processStartToken !== inspecting.process.processStartToken || processIdentity.uid !== root.ownerUid ||
        processIdentity.executableImageDigest !== active.supervisorExecutableDigest) terminalFailure();
    const inspector = supervisorInspectorIdentity(active);
    const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
    const metadata: PublishedArtifact[] = [inspectorArtifact];
    const observations: Array<{ frame: TerminalFrame; process: typeof inspecting.process; evidence: BrokerProcessDomainDeathEvidenceV1 }> = [];
    const abandonedRetryInvocations: Abandonments = [];
    for (const frame of frames) {
      const claiming = terminalRecipe(history, frame);
      if (active.ownerEpoch <= claiming.owner.ownerEpoch) terminalFailure();
      const observedAt = new Date(owner.filesystem.observePriorProcessDeath(claiming.process.pid, claiming.process.processStartToken)).toISOString();
      if (observedAt < frame.unknown.timestamp || observedAt < active.acquiredAt) terminalFailure();
      const evidence: BrokerProcessDomainDeathEvidenceV1 = {
        schemaVersion: 1, format: 'cliq-broker-process-domain-death-evidence-v1',
        runId: frame.run.id, opId: frame.claim.opId, attempt: frame.claim.attempt, dispatchId: frame.claim.dispatchId!,
        dispatchJournalSeq: frame.claim.seq, operationRequestRef: frame.claim.requestRef,
        operationTargetDigest: frame.evidence.operationTargetDigest, operationGrantRef: frame.claim.grantRef!,
        claimingSupervisorInstanceId: claiming.owner.supervisorInstanceId, claimingStateOwnerEpoch: claiming.owner.ownerEpoch,
        claimingProcessIdentityRef: claiming.owner.processIdentityRef, claimingProcessIdentityDigest: claiming.owner.processIdentityDigest,
        inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, inspectorStateOwnerEpoch: active.ownerEpoch,
        brokerFenceTokenDigest: frame.claim.brokerFenceTokenDigest!, authorityDomain: 'linux_installed_native_creator_process_v1',
        processObservation: 'absent_or_start_token_mismatch', observedAt, evidenceDigest: ''
      };
      evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); decodeBrokerProcessDomainDeath(evidence);
      const death = await artifacts.publishCanonical(evidence, evidence.format);
      const closure: BrokerProcessDomainDeathDispatchClosureV1 = {
        schemaVersion: 1, format: 'cliq-invocation-dispatch-closure-evidence-v1', runId: frame.run.id,
        opId: frame.claim.opId, attempt: frame.claim.attempt, dispatchId: frame.claim.dispatchId!, unknownJournalSeq: frame.unknown.seq,
        closure: { kind: 'broker_process_domain_dead', brokerProcessDeathEvidenceRef: death.ref,
          brokerProcessDeathEvidenceDigest: evidence.evidenceDigest }, observedAt, evidenceDigest: ''
      };
      closure.evidenceDigest = digestOmitting(closure, 'evidenceDigest'); decodeBrokerProcessDomainDeathDispatchClosure(closure);
      const dispatch = await artifacts.publishCanonical(closure, closure.format);
      metadata.push(death, dispatch); abandonedRetryInvocations.push(abandonment(frame, dispatch.ref));
      observations.push({ frame, process: claiming.process, evidence });
    }
    let fresh: number[] | undefined;
    return operation(Object.freeze({ metadata: immutableSnapshot(metadata), abandonedRetryInvocations: immutableSnapshot(abandonedRetryInvocations),
      reobserve(connection) {
        assertActiveStateOwner(connection, owner);
        fresh = observations.map(({ process }) => owner.filesystem.observePriorProcessDeath(process.pid, process.processStartToken));
      },
      validate(connection, currentRun, committedAt) {
        const live = assertActiveStateOwner(connection, owner);
        if (!same(live, active) || !same(currentRun, cut.run) || !same(readRun(connection, cut.run.id), cut.run) ||
            !fresh || fresh.length !== observations.length) terminalFailure();
        history.assertUnchanged(connection);
        for (const [index, { frame, evidence }] of observations.entries()) {
          const now = parseCanonicalTime(committedAt), recorded = parseCanonicalTime(evidence.observedAt);
          if (fresh[index]! < recorded || now < fresh[index]! || now - recorded > 5000 ||
              !same(readInvocationAttempt(connection, cut.run.id, frame.claim.opId, frame.claim.attempt), frame.entries) ||
              readSessionPrincipalId(connection, cut.run.sessionId) !== frame.principalId ||
              connection.prepare('SELECT principal_id FROM runs WHERE id=?').get<{ principal_id: string }>(cut.run.id)?.principal_id !== frame.principalId)
            terminalFailure();
        }
      }
    }));
  });
}

/** Retained-only terminal verification. It deliberately selects the inspector
 * recorded THEN, not today's active owner/installation or a new death clock. */
export async function validateInstalledBrokerTerminalHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, detail: TerminalDetail): Promise<Abandonments> {
  const frames = await terminalFrames(driver, artifacts, cut);
  if (!Array.isArray(detail.abandonedRetryInvocations) || detail.abandonedRetryInvocations.length !== frames.length) terminalFailure();
  if (!frames.length) return [];
  const closures = await Promise.all(detail.abandonedRetryInvocations.map(async entry =>
    decodeBrokerProcessDomainDeathDispatchClosure(await readCanonicalArtifact(artifacts, entry.dispatchFenceOrDeathEvidenceRef))));
  const deaths = await Promise.all(closures.map(async closure =>
    decodeBrokerProcessDomainDeath(await readCanonicalArtifact(artifacts, closure.closure.brokerProcessDeathEvidenceRef))));
  const epoch = deaths[0]!.inspectorStateOwnerEpoch;
  if (deaths.some(evidence => evidence.inspectorStateOwnerEpoch !== epoch)) terminalFailure();
  const history = await readRetainedStateOwnerHistory(driver, artifacts, epoch);
  const inspecting = ownerFrame(history, epoch);
  const expected: Abandonments = [];
  for (const [index, frame] of frames.entries()) {
    const closure = closures[index]!, evidence = deaths[index]!;
    const claiming = terminalRecipe(history, frame);
    if (closure.runId !== cut.run.id || closure.opId !== frame.claim.opId || closure.attempt !== frame.claim.attempt ||
        closure.dispatchId !== frame.claim.dispatchId || closure.unknownJournalSeq !== frame.unknown.seq ||
        closure.closure.brokerProcessDeathEvidenceDigest !== evidence.evidenceDigest || closure.observedAt !== evidence.observedAt ||
        evidence.runId !== cut.run.id || evidence.opId !== frame.claim.opId || evidence.attempt !== frame.claim.attempt ||
        evidence.dispatchId !== frame.claim.dispatchId || evidence.dispatchJournalSeq !== frame.claim.seq ||
        evidence.operationRequestRef !== frame.claim.requestRef || evidence.operationGrantRef !== frame.claim.grantRef ||
        evidence.operationTargetDigest !== frame.evidence.operationTargetDigest ||
        evidence.claimingSupervisorInstanceId !== claiming.owner.supervisorInstanceId || evidence.claimingStateOwnerEpoch !== claiming.owner.ownerEpoch ||
        evidence.claimingProcessIdentityRef !== claiming.owner.processIdentityRef || evidence.claimingProcessIdentityDigest !== claiming.owner.processIdentityDigest ||
        evidence.brokerFenceTokenDigest !== frame.claim.brokerFenceTokenDigest || evidence.observedAt < frame.unknown.timestamp ||
        evidence.observedAt > detail.createdAt || detail.createdAt > cut.run.updatedAt ||
        parseCanonicalTime(cut.run.updatedAt) - parseCanonicalTime(evidence.observedAt) > 5000 ||
        (inspecting.owner.state === 'terminal' && cut.run.updatedAt > inspecting.owner.releasedAt)) terminalFailure();
    const inspector = await readSupervisorInspector(artifacts, inspecting.owner, frame.assembly, evidence);
    if (!same(inspector, supervisorInspectorIdentity(inspecting.owner))) terminalFailure();
    const entry = abandonment(frame, detail.abandonedRetryInvocations[index]!.dispatchFenceOrDeathEvidenceRef);
    if (!same(entry, detail.abandonedRetryInvocations[index])) terminalFailure();
    expected.push(entry);
  }
  return expected;
}
