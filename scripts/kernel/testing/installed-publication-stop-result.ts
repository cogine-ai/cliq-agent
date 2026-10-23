// Pure retained-data assertions only. No process, clock, native proof or authority.
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { CONTROL_FRAME_BYTES, decodeInstalledControlEnvelope } from '../../../src/kernel/control-wire.js';
import { assertControlWireJson } from '../../../src/kernel/control-wire-data.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeDeliveryTerminalProjectionEvidence, decodePublicationArenaBirth, decodePublicationPathProgressItem,
  decodePublicationProof } from '../../../src/kernel/publication.js';
import type { StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import { immutableSnapshot } from '../../../src/model/immutable.js';
import { decodeContextManifest, decodePlatformProcessIdentity, decodeStateLockIdentity, decodeStateOwnerAcquisitionEvidence,
  decodeStateOwnerRecord, decodeStateOwnerTransitionEvidence, decodeStateRootIdentity, decodeWorkspaceState } from '../../../src/state/decoders.js';
import { deliveryPublicationCheckpointId } from '../../../src/state/delivery-publication-progress.js';
import { publicationClaimRetirementDiagnosticKey } from '../../../src/state/publication-retirement-diagnostics.js';
import { decodeRunResult } from '../../../src/state/result-artifacts.js';
import { supervisorInspectorIdentity } from '../../../src/state/supervisor-inspector.js';
import { assertInstalledDeliveryOutcome } from './installed-delivery-result.js';
import type { InstalledWorkerRetirementBinding } from './installed-worker-lease.js';

export type InstalledPublicationStopResultInput = {
  beforeCut: Record<string, any>; cut: Record<string, any>; sessionCut: Record<string, any>; sourceCut: Record<string, any>;
  sourceResultRef: string; expectedFiles: readonly { path: string; text: string }[];
  readRetainedArtifact(ref: string): Promise<Buffer>;
  readOwnerHistory(): Promise<readonly StateOwnerRecordV1[]>;
};
export type InstalledPublicationStopResult = Readonly<{
  diagnosticOnly: true; runId: string; opId: string; attempt: 0; dispatchId: string; planRef: string;
  arenaBirthRef: string; receiptRef: string; handoffRef: string; resourceCheckpointId: string;
  retirementDiagnosticKey: string; originalOwnerEpoch: 2; successorOwnerEpoch: 3; terminalInspectorOwnerEpoch: 2 | 3;
  resultRef: string; diffRef: string; projectionRef: string; publicationWorkerRetirement: InstalledWorkerRetirementBinding;
}>;
const refused = 'installed publication stop closure refused';
const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
function check(value: unknown): asserts value { if (!value) throw new Error(refused); }
function same(left: unknown, right: unknown): void { check(canonicalSha256(left) === canonicalSha256(right)); }
function snapshot<T>(value: T): T {
  assertControlWireJson(value); check(canonicalJsonBytes(value).length <= CONTROL_FRAME_BYTES); return immutableSnapshot(value);
}

/** Pair caller-captured cuts with the original normal graph. Timing packets,
 * real death, directory observations and signed installation stay independent.
 * A fully charged UNKNOWN is deliberately not this successful stop branch. */
export async function assertInstalledPublicationStopResult(input: InstalledPublicationStopResultInput): Promise<InstalledPublicationStopResult> {
  try {
    const keys = ['beforeCut', 'cut', 'sessionCut', 'sourceCut', 'sourceResultRef', 'expectedFiles', 'readRetainedArtifact', 'readOwnerHistory'];
    const fields = Object.getOwnPropertyDescriptors(input);
    check(Reflect.ownKeys(fields).length === keys.length && keys.every(key => fields[key]?.enumerable && Object.hasOwn(fields[key]!, 'value')));
    const readRetainedArtifact = fields.readRetainedArtifact!.value, readOwnerHistory = fields.readOwnerHistory!.value;
    check(typeof readRetainedArtifact === 'function' && typeof readOwnerHistory === 'function');
    const before = snapshot<Record<string, any>>(fields.beforeCut!.value!), cut = snapshot<Record<string, any>>(fields.cut!.value!),
      sourceCut = snapshot<Record<string, any>>(fields.sourceCut!.value!), sessionCut = snapshot<Record<string, any>>(fields.sessionCut!.value!),
      expectedFiles = snapshot(fields.expectedFiles!.value), sourceResultRef = fields.sourceResultRef!.value;
    check(Array.isArray(expectedFiles) && expectedFiles.length <= 1000 && typeof sourceResultRef === 'string');
    const decode = (value: Record<string, any>) => {
      const decoded = decodeInstalledControlEnvelope({ protocolVersion: 1, ok: true, result: value }, 'run.get');
      check(decoded.ok); const result = decoded.result;
      check(result.items.length <= 1000 && result.journal.length <= 1000 && result.checkpoints.length <= 1000 &&
        result.items.length === result.highWaterItemSeq && result.nextItemSeq === result.highWaterItemSeq &&
        result.journal.length === result.highWaterJournalSeq && result.nextJournalSeq === result.highWaterJournalSeq &&
        result.nextCheckpointCursor === result.highWaterCheckpointCursor);
      return result;
    };
    const initial = decode(before), final = decode(cut), run = final.snapshot.run, priorRun = initial.snapshot.run;
    check(initial.snapshot.operation === 'delivery' && final.snapshot.operation === 'delivery' && priorRun.id === run.id &&
      priorRun.sessionId === run.sessionId && priorRun.specRef === run.specRef && priorRun.deadlineAt === run.deadlineAt &&
      priorRun.status === 'running' && priorRun.nextStep === 'delivery' && priorRun.activeWorkerLaunchId &&
      !priorRun.cancelRequested && !priorRun.stopIntentRef && !priorRun.resultRef && initial.journal.length === 2);
    check(final.journal.length === 3 && final.journal[2]!.phase === 'completed');
    same(final.journal.slice(0, 2), initial.journal);
    const [prepared, claim] = initial.journal;
    check(prepared?.phase === 'prepared' && claim?.phase === 'dispatch_claimed' && claim.opKind === 'publish' && claim.attempt === 0 &&
      claim.stateOwnerEpoch === 2 && claim.dispatchId && claim.evidenceRef && claim.evidenceDigest);
    // Preparation writes the Run; claim appends only its Journal row and
    // cannot be treated as a fabricated update of Run.updatedAt.
    check(priorRun.revision < run.revision && priorRun.leaseEpoch === claim.leaseEpoch &&
      prepared.timestamp <= priorRun.updatedAt && priorRun.updatedAt <= run.updatedAt);
    same(priorRun.budgetConsumed, ZERO); same(priorRun.budgetReserved, { ...ZERO, toolCalls: 1 });
    check(initial.items.length < final.items.length); same(initial.items, final.items.slice(0, initial.items.length));
    check(initial.snapshot.latestRunItemSeq === initial.items.length);
    const initialCheckpoints = initial.checkpoints.filter(cp => cp.id === priorRun.latestCheckpointId);
    check(initialCheckpoints.length === 1 && initialCheckpoints[0]!.createdAt <= priorRun.updatedAt &&
      initialCheckpoints[0]!.runItemSeq === initial.items.length && initialCheckpoints[0]!.journalSeq <= claim.seq);
    for (const cp of initial.checkpoints) {
      const selected = final.checkpoints.filter(value => value.id === cp.id); check(selected.length === 1); same(selected[0], cp);
    }
    const objects = new Map<string, Promise<Buffer>>();
    const bytes = async (ref: string) => {
      check(typeof ref === 'string' && /^[0-9a-f]{64}$/u.test(ref)); let retained = objects.get(ref);
      if (!retained) {
        check(objects.size < 256);
        retained = Promise.resolve().then(async () => {
          const value = await readRetainedArtifact(ref);
          check(Buffer.isBuffer(value) && value.length <= 1_048_576 && sha256Bytes(value) === ref); return Buffer.from(value);
        });
        // Reserve before awaiting: parallel full readers cannot exceed the
        // same fixed object budget or observe two versions of one reference.
        objects.set(ref, retained);
      }
      return Buffer.from(await retained);
    };
    const object = async (ref: string): Promise<any> => {
      const retained = await bytes(ref), value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(retained));
      check(canonicalJsonBytes(value).equals(retained)); return value;
    };
    const owners = snapshot(await readOwnerHistory()).map(decodeStateOwnerRecord);
    check(owners.length === 3);
    const identities = [];
    for (const [index, owner] of owners.entries()) {
      check(owner.ownerEpoch === index + 1 && (index === 2 ? owner.state === 'active' : owner.state === 'terminal' && owner.terminalReason === 'graceful_release'));
      const acquisition = decodeStateOwnerAcquisitionEvidence(await object(owner.acquisitionEvidenceRef));
      check(acquisition.evidenceDigest === owner.acquisitionEvidenceDigest);
      for (const key of ['ownerEpoch', 'supervisorInstanceId', 'runtimeBundleRef', 'runtimeBundleManifestDigest', 'processIdentityRef',
        'processIdentityDigest', 'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest', 'acquiredAt'] as const) same(acquisition[key], owner[key]);
      const process = decodePlatformProcessIdentity(await object(owner.processIdentityRef));
      check(process.platform === 'linux' && process.identityDigest === owner.processIdentityDigest && process.executableImageDigest === owner.supervisorExecutableDigest);
      const lock = decodeStateLockIdentity(await object(owner.stateLockIdentityRef)), root = decodeStateRootIdentity(await object(lock.stateRootIdentityRef));
      check(lock.identityDigest === owner.stateLockIdentityDigest && root.identityDigest === lock.stateRootIdentityDigest && root.platform === 'linux' &&
        process.ownerUid === root.ownerUid && lock.ownerUid === root.ownerUid && lock.deviceId === root.deviceId);
      if (index) {
        const prior = owners[index - 1]!; check(prior.state === 'terminal' && acquisition.kind === 'acquire_after_graceful_release');
        check(acquisition.priorOwnerEpoch === prior.ownerEpoch && acquisition.priorTerminalRowDigest === prior.rowDigest &&
          acquisition.priorTransitionEvidenceRef === prior.transitionEvidenceRef && acquisition.priorTransitionEvidenceDigest === prior.transitionEvidenceDigest &&
          acquisition.priorTerminalReason === 'graceful_release' && owner.acquiredAt >= prior.releasedAt);
        for (const key of ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'stateLockIdentityRef', 'stateLockIdentityDigest',
          'supervisorEntryId', 'supervisorEntryVersion', 'supervisorExecutableDigest'] as const) same(owner[key], prior[key]);
        check(process.identityDigest !== identities[index - 1]!.process.identityDigest && owner.supervisorInstanceId !== prior.supervisorInstanceId);
      } else check(acquisition.kind === 'genesis');
      if (owner.state === 'terminal') {
        const transition = decodeStateOwnerTransitionEvidence(await object(owner.transitionEvidenceRef));
        check(transition.kind === 'graceful_release' && transition.evidenceDigest === owner.transitionEvidenceDigest && transition.observedAt === owner.releasedAt &&
          transition.releasingProcessIdentityRef === owner.processIdentityRef && transition.releasingProcessIdentityDigest === owner.processIdentityDigest);
        for (const [key, field] of [['priorOwnerEpoch', 'ownerEpoch'], ['priorSupervisorInstanceId', 'supervisorInstanceId'],
          ['priorProcessIdentityRef', 'processIdentityRef'], ['priorProcessIdentityDigest', 'processIdentityDigest'],
          ['stateLockIdentityRef', 'stateLockIdentityRef'], ['stateLockIdentityDigest', 'stateLockIdentityDigest']] as const) same(transition[key], owner[field]);
      }
      identities.push({ process, root, lock });
    }
    const original = owners[1]!, successor = owners[2]!; check(original.state === 'terminal');
    check(claim.supervisorInstanceId === original.supervisorInstanceId && claim.timestamp >= original.acquiredAt && priorRun.updatedAt <= original.releasedAt);
    const birth = decodePublicationArenaBirth(await object(claim.evidenceRef));
    check(birth.deliveryRunId === run.id && birth.opId === claim.opId && birth.dispatchId === claim.dispatchId && birth.attempt === 0 &&
      birth.birthDigest === claim.evidenceDigest && birth.stateRootIdentityRef === identities[1]!.lock.stateRootIdentityRef &&
      birth.stateRootIdentityDigest === identities[1]!.root.identityDigest);
    same(await object(birth.inspectorIdentityRef), supervisorInspectorIdentity(original));
    const initialItems = await Promise.all(initial.items.map(row => object(row.payloadRef)));
    check(!initialItems.some(item => item.kind === 'publication_path_result' || item.kind === 'publication_late_observation' || item.state === 'received_handoff'));
    // All initial Checkpoints remain actual members of the final closure, not
    // caller-invented prefixes or a shortcut around complete context bytes.
    for (const cp of initial.checkpoints) {
      const context = decodeContextManifest(await object(cp.contextManifestRef)), workspace = decodeWorkspaceState(await object(cp.workspaceStateRef));
      check(context.runId === run.id && context.throughItemSeq === cp.runItemSeq && workspace.runId === run.id);
    }
    const outcome = await assertInstalledDeliveryOutcome({ cut: final, sourceCut, sessionCut, sourceResultRef, expectedFiles,
      kind: 'publish', readRetainedArtifact: bytes, readOwnerHistory: async () => owners });
    check(outcome.publicationWorkerRetirement && outcome.publicationWorkerRetirement.launchId === priorRun.activeWorkerLaunchId);
    const items = await Promise.all(final.items.map(async row => ({ row, item: await object(row.payloadRef) })));
    const handoffs = items.filter(value => value.item.kind === 'publication_path_progress' && value.item.state === 'received_handoff'); check(handoffs.length === 1);
    const handoff = decodePublicationPathProgressItem(handoffs[0]!.item); check(handoff.state === 'received_handoff' && handoff.generationResources.kind === 'sealed');
    const receipts = final.journal[2]!; check(receipts.receiptRef && handoff.receiptRef === receipts.receiptRef &&
      handoff.dispatchId === claim.dispatchId && handoff.claimJournalSeq === claim.seq && handoff.createdAt <= original.releasedAt);
    const receipt = decodePublicationProof(await object(receipts.receiptRef)); check(receipt.kind === 'terminal_receipt');
    check(receipt.inspectorIdentityRef === birth.inspectorIdentityRef && receipt.inspectorIdentityDigest === birth.inspectorIdentityDigest &&
      receipt.observedAt <= handoff.createdAt && receipt.observedAt <= original.releasedAt && receipt.namespaceRetirementEvidenceRef === undefined);
    const resourceCheckpointId = deliveryPublicationCheckpointId(run.id, birth.deliveryPlanRef), resources = final.checkpoints.filter(cp => cp.id === resourceCheckpointId);
    check(resources.length === 1 && resources[0]!.createdAt >= handoff.createdAt && resources[0]!.createdAt <= original.releasedAt &&
      resources[0]!.runItemSeq === handoffs[0]!.row.itemSeq && resources[0]!.journalSeq === claim.seq);
    const result = decodeRunResult(await object(run.resultRef!)); check(result.deliveryTerminalProjectionEvidenceRef);
    const projection = decodeDeliveryTerminalProjectionEvidence(await object(result.deliveryTerminalProjectionEvidenceRef));
    const terminal = decodePublicationProof(await object(projection.projectionClosureEvidenceRef)); check(terminal.kind === 'projection_closure');
    const originalInspector = supervisorInspectorIdentity(original), successorInspector = supervisorInspectorIdentity(successor);
    const terminalInspectorOwnerEpoch = terminal.inspectorIdentityDigest === originalInspector.identityDigest ? 2 : 3;
    same(await object(terminal.inspectorIdentityRef), terminalInspectorOwnerEpoch === 2 ? originalInspector : successorInspector);
    check(terminal.inspectorIdentityDigest === (terminalInspectorOwnerEpoch === 2 ? originalInspector : successorInspector).identityDigest);
    check(receipts.timestamp <= terminal.observedAt);
    if (terminalInspectorOwnerEpoch === 2) check(run.updatedAt <= original.releasedAt && receipts.timestamp <= original.releasedAt);
    else check(terminal.observedAt >= successor.acquiredAt &&
      (receipts.timestamp <= original.releasedAt || receipts.timestamp >= successor.acquiredAt));
    return immutableSnapshot({ diagnosticOnly: true, runId: run.id, opId: claim.opId, attempt: 0, dispatchId: claim.dispatchId, planRef: birth.deliveryPlanRef,
      arenaBirthRef: claim.evidenceRef, receiptRef: receipts.receiptRef, handoffRef: handoffs[0]!.row.payloadRef, resourceCheckpointId,
      retirementDiagnosticKey: publicationClaimRetirementDiagnosticKey({ runId: run.id, planRef: birth.deliveryPlanRef,
        opId: claim.opId, attempt: 0, dispatchId: claim.dispatchId }), originalOwnerEpoch: 2, successorOwnerEpoch: 3,
      terminalInspectorOwnerEpoch, resultRef: run.resultRef!, diffRef: result.diffRef, projectionRef: result.deliveryTerminalProjectionEvidenceRef,
      publicationWorkerRetirement: outcome.publicationWorkerRetirement });
  } catch { throw new Error(refused); }
}
