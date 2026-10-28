// Read-only assertions for the actual installed journey. Retained data is not
// active process observation, a release signature check or execution authority.
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { readPrivateGitData, readGitIndexData, privateGitSourceHead, type PrivateGitReader } from '../../../src/workspace/private-git-data.js';
import { decodeSandboxProfile } from '../../../src/state/execution-closure.js';
import { digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, Run, StateOwnerRecordV1, WorkspaceEntry } from '../../../src/kernel/types.js';
import type { FinalCandidateItem, VerifierPlan, VerificationClosureV1 } from '../../../src/kernel/result.js';
import type { VerificationReceipt, VerifierResultItem } from '../../../src/kernel/verifier.js';
import type { VerifierOperationGrantV1, VerifierPolicyChannelEvidenceV1 } from '../../../src/kernel/verifier-invocation.js';
import type { RunPolicySnapshotV1 } from '../../../src/kernel/tool-authorization.js';
import { verifyModelText } from '../../../src/model/attempt.js';
import type { ModelTextV1 } from '../../../src/protocol/agent-ir.js';
import { decodeRetainedRunAssembly } from '../../../src/model/run-assembly.js';
import { exactKeys } from '../../../src/policy/runtime-authority.js';
import { validateContextItems } from '../../../src/runtime/context-compaction.js';
import { agentStopDetail, decodeAgentStop, stopCheckpointId } from '../../../src/runtime/stop.js';
import { decodeAdmittedContext, decodeBudgetSettlement, decodeContextManifest, decodeRunSpec, decodeSessionProjection,
  decodeSourceManifest, decodeUnverifiedConsent, decodeWorkspaceEntries,
  decodeWorkspaceIdentity, decodeWorkspaceState } from '../../../src/state/decoders.js';
import { decodeFinalCandidateItem, decodeRunResult, decodeVerificationClosure, decodeVerifierPlan,
  decodeWorkspaceDiff } from '../../../src/state/result-artifacts.js';
import { decodeRepairDiagnosticItem, decodeVerificationReceipt,
  decodeVerifierResultItem } from '../../../src/state/verifier-artifacts.js';
import { decodeVerifierSpec } from '../../../src/state/verifier-artifacts.js';
import { loadVerifierPolicy, planVerifierRequest, verifierOperationId } from '../../../src/state/verifier-policy.js';
import { verifierCheckpointId, verifierResultItemId, type VerifierProgress } from '../../../src/state/verifier-recovery.js';
import { planVerifierRepair } from '../../../src/state/verifier-repair.js';
import { assertInstalledVerifierRetirement, readInstalledVerifierInputs, type InstalledVerifierRetirementPhase, type InstalledVerifierOwnerHistoryReader } from './installed-verifier-evidence.js';

type CaseKind = 'required_pass' | 'required_repair' | 'advisory_failure' | 'required_timeout';
type ProcessIdentity = { role: 'namespace_init' | 'monitor' | 'subreaper'; pid: number; startTicks: string };
export type InstalledVerifierDiagnosticStage = InstalledVerifierRetirementPhase | 'public_cut' | 'frozen_inputs' | 'source_and_candidate' | 'candidate_producer' |
  'candidate_source' | 'verifier_request' | 'verifier_policy_and_attempt' | 'verifier_settlement' | 'verifier_receipt' |
  'verifier_retirement' | 'verifier_retirement_state' | 'verifier_retirement_context' | 'verifier_retirement_item_seq' |
  'reverse_history_and_repair' | 'terminal_result' | 'session_publication';
export class InstalledVerifierOutcomeError extends Error {
  readonly code = 'INSTALLED_VERIFIER_OUTCOME_REFUSED';
  constructor(readonly diagnosticStage: InstalledVerifierDiagnosticStage) {
    super(`Installed verifier outcome refused at ${diagnosticStage}`);
    this.name = 'InstalledVerifierOutcomeError';
  }
}
export type InstalledVerifierOutcome = {
  caseKind: CaseKind; runId: string; sessionId: string;
  status: 'succeeded' | 'completed_unverified' | 'failed';
  terminalReason: 'verified' | 'no_required_verifier' | 'verifier_infrastructure_failed';
  candidateCount: number; verifierAttemptCount: number; repairCount: number; checkedFileCount: number;
  resultRef?: string; verificationClosureRef?: string;
  retirementIdentities: Array<{ opId: string; attempt: number; containmentRef: string; deathEvidenceRef: string;
    namespaceInitStartToken: string; subreaperStartToken: string; processes: ProcessIdentity[] }>;
};

const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const ONE_TOOL = { ...ZERO, toolCalls: 1 };
const MAX_JSON_BYTES = 1_048_576;
const check = (condition: unknown): void => { if (!condition) throw new Error('installed verifier assertion failed'); };
const same = (actual: unknown, expected: unknown): void => check(canonicalSha256(actual) === canonicalSha256(expected));
const comparePath = (left: { path: string }, right: { path: string }) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path));

/** No database, filesystem, provider, clock or process mutation. Every object
 * below comes from the public cut or the supplied real CAS reader. On failure
 * only a fixed stage name escapes: assertions must not print raw outputs,
 * workspace bytes, argv, environment values or untrusted decoder messages. */
export async function assertInstalledVerifierOutcome(input: {
  cut: Record<string, any>; sessionCut: Record<string, any>; readCas: (ref: string) => Promise<Buffer>;
  readOwnerHistory: InstalledVerifierOwnerHistoryReader;
  caseKind: CaseKind; expectedFiles: readonly { path: string; before: string; after: string }[]; principalId: string;
  expectedGit?: true;
}): Promise<InstalledVerifierOutcome> {
  let stage: InstalledVerifierDiagnosticStage = 'public_cut';
  try {
    const { cut, sessionCut, caseKind } = input;
    check(input.expectedGit === undefined || input.expectedGit === true);
    check(['required_pass', 'required_repair', 'advisory_failure', 'required_timeout'].includes(caseKind));
    const run = cut.snapshot?.run as Run;
    check(cut.method === 'run.get' && cut.snapshot.schemaVersion === 1 && cut.snapshot.operation === 'agent');
    check(run && !run.parentRunId && run.cancelRequested === false && run.nextStep === null && !run.frontierRef &&
      !run.activeWorkerLaunchId && !run.waitingReason && !run.waitingOnRef);
    check(/^[A-Za-z0-9_-]{43}$/u.test(run.id) && /^[A-Za-z0-9_-]{43}$/u.test(run.sessionId));
    check(Array.isArray(cut.items) && cut.items.length > 0 && cut.items.length <= 10_000 && Array.isArray(cut.journal) &&
      cut.journal.length <= 10_000 && Array.isArray(cut.checkpoints) && cut.checkpoints.length <= 10_000);
    check(cut.nextItemSeq === cut.highWaterItemSeq && cut.highWaterItemSeq === cut.items.length &&
      cut.snapshot.latestRunItemSeq === cut.items.length && cut.nextJournalSeq === cut.highWaterJournalSeq &&
      cut.highWaterJournalSeq === cut.journal.length && cut.nextCheckpointCursor === cut.highWaterCheckpointCursor);
    same(run.budgetReserved, ZERO);
    parseCanonicalTime(run.createdAt); parseCanonicalTime(run.updatedAt); parseCanonicalTime(run.deadlineAt);
    check(run.createdAt < run.updatedAt && run.updatedAt < run.deadlineAt);
    const cache = new Map<string, Buffer>();
    async function bytes(ref: string, maximum = MAX_JSON_BYTES): Promise<Buffer> {
      check(typeof ref === 'string' && /^[a-f0-9]{64}$/u.test(ref));
      let value = cache.get(ref);
      if (!value) { value = await input.readCas(ref); check(Buffer.isBuffer(value) && sha256Bytes(value) === ref); cache.set(ref, value); }
      check(value.length <= maximum); return value;
    }
    async function object<T = Record<string, any>>(ref: string): Promise<T> {
      const retained = await bytes(ref), value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(retained));
      check(canonicalJsonBytes(value).equals(retained)); return value as T;
    }
    const itemRows = cut.items as Array<{ schemaVersion: 1; itemId: string; itemSeq: number; payloadRef: string; payloadDigest: string; createdAt: string }>;
    const items: ContinuationItem[] = [];
    for (const [index, row] of itemRows.entries()) {
      check(row.schemaVersion === 1 && row.itemSeq === index + 1 && row.payloadDigest === row.payloadRef &&
        !itemRows.slice(0, index).some(prior => prior.itemId === row.itemId));
      const item = await object<ContinuationItem>(row.payloadRef);
      check(item.runId === run.id && item.itemId === row.itemId && item.createdAt === row.createdAt);
      parseCanonicalTime(item.createdAt); check(item.createdAt >= run.createdAt && item.createdAt <= run.updatedAt); items.push(item);
    }
    const journal = cut.journal as InvocationJournalEntry[], checkpoints = cut.checkpoints as Checkpoint[];
    for (const [index, entry] of journal.entries()) {
      check(entry.seq === index + 1 && entry.runId === run.id && Number.isSafeInteger(entry.attempt) && entry.attempt >= 0);
      parseCanonicalTime(entry.timestamp); check(entry.timestamp >= run.createdAt && entry.timestamp <= run.updatedAt);
    }
    for (const [index, checkpoint] of checkpoints.entries()) {
      check(checkpoint.schemaVersion === 1 && checkpoint.runId === run.id && checkpoint.journalSeq <= journal.length &&
        checkpoint.runItemSeq <= items.length && !checkpoints.slice(0, index).some(prior => prior.id === checkpoint.id));
      parseCanonicalTime(checkpoint.createdAt); check(checkpoint.createdAt >= run.createdAt && checkpoint.createdAt <= run.updatedAt);
    }
    const checkpoint = (id: string): Checkpoint => {
      const matches = checkpoints.filter(row => row.id === id); check(matches.length === 1); return matches[0]!;
    };
    const rowFor = (id: string) => { const rows = itemRows.filter(row => row.itemId === id); check(rows.length === 1); return rows[0]!; };
    const context = async (cp: Checkpoint) => {
      const value = decodeContextManifest(await object(cp.contextManifestRef));
      check(value.runId === run.id && value.assemblyRef === spec.assemblyRef && value.admittedContextRef === spec.admittedContextRef &&
        value.throughItemSeq === cp.runItemSeq);
      validateContextItems(value, itemRows.slice(0, cp.runItemSeq).map((row, index) => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef, item: items[index]! })));
      return value;
    };

    stage = 'frozen_inputs';
    const spec = decodeRunSpec(await object(run.specRef));
    check(spec.operation === 'agent' && spec.dependencyPolicyRef === undefined);
    const frozen = decodeVerifierSpec(await object(spec.verifierSpecRef)); check(frozen.verifiers.length > 0);
    const assembly = decodeRetainedRunAssembly(await object(spec.assemblyRef));
    const policy = await object<RunPolicySnapshotV1>(spec.policyRef);
    const session = sessionCut.snapshot?.session;
    check(sessionCut.method === 'session.get' && sessionCut.snapshot.schemaVersion === 1 && session.id === run.sessionId &&
      sessionCut.nextItemSeq === sessionCut.highWaterItemSeq && sessionCut.highWaterItemSeq === session.latestItemSeq && Array.isArray(sessionCut.items));
    const workspace = decodeWorkspaceIdentity(await object(session.workspaceIdentityRef));
    check(workspace.kind === 'live' && workspace.platform === 'linux' && workspace.ownerPrincipalId === input.principalId);
    const admitted = decodeAdmittedContext(await object(spec.admittedContextRef)); check(admitted.sessionId === run.sessionId);
    const required = frozen.verifiers.some(entry => entry.gate === 'required');
    check(required === (caseKind !== 'advisory_failure'));
    if (required) check(spec.unverifiedConsentRef === undefined);
    else {
      check(!!spec.unverifiedConsentRef);
      const consent = decodeUnverifiedConsent(await object(spec.unverifiedConsentRef!));
      const { unverifiedConsentRef: _consent, ...core } = spec;
      check(consent.allowUnverified && consent.principalId === input.principalId && consent.createdAt === run.createdAt &&
        consent.runSpecCoreDigest === canonicalSha256(core));
    }
    const { commands, environments } = await readInstalledVerifierInputs(spec, bytes);

    stage = 'source_and_candidate';
    check(input.expectedFiles.length > 0 && input.expectedFiles.length <= 32);
    const fixedEntries = (side: 'before' | 'after'): WorkspaceEntry[] => {
      const directories = new Set<string>(), files: WorkspaceEntry[] = [];
      for (const fixed of input.expectedFiles) {
        check(typeof fixed.path === 'string' && fixed.path.length > 0 && fixed.path === fixed.path.normalize('NFC') &&
          !fixed.path.includes('\\') && !fixed.path.includes('\0') && !fixed.path.split('/').some(part => !part || part === '.' || part === '..' || part.toLowerCase() === '.git'));
        check(typeof fixed[side] === 'string');
        const content = Buffer.from(fixed[side]); check(content.length <= MAX_JSON_BYTES);
        const parts = fixed.path.split('/'); for (let index = 1; index < parts.length; index++) directories.add(parts.slice(0, index).join('/'));
        files.push({ path: fixed.path, kind: 'file', mode: 0o644, size: content.length, blobRef: sha256Bytes(content) });
      }
      check(new Set(files.map(file => file.path)).size === files.length && !files.some(file => directories.has(file.path)));
      return [...[...directories].map(path => ({ path, kind: 'directory' as const, mode: 0o755 })), ...files].sort(comparePath);
    };
    const expectedBase = fixedEntries('before'), expectedAfter = fixedEntries('after');
    const base = decodeSourceManifest(await object(spec.baseWorkspaceManifestRef));
    const baseEntries = decodeWorkspaceEntries(await object(base.entriesRef));
    check(base.role === 'base' && !!base.git === !!input.expectedGit && workspace.kind === 'live' && !!workspace.repositoryIdentityRef === !!input.expectedGit && base.sourceProjectionRef === spec.sourceProjectionRef &&
      base.workspaceIdentityDigest === workspace.identityDigest && base.treeDigest === baseEntries.treeDigest);
    same(baseEntries.entries, expectedBase);
    for (const fixed of input.expectedFiles) check((await bytes(sha256Bytes(Buffer.from(fixed.before)))).equals(Buffer.from(fixed.before)));
    const candidates = items.filter((item): item is FinalCandidateItem => item.kind === 'final_candidate').map(decodeFinalCandidateItem);
    check(candidates.length === (caseKind === 'required_repair' ? 2 : 1));
    const progresses: VerifierProgress[] = [], seenVerifierJournal = new Set<number>(), seenVerifierItems = new Set<string>();
    const retirementIdentities: InstalledVerifierOutcome['retirementIdentities'] = [];
    let verifierAttemptCount = 0;
    let originalPrivateGitRef: string | undefined;
    const gitReader = (signal?: AbortSignal): PrivateGitReader => ({
      async readBoundedBytes(ref, maximum) { signal?.throwIfAborted(); const value = await bytes(ref, Math.min(maximum, MAX_JSON_BYTES)); signal?.throwIfAborted(); return value; },
      async *readChunks(ref, expectedSize) { signal?.throwIfAborted(); const value = await bytes(ref, Math.min(expectedSize ?? MAX_JSON_BYTES, MAX_JSON_BYTES));
        check(expectedSize === undefined || value.length === expectedSize); signal?.throwIfAborted(); yield value; },
      withReadSignal: selected => gitReader(signal ? AbortSignal.any([signal, selected]) : selected)
    });
    async function state(cp: Checkpoint, sourceEntriesRef: string) {
      const value = decodeWorkspaceState(await object(cp.workspaceStateRef));
      check(value.runId === run.id && value.baseWorkspaceManifestRef === spec.baseWorkspaceManifestRef &&
        value.sourceProjectionDigest === base.sourceProjectionDigest && value.entriesRef === sourceEntriesRef && !!value.privateGitStateRef === !!input.expectedGit);
      if (input.expectedGit) {
        check(base.git && value.privateGitStateRef);
        const profile = decodeSandboxProfile(await object(spec.sandboxProfileRef));
        const expected = { repositoryIdentityDigest: base.git!.repositoryIdentityDigest, resources: profile.resources };
        const privateGit = await readPrivateGitData(gitReader(), value.privateGitStateRef!, expected);
        const admitted = await readGitIndexData(gitReader(), base.git!.indexRef, expected);
        same(privateGitSourceHead(privateGit), base.git!.head);
        check(admitted.indexTreeObjectId === base.git!.indexTreeObjectId && admitted.objectFormat === privateGit.index.objectFormat);
        originalPrivateGitRef ??= value.privateGitStateRef;
        // Ordinary edit and verifier preserve the exact original private graph.
        check(value.privateGitStateRef === originalPrivateGitRef);
      }
      check(value.invalidatedEphemeralPaths.length === 0); return value;
    }
    for (const [candidateIndex, candidate] of candidates.entries()) {
      stage = 'candidate_producer';
      const row = rowFor(candidate.itemId), producer = items[row.itemSeq - 2];
      check(candidate.operation === 'agent' && candidate.runId === run.id && producer?.kind === 'model_turn' && producer.stopReason === 'end');
      if (producer?.kind !== 'model_turn') throw new Error('missing candidate producer');
      check(candidate.itemId === identityHash('cliq-final-candidate-item-v1', run.id, producer.itemId) && candidate.producingItemId === producer.itemId &&
        candidate.producingOpId === producer.modelOpId && candidate.summaryRef === producer.textRef && candidate.baseSourceRef === spec.baseWorkspaceManifestRef);
      const turn = await object(producer.modelTurnRef);
      check(turn.schemaVersion === 1 && turn.format === 'cliq-agent-model-turn-v1' && turn.stopReason === 'end' &&
        Array.isArray(turn.toolCalls) && turn.toolCalls.length === 0 && turn.textRef === candidate.summaryRef);
      const modelTerminal = journal.filter(entry => entry.opKind === 'model' && entry.opId === producer.modelOpId && entry.attempt === producer.modelAttempt && entry.phase === 'completed');
      check(modelTerminal.length === 1 && modelTerminal[0]!.resultRef === producer.modelTurnRef && producer.createdAt >= modelTerminal[0]!.timestamp);
      const request = await object(modelTerminal[0]!.requestRef);
      check(request.format === 'cliq-model-request-v1' && request.kind === 'normal' && request.runId === run.id &&
        request.opId === producer.modelOpId && request.attempt === producer.modelAttempt && request.requestDigest === turn.requestDigest &&
        request.promptProjectionRef === turn.promptProjectionRef && request.promptProjectionDigest === turn.promptProjectionDigest);
      check(producer.itemId === identityHash('cliq-model-turn-item-v1', run.id, producer.modelOpId, String(producer.modelAttempt)));
      stage = 'candidate_source';
      const source = decodeSourceManifest(await object(candidate.resultSourceRef)), entries = decodeWorkspaceEntries(await object(source.entriesRef));
      const expectedSource = { ...base, role: 'result' as const, entriesRef: source.entriesRef, treeDigest: entries.treeDigest, manifestDigest: '' };
      expectedSource.manifestDigest = digestOmitting(expectedSource, 'manifestDigest'); same(source, expectedSource);
      check(source.manifestDigest === candidate.sourceDigest);
      const paths = entries.entries.map(entry => ({ path: entry.path, kind: entry.kind, mode: entry.mode }));
      same(paths, expectedBase.map(entry => ({ path: entry.path, kind: entry.kind, mode: entry.mode })));
      for (const file of entries.entries) if (file.kind === 'file') check((await bytes(file.blobRef)).length === file.size);
      const diff = decodeWorkspaceDiff(await object(candidate.diffRef));
      const operations = baseEntries.entries.flatMap((before, index) => {
        const after = entries.entries[index]!; return canonicalSha256(before) === canonicalSha256(after) ? [] : [{ path: before.path, kind: 'modify', before, after }];
      });
      check(diff.baseSourceRef === candidate.baseSourceRef && diff.resultSourceRef === candidate.resultSourceRef && diff.diffDigest === candidate.diffDigest);
      same(diff.operations, operations);
      if (candidateIndex === candidates.length - 1) {
        same(entries.entries, expectedAfter);
        for (const fixed of input.expectedFiles) check((await bytes(sha256Bytes(Buffer.from(fixed.after)))).equals(Buffer.from(fixed.after)));
      }
      const candidateCp = checkpoint(identityHash('cliq-final-candidate-checkpoint-v1', run.id, producer.itemId));
      check(candidateCp.reason === 'auto' && candidateCp.runItemSeq === row.itemSeq && candidateCp.journalSeq === modelTerminal[0]!.seq &&
        candidateCp.createdAt >= candidate.createdAt && candidateCp.createdAt < run.deadlineAt);
      await state(candidateCp, source.entriesRef); await context(candidateCp);
      const planCore = { schemaVersion: 1 as const, runId: run.id, candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef,
        verifierSpecRef: spec.verifierSpecRef, verifierSpecDigest: frozen.specDigest,
        entries: frozen.verifiers.map(entry => ({ index: entry.index, verifierId: entry.id, verifierSpecDigest: frozen.specDigest,
          verifierEntryDigest: entry.entryDigest, commandRef: entry.commandRef, commandDigest: entry.commandDigest,
          environmentRef: entry.environmentRef, environmentDigest: entry.environmentDigest, required: entry.gate === 'required', maxAttempts: entry.retries + 1 })) };
      const expectedPlan: VerifierPlan = { ...planCore, planDigest: canonicalSha256(planCore) }, planRef = canonicalSha256(expectedPlan);
      const plan = decodeVerifierPlan(await object(planRef)); same(plan, expectedPlan);
      const progress: VerifierProgress = { candidate, planRef, plan, spec: frozen, entries: [], nextVerifierIndex: plan.entries.length, complete: true };
      progresses.push(progress);
      for (const [index, planEntry] of plan.entries.entries()) {
        stage = 'verifier_request';
        const specEntry = frozen.verifiers[index]!, command = commands[index]!, environment = environments[index]!;
        const frontier = { schemaVersion: 1, kind: 'verify', phase: 'verifiers', candidateItemId: candidate.itemId,
          resultSourceRef: candidate.resultSourceRef, verifierPlanRef: planRef, nextVerifierIndex: index, afterPass: 'finalize' };
        same(await object(canonicalSha256(frontier)), frontier);
        const requestContext = { runId: run.id, frontierRef: canonicalSha256(frontier), assemblyRef: spec.assemblyRef,
          candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef, sourceDigest: candidate.sourceDigest,
          verifierPlanRef: planRef, plan, verifierSpecRef: spec.verifierSpecRef, verifierSpec: frozen, verifierIndex: index, command, environment };
        const planned = planVerifierRequest(requestContext), opId = verifierOperationId(run.id, candidate.itemId, planRef, index);
        const operation = journal.filter(entry => entry.opId === opId);
        check(operation.length > 0 && operation.every(entry => entry.opKind === 'verifier' && entry.target === planned.request.targetRef && entry.requestRef === canonicalSha256(planned.request) &&
          entry.seq > candidateCp.journalSeq && entry.timestamp >= candidateCp.createdAt));
        same(await object(canonicalSha256(planned.request)), planned.request); same(await object(planned.request.targetRef), planned.target);
        operation.forEach(entry => seenVerifierJournal.add(entry.seq));
        const preparedRows = operation.filter(entry => entry.phase === 'prepared');
        check(preparedRows.length > 0 && operation.filter(entry => entry.phase === 'dispatch_claimed').length <= planEntry.maxAttempts);
        const evaluator = loadVerifierPolicy({ policy, policyRef: spec.policyRef, assembly, assemblyRef: spec.assemblyRef,
          principalId: input.principalId, workspaceIdentityDigest: workspace.identityDigest, context: requestContext });
        const entryProgress: VerifierProgress['entries'][number] = { planEntry, specEntry }; progress.entries.push(entryProgress);
        let previous: { terminal: InvocationJournalEntry; receipt?: VerificationReceipt; claimed: boolean; checkpointAt?: string } | undefined;
        for (const [attemptIndex, prepared] of preparedRows.entries()) {
          stage = 'verifier_policy_and_attempt';
          check(prepared.attempt === attemptIndex && prepared.grantRef && prepared.replayClass === 'retry'); same(prepared.budgetDelta, ONE_TOOL);
          if (previous) check(previous.terminal.phase === 'failed' && !previous.claimed || previous.terminal.phase === 'completed' && previous.receipt?.outcome === 'infra_failed');
          const attempt = operation.filter(entry => entry.attempt === attemptIndex), terminal = attempt.at(-1)!;
          const claims = attempt.filter(entry => entry.phase === 'dispatch_claimed'), claim = claims[0];
          check(['prepared,failed', 'prepared,dispatch_claimed,completed', 'prepared,dispatch_claimed,unknown,completed'].includes(attempt.map(entry => entry.phase).join(',')) &&
            attempt[0] === prepared && claims.length <= 1 && (!previous || previous.terminal.seq < prepared.seq && (!previous.checkpointAt || prepared.timestamp >= previous.checkpointAt)));
          check(attempt.every(entry => entry.grantRef === prepared.grantRef && entry.leaseEpoch === prepared.leaseEpoch && entry.replayClass === prepared.replayClass && entry.timestamp >= prepared.timestamp));
          const grant = await object<VerifierOperationGrantV1>(prepared.grantRef!);
          check(grant.provenance.kind === 'policy_snapshot');
          const channel = await object<VerifierPolicyChannelEvidenceV1>(grant.provenance.channelEvidenceRef);
          same(grant, evaluator.grant(planned.request, planned.target, channel, grant.issuedAt, grant.expiresAt));
          check(grant.issuedAt >= candidate.createdAt && grant.expiresAt <= run.deadlineAt && prepared.timestamp >= grant.issuedAt && prepared.timestamp < grant.expiresAt);
          const decisionId = identityHash('cliq-verifier-policy-item-v1', run.id, opId, grant.provenance.channelEvidenceRef);
          const decisionRow = rowFor(decisionId), decision = items[decisionRow.itemSeq - 1]!;
          same(decision, { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'verifier_launch', itemId: decisionId, runId: run.id, opId,
            principalId: input.principalId, decisionRef: grant.provenance.channelEvidenceRef, policyChannelEvidenceRef: grant.provenance.channelEvidenceRef,
            policyChannelEvidenceDigest: channel.evidenceDigest, createdAt: channel.evaluatedAt, decisionSource: 'direct_policy', decision: 'allow', grantRef: prepared.grantRef });
          check(decisionRow.itemSeq > row.itemSeq && decisionRow.createdAt <= prepared.timestamp && decisionRow.createdAt >= candidate.createdAt); seenVerifierItems.add(decisionId);
          previous = { terminal, claimed: !!claim };
          const firstTerminal = attempt.find(entry => ['unknown', 'completed', 'failed'].includes(entry.phase)); check(firstTerminal?.budgetSettlementRef);
          stage = 'verifier_settlement';
          const settlement = decodeBudgetSettlement(await object(firstTerminal!.budgetSettlementRef!));
          check(settlement.runId === run.id && settlement.opId === opId && settlement.attempt === attemptIndex && settlement.preparedJournalSeq === prepared.seq &&
            settlement.terminalJournalSeq === firstTerminal!.seq && settlement.terminalPhase === firstTerminal!.phase && settlement.settledAt === firstTerminal!.timestamp);
          same(settlement.reserved, ONE_TOOL); same(settlement.consumed, claim ? ONE_TOOL : ZERO); same(firstTerminal!.budgetDelta, claim ? ONE_TOOL : ZERO);
          for (const later of attempt.filter(entry => entry.seq > firstTerminal!.seq)) { check(later.budgetSettlementRef === firstTerminal!.budgetSettlementRef); same(later.budgetDelta, ZERO); }
          if (!claim) {
            check(terminal.phase === 'failed' && terminal.errorRef && !terminal.receiptRef && !terminal.resultRef && !terminal.dispatchId && !terminal.sandboxLaunchSpecRef);
            same(await object(terminal.errorRef!), { schemaVersion: 1, format: 'cliq-verifier-preparation-closure-v1', runId: run.id, opId,
              attempt: attemptIndex, preparedJournalSeq: prepared.seq, requestRef: prepared.requestRef, targetRef: prepared.target, grantRef: prepared.grantRef, disposition: 'unclaimed' });
            continue;
          }
          verifierAttemptCount++; same(claim.budgetDelta, ZERO);
          stage = 'verifier_receipt';
          check(claim.dispatchId && claim.supervisorInstanceId && claim.stateOwnerEpoch && claim.sandboxLaunchSpecRef && claim.timestamp >= grant.issuedAt && claim.timestamp < grant.expiresAt &&
            terminal.phase === 'completed' && terminal.receiptRef && terminal.resultRef === terminal.receiptRef);
          const receipt = decodeVerificationReceipt(await object(terminal.receiptRef!));
          check(receipt.runId === run.id && receipt.verifierId === specEntry.id && receipt.verifierVersion === specEntry.version && receipt.attempt === attemptIndex &&
            receipt.leaseEpoch === prepared.leaseEpoch && receipt.resultSourceRef === candidate.resultSourceRef && receipt.sourceDigestBefore === candidate.sourceDigest &&
            receipt.sourceDigestAfter === candidate.sourceDigest && receipt.commandRef === specEntry.commandRef && receipt.commandDigest === specEntry.commandDigest &&
            receipt.environmentRef === specEntry.environmentRef && receipt.environmentDigest === specEntry.environmentDigest && receipt.startedAt >= claim.timestamp && receipt.endedAt <= terminal.timestamp &&
            receipt.outcome !== 'source_mutation' && receipt.terminationReason !== 'controller_stop');
          if (caseKind === 'required_timeout') check(receipt.outcome === 'infra_failed' && receipt.terminationReason === 'timeout' &&
            receipt.durationMs >= specEntry.timeoutMs);
          const resultId = verifierResultItemId(run.id, opId, attemptIndex), resultRow = rowFor(resultId);
          const resultItem = decodeVerifierResultItem(items[resultRow.itemSeq - 1]);
          const expectedItem: VerifierResultItem = { schemaVersion: 1, kind: 'verifier_result', itemId: resultId, runId: run.id,
            candidateItemId: candidate.itemId, verifierPlanRef: planRef, verifierIndex: index, verifierId: specEntry.id, opId, attempt: attemptIndex,
            outcome: receipt.outcome, receiptRef: terminal.receiptRef!, createdAt: terminal.timestamp };
          same(resultItem, expectedItem); check(resultRow.itemSeq > decisionRow.itemSeq); seenVerifierItems.add(resultId);
          stage = 'verifier_retirement';
          const physical = await assertInstalledVerifierRetirement({ run, checkpoints, prepared, claim, terminal, requestContext,
            measurement: { retirementRef: receipt.containmentEvidenceRef, endedAt: receipt.endedAt, stdoutRef: receipt.stdoutRef, stderrRef: receipt.stderrRef },
            readRetainedArtifact: bytes, readOwnerHistory: input.readOwnerHistory }, value => { stage = value; });
          const cp = physical.checkpoint;
          stage = 'verifier_retirement_state';
          await state(cp, source.entriesRef);
          stage = 'verifier_retirement_context';
          await context(cp);
          stage = 'verifier_retirement_item_seq';
          check(cp.runItemSeq === resultRow.itemSeq);
          retirementIdentities.push(physical.identity);
          previous = { terminal, receipt, claimed: true, checkpointAt: cp.createdAt };
          if (attemptIndex === preparedRows.length - 1) {
            Object.assign(entryProgress, { receipt, resultItem, terminalJournal: terminal });
            if (receipt.outcome === 'passed') entryProgress.disposition = { kind: 'passed', verifierResultItemId: resultId, opId, attempt: attemptIndex, completedJournalSeq: terminal.seq, receiptRef: terminal.receiptRef! };
            else if (!planEntry.required && (receipt.outcome === 'assertion_failed' || receipt.outcome === 'infra_failed'))
              entryProgress.disposition = { kind: 'advisory_nonpassing', outcome: receipt.outcome, verifierResultItemId: resultId, opId, attempt: attemptIndex, terminalJournalSeq: terminal.seq, receiptRef: terminal.receiptRef! };
          }
        }
        check(operation.every(entry => entry.attempt < preparedRows.length));
        check(entryProgress.receipt && entryProgress.resultItem && entryProgress.terminalJournal);
        if (index > 0) {
          const prior = progress.entries[index - 1]!;
          check(prior.disposition && !(prior.receipt?.outcome === 'infra_failed' && journal.filter(entry => entry.opId === prior.terminalJournal?.opId && entry.phase === 'dispatch_claimed').length < prior.planEntry.maxAttempts));
        }
      }
    }

    stage = 'reverse_history_and_repair';
    check(journal.filter(entry => entry.opKind === 'verifier').every(entry => seenVerifierJournal.has(entry.seq)));
    check(items.filter(item => item.kind.startsWith('verifier_') || item.kind === 'policy_decision' && item.subjectKind === 'verifier_launch').every(item => seenVerifierItems.has(item.itemId)));
    const repairs = items.filter(item => item.kind === 'repair_diagnostic').map(decodeRepairDiagnosticItem);
    check(repairs.length === (caseKind === 'required_repair' ? 1 : 0) && run.repairCount === repairs.length && run.budgetConsumed.repairAttempts === repairs.length &&
      repairs.length <= spec.budgets.repairAttempts);
    for (const [index, repair] of repairs.entries()) {
      const progress = progresses[index]!, repairRow = rowFor(repair.itemId), nextCandidate = candidates[index + 1]!;
      check(repair.repairOrdinal === index + 1 && repair.candidateItemId === progress.candidate.itemId && repairRow.itemSeq > rowFor(progress.candidate.itemId).itemSeq &&
        repairRow.itemSeq < rowFor(nextCandidate.itemId).itemSeq);
      const expected = planVerifierRepair(progress, { runId: run.id, repairOrdinal: index + 1, createdAt: repair.createdAt }); same(repair, expected.item);
      for (const plan of expected.plans) same(await object(plan.ref), parseJsonStrict(Buffer.from(plan.bytes).toString('utf8')));
      const cp = checkpoint(expected.checkpointId), completion = progress.entries.at(-1)!.resultItem!;
      const producerCp = checkpoint(verifierCheckpointId(run.id, completion.opId, completion.attempt));
      check(cp.reason === 'auto' && cp.runItemSeq === repairRow.itemSeq && cp.journalSeq === producerCp.journalSeq &&
        cp.workspaceStateRef === producerCp.workspaceStateRef && cp.createdAt >= repair.createdAt && repair.createdAt >= producerCp.createdAt &&
        cp.basedOnRunRevision === producerCp.basedOnRunRevision + 1);
      await context(cp);
      const frontier = { ...expected.frontier, contextItemSeq: repairRow.itemSeq }; same(await object(canonicalSha256(frontier)), frontier);
      const nextModel = journal.find(entry => entry.opKind === 'model' && entry.phase === 'prepared' && entry.seq > cp.journalSeq);
      check(nextModel?.grantRef && nextModel.timestamp >= cp.createdAt);
      const grant = await object(nextModel!.grantRef!), request = await object(nextModel!.requestRef);
      check(grant.frontierRef === canonicalSha256(frontier) && grant.issuedAt >= cp.createdAt && request.kind === 'normal');
      const projection = await object(request.promptProjectionRef);
      check(projection.runId === run.id && projection.runSpecRef === run.specRef && projection.frontierDigest === canonicalSha256(frontier) &&
        projection.contextManifestRef === cp.contextManifestRef && projection.projectionDigest === digestOmitting(projection, 'projectionDigest') &&
        request.promptProjectionDigest === projection.projectionDigest);
      const messages = projection.messages.filter((message: any) => message.sourceKind === 'verifier_repair');
      same(messages.map((message: any) => ({ role: message.role, sourceKind: message.sourceKind, sourceId: message.sourceId, contentUtf8: message.contentUtf8 })),
        expected.plans.filter(plan => plan.schemaKind === 'cliq-verifier-repair-model-content-v1').map(plan => ({ role: 'user', sourceKind: 'verifier_repair', sourceId: repair.itemId,
          contentUtf8: (parseJsonStrict(Buffer.from(plan.bytes).toString('utf8')) as { message: string }).message })));
      check(!journal.some(entry => entry.opKind === 'verifier' && entry.seq > cp.journalSeq && progress.entries.some(prior => prior.terminalJournal?.opId === entry.opId)));
    }
    // Sum original settlements, never the resolved UNKNOWN row or Run's own
    // counter as evidence. Repair is counted only from the graph above.
    const consumed = { ...ZERO, repairAttempts: repairs.length }, seenSettlements = new Set<string>();
    for (const entry of journal) if (entry.budgetSettlementRef && !seenSettlements.has(entry.budgetSettlementRef)) {
      seenSettlements.add(entry.budgetSettlementRef);
      const settlement = decodeBudgetSettlement(await object(entry.budgetSettlementRef));
      check(settlement.runId === run.id && settlement.opId === entry.opId && settlement.attempt === entry.attempt && settlement.terminalJournalSeq === entry.seq && settlement.settledAt === entry.timestamp);
      for (const key of Object.keys(consumed) as Array<keyof typeof consumed>) { consumed[key] += settlement.consumed[key]; check(Number.isSafeInteger(consumed[key])); }
    }
    same(run.budgetConsumed, consumed);
    const attempts = new Map<string, InvocationJournalEntry>();
    for (const entry of journal) attempts.set(`${entry.opId}:${entry.attempt}`, entry);
    check([...attempts.values()].every(entry => entry.phase === 'completed' || entry.phase === 'failed'));

    stage = 'terminal_result';
    const last = progresses.at(-1)!, candidate = last.candidate;
    let resultRef: string | undefined, verificationClosureRef: string | undefined, summaryRef: string | undefined, summaryDigest: string | undefined;
    if (caseKind === 'required_timeout') {
      check(run.status === 'failed' && run.terminalReason === 'verifier_infrastructure_failed' && !run.resultRef && run.stopIntentRef && run.terminalDetailRef);
      check(last.entries.some(entry => entry.planEntry.required && entry.receipt?.outcome === 'infra_failed'));
      for (const entry of last.entries.filter(entry => entry.planEntry.required && entry.receipt?.outcome === 'infra_failed')) {
        check(entry.receipt!.terminationReason === 'timeout' && journal.filter(row => row.opId === entry.terminalJournal!.opId && row.phase === 'dispatch_claimed').length === entry.planEntry.maxAttempts);
      }
      const stop = decodeAgentStop(await object(run.stopIntentRef!), run);
      check(stop.origin === 'verification' && stop.reason === 'verifier_infrastructure_failed');
      if (stop.origin !== 'verification') throw new Error('wrong required timeout stop');
      check(stop.candidateItemId === candidate.itemId && stop.verifierPlanRef === last.planRef);
      const detail = await object(run.terminalDetailRef!); same(detail, agentStopDetail(stop, run.stopIntentRef!, detail.createdAt));
      const cp = checkpoint(stopCheckpointId(run.id, run.stopIntentRef!));
      check(cp.id === run.latestCheckpointId && cp.createdAt === run.updatedAt && cp.basedOnRunRevision === run.revision - 1 && cp.runItemSeq === items.length && cp.journalSeq === journal.length);
      const completion = last.entries.at(-1)!.resultItem!, producerCp = checkpoint(verifierCheckpointId(run.id, completion.opId, completion.attempt));
      check(cp.workspaceStateRef === producerCp.workspaceStateRef && cp.contextManifestRef === producerCp.contextManifestRef && stop.createdAt >= producerCp.createdAt);
    } else {
      check(run.status === (required ? 'succeeded' : 'completed_unverified') && run.terminalReason === (required ? 'verified' : 'no_required_verifier') &&
        !run.stopIntentRef && !run.terminalDetailRef && run.resultRef);
      check(last.entries.every(entry => entry.disposition) && last.entries.every(entry => !entry.planEntry.required || entry.receipt?.outcome === 'passed'));
      if (caseKind === 'advisory_failure') check(last.entries.some(entry => !entry.planEntry.required && entry.receipt?.outcome === 'assertion_failed'));
      resultRef = run.resultRef!;
      const result = decodeRunResult(await object(resultRef)); verificationClosureRef = result.verificationClosureRef;
      const closure = decodeVerificationClosure(await object(verificationClosureRef));
      const entries = last.entries.map(entry => ({ verifierIndex: entry.planEntry.index, verifierId: entry.planEntry.verifierId,
        verifierSpecDigest: entry.planEntry.verifierSpecDigest, verifierEntryDigest: entry.planEntry.verifierEntryDigest,
        required: entry.planEntry.required, disposition: entry.disposition! }));
      const verification = { kind: 'local' as const, outcome: required ? 'verified' as const : 'unverified' as const,
        ...(required ? {} : { unverifiedConsentRef: spec.unverifiedConsentRef! }), entries };
      const closureCore = { schemaVersion: 1 as const, format: 'cliq-verification-closure-v1' as const, runId: run.id,
        candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef, verifierPlanRef: last.planRef,
        dependency: { kind: 'none' as const }, verification, createdAt: closure.createdAt };
      same(closure, { ...closureCore, closureDigest: canonicalSha256(closureCore) } satisfies VerificationClosureV1);
      same(result, { schemaVersion: 1, runId: run.id, baseSourceRef: candidate.baseSourceRef, resultSourceRef: candidate.resultSourceRef,
        diffRef: candidate.diffRef, verificationClosureRef, verificationReceiptRefs: entries.map(entry => {
          check('receiptRef' in entry.disposition); return (entry.disposition as { receiptRef: string }).receiptRef;
        }), summaryRef: candidate.summaryRef, createdAt: result.createdAt });
      const completion = last.entries.at(-1)!.resultItem!, producerCp = checkpoint(verifierCheckpointId(run.id, completion.opId, completion.attempt));
      const verificationCp = checkpoint(identityHash('cliq-verification-finalize-checkpoint-v1', run.id, candidate.itemId, verificationClosureRef));
      const finalCp = checkpoint(identityHash('cliq-run-result-checkpoint-v1', run.id, candidate.itemId, resultRef));
      for (const cp of [verificationCp, finalCp]) check(cp.reason === 'auto' && cp.runItemSeq === items.length && cp.journalSeq === journal.length &&
        cp.contextManifestRef === producerCp.contextManifestRef && cp.workspaceStateRef === producerCp.workspaceStateRef);
      check(verificationCp.basedOnRunRevision === producerCp.basedOnRunRevision + 1 && verificationCp.createdAt >= producerCp.createdAt &&
        verificationCp.createdAt >= closure.createdAt && closure.createdAt >= candidate.createdAt && result.createdAt >= verificationCp.createdAt &&
        finalCp.basedOnRunRevision === verificationCp.basedOnRunRevision + 1 && finalCp.basedOnRunRevision === run.revision - 1 &&
        finalCp.id === run.latestCheckpointId && finalCp.createdAt === run.updatedAt && result.createdAt <= run.updatedAt);
      summaryRef = result.summaryRef;
      const summary = await object<ModelTextV1>(summaryRef); verifyModelText(summary); check(summary.utf8.trim()); summaryDigest = summary.textDigest;
    }

    stage = 'session_publication';
    const terminalRows = [];
    for (const row of sessionCut.items) {
      check(row.schemaVersion === 1 && row.sessionId === run.sessionId && row.itemSeq <= session.latestItemSeq);
      const payload = await object(row.payloadRef);
      if (payload.runId === run.id) terminalRows.push({ row, payload });
    }
    check(terminalRows.length === 1);
    const { row: terminalRow, payload } = terminalRows[0]!;
    check(terminalRow.itemId === identityHash('cliq-session-run-terminal-item-v1', run.sessionId, run.id) && terminalRow.kind === 'run_terminal' && terminalRow.createdAt === run.updatedAt);
    same(payload, { schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal', itemKey: `run-terminal:${run.id}`,
      runId: run.id, operation: 'agent', admittedSessionItemSeq: admitted.throughSessionItemSeq, status: run.status, terminalReason: run.terminalReason,
      ...(resultRef ? { resultRef, summaryRef, summaryDigest } : { terminalDetailRef: run.terminalDetailRef }) });
    const projection = decodeSessionProjection(await object(session.contextProjectionRef));
    check(projection.sessionId === run.sessionId && projection.contextRevision === session.contextRevision && projection.throughItemSeq === session.latestItemSeq);
    const segments = projection.segments.filter(segment => segment.fromItemSeq <= terminalRow.itemSeq && segment.throughItemSeq >= terminalRow.itemSeq);
    same(segments, [{ kind: 'raw', fromItemSeq: terminalRow.itemSeq, throughItemSeq: terminalRow.itemSeq,
      items: [{ sourceSessionId: run.sessionId, itemSeq: terminalRow.itemSeq, itemId: terminalRow.itemId, kind: 'run_terminal', payloadRef: terminalRow.payloadRef }] }]);
    return { caseKind, runId: run.id, sessionId: run.sessionId, status: run.status as InstalledVerifierOutcome['status'],
      terminalReason: run.terminalReason as InstalledVerifierOutcome['terminalReason'], candidateCount: candidates.length,
      verifierAttemptCount, repairCount: repairs.length, checkedFileCount: input.expectedFiles.length,
      ...(resultRef ? { resultRef, verificationClosureRef } : {}), retirementIdentities };
  } catch {
    // In particular, never attach decoder/assertion errors as a cause: a
    // failed comparison may contain workspace/provider-controlled data.
    throw new InstalledVerifierOutcomeError(stage);
  }
}
