// One public consumer journey. Its owner supplies the real signed installation,
// authenticated client, scoped credential and actual process/resource joins.
// No setup, secret handling, host execution or native authority lives here.
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { BudgetUsage, RunSpec } from '../../../src/kernel/types.js';
import type { RunModelRequest } from '../../../src/kernel/control-submit.js';
import { decodeInstalledControlRequest, decodeInstalledControlResponse,
  type InstalledControlFeature, type InstalledControlRequestV1, type InstalledControlResponseFor } from '../../../src/control/v1.js';
import { clientMutation } from '../../../src/client/commands.js';
import { presentControlArtifacts, type ClientDetail } from '../../../src/client/details.js';
import { decodeRunSpec, decodeSourceManifest, decodeWorkspaceEntries, decodeBudgetSettlement } from '../../../src/state/decoders.js';
import { decodeRetainedRunAssembly } from '../../../src/model/run-assembly.js';
import { decodeRunResult, decodeWorkspaceDiff, decodeVerificationClosure, decodeInheritedVerificationProvenance } from '../../../src/state/result-artifacts.js';
import { decodeVerificationReceipt, decodeVerifierCommand, decodeVerifierEnvironment } from '../../../src/state/verifier-artifacts.js';
import { decodeDeliveryTerminalProjectionEvidence } from '../../../src/kernel/publication.js';

export const PROVIDER_JOURNEY_FILES = Object.freeze({
  'math.mjs': 'export function add(a, b) {\n  return a - b;\n}\n',
  'check.test.mjs': "import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport { add } from './math.mjs';\n\ntest('add handles positive, negative and zero operands', () => {\n  assert.equal(add(3, 2), 5);\n  assert.equal(add(-3, 2), -1);\n  assert.equal(add(0, 7), 7);\n});\n"
});
const CHECK_ARGS = ['--test', '--test-concurrency=1', 'check.test.mjs'];
const ZERO: BudgetUsage = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const ARTIFACT_BYTES = 64 * 1024 * 1024, REQUEST_MS = 30_000, TERMINAL_MS = 90_000;
type Result<M extends InstalledControlFeature> = Extract<InstalledControlResponseFor<M>, { ok: true }>['result'];
type Cut = Result<'run.get'>;
export type ProviderJourneyStage = 'workspace' | 'session' | 'authorization' | 'admission' | 'execution' | 'result' |
  'review' | 'reconnect' | 'application' | 'publication' | 'accounting';
export class InstalledProviderJourneyError extends Error {
  readonly code = 'INSTALLED_PROVIDER_JOURNEY_REFUSED';
  constructor(readonly stage: ProviderJourneyStage) { super(`installed provider journey refused at ${stage}`); this.name = 'InstalledProviderJourneyError'; }
}
export type InstalledProviderJourneyInput = Readonly<{
  workspacePath: string; model: RunModelRequest & { provider: 'openai-compatible' }; budgets: RunSpec['budgets'];
  guestToolchainManifestId: string; endpointIdentityDigest: string;
}>;
export type InstalledProviderJourneyContext = Readonly<{
  send(request: InstalledControlRequestV1, timeoutMs: number): Promise<unknown>;
  artifact(ref: string, options: { maxBytes: number; signal?: AbortSignal }): Promise<Buffer>;
  reconnect(): Promise<void>;
  /** Owner's joined no-follow/full-byte observation of only its tiny fixture.
   * This is read-only test composition, never a native proof or execution grant. */
  observeWorkspace(): Promise<Readonly<{ paths: readonly string[]; math: Buffer; test: Buffer }>>;
  review?(detail: ClientDetail): void | Promise<void>;
  mark?(phase: ProviderJourneyStage): void;
}>;
const check = (condition: unknown): void => { if (!condition) throw new Error('public provider workflow invariant failed'); };
const same = (a: unknown, b: unknown) => check(canonicalJsonBytes(a).equals(canonicalJsonBytes(b)));

/** Run only after the owner has installed and registered the actual package,
 * endpoint, safe credential and Workspace Trust. A test protocol implementation
 * can exercise these decisions, but can never turn this report into provider,
 * containment, billing, installation or complete I1/I2 qualification. */
export async function runInstalledProviderJourney(input: InstalledProviderJourneyInput, context: InstalledProviderJourneyContext) {
  let stage: ProviderJourneyStage = 'workspace';
  const mark = (next: ProviderJourneyStage) => { stage = next; context.mark?.(next); };
  try {
    async function send<M extends InstalledControlFeature>(request: unknown, method: M): Promise<Result<M>> {
      const selected = decodeInstalledControlRequest(request); check(selected.method === method);
      const response = decodeInstalledControlResponse(await context.send(selected, REQUEST_MS), selected);
      check(response.ok);
      return (response as Extract<typeof response, { ok: true }>).result as Result<M>;
    }
    async function bytes(ref: string) {
      const data = await context.artifact(ref, { maxBytes: ARTIFACT_BYTES });
      check(Buffer.isBuffer(data) && data.length <= ARTIFACT_BYTES && sha256Bytes(data) === ref); return data;
    }
    async function object(ref: string) {
      const data = await bytes(ref), value: unknown = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data));
      check(canonicalJsonBytes(value).equals(data)); return value;
    }
    const observe = async (expectedMath: Buffer) => {
      const observation = await context.observeWorkspace();
      same([...observation.paths].sort(), ['check.test.mjs', 'math.mjs']);
      check(observation.math.equals(expectedMath) && observation.test.equals(Buffer.from(PROVIDER_JOURNEY_FILES['check.test.mjs'])));
    };
    const originalMath = Buffer.from(PROVIDER_JOURNEY_FILES['math.mjs']);
    await observe(originalMath);
    mark('session');
    const created = await send(clientMutation({ method: 'session.create', workspacePath: input.workspacePath }, true), 'session.create');
    const session = created.snapshot.session;
    mark('authorization');
    const authorized = await send(clientMutation({ method: 'authorization.create', decision: { kind: 'execution_identity_read', purpose: 'verifier',
      target: { kind: 'guest_toolchain', guestToolchainManifestId: input.guestToolchainManifestId, toolId: 'node' } } }), 'authorization.create');
    check(authorized.grant.state === 'active' && authorized.grant.purpose === 'verifier' &&
      authorized.grant.targetKind === 'execution_identity_read' && authorized.grant.useCount === 0);
    mark('admission');
    const submit = clientMutation({ method: 'run.submit', sessionId: session.id, expectedContextRevision: session.contextRevision,
      workspacePath: input.workspacePath,
      objective: 'Fix the add function in math.mjs so the existing check.test.mjs tests pass. Inspect the files and edit only math.mjs. Preserve check.test.mjs byte-for-byte. Do not add files, dependencies or network calls. Finish with a concise explanation of the fix.',
      model: input.model, policyMode: 'yolo', budgets: input.budgets, maxChangedPaths: 1, maxChangedBytes: 65_536,
      verifiers: [{ id: 'node-tests', version: '1', required: true, executable: { kind: 'toolchain', toolId: 'node' },
        argv: CHECK_ARGS.map(value => ({ kind: 'non_secret_literal', value })), cwd: '.', env: {}, writableEphemeralPaths: [],
        identityReadGrantId: authorized.grant.grantId, timeoutMs: 10_000, retries: 0, outputLimitBytes: 65_536 }],
      dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: false }, true);
    const admitted = await send(submit, 'run.submit'), sourceRunId = admitted.snapshot.run.id;
    check(admitted.snapshot.operation === 'agent' && admitted.snapshot.run.sessionId === session.id);

    async function terminal(runId: string): Promise<Cut> {
      const by = Date.now() + TERMINAL_MS;
      for (;;) {
        check(Date.now() < by);
        const cut = await send({ protocolVersion: 1, method: 'run.get', runId, itemLimit: 1, journalLimit: 1, checkpointLimit: 1 }, 'run.get');
        check(Date.now() < by);
        if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(cut.snapshot.run.status)) return cut;
        // A wait is visible refusal to finish this particular autonomous case.
        // Never approve, probe, replace an admission or guess UNKNOWN here.
        check(cut.snapshot.run.status !== 'waiting'); await delay(250);
      }
    }
    async function fullCut(runId: string): Promise<Cut> {
      const first = await send({ protocolVersion: 1, method: 'run.get', runId, itemLimit: 100, journalLimit: 100, checkpointLimit: 100 }, 'run.get');
      check(['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(first.snapshot.run.status));
      const items = [...first.items], journal = [...first.journal], checkpoints = [...first.checkpoints];
      let page = first, pages = 1;
      while (page.nextItemSeq < first.highWaterItemSeq || page.nextJournalSeq < first.highWaterJournalSeq || page.nextCheckpointCursor !== first.highWaterCheckpointCursor) {
        check(++pages <= 1000 && items.length + journal.length + checkpoints.length <= 10_000);
        const next = await send({ protocolVersion: 1, method: 'run.get', runId, afterItemSeq: page.nextItemSeq, afterJournalSeq: page.nextJournalSeq,
          // A full item/Journal frame may not have reached checkpoints yet.
          // Only an actually issued next cursor advances that stream.
          ...(page.nextCheckpointCursor === undefined ? {} : { checkpointCursor: page.nextCheckpointCursor }),
          itemLimit: 100, journalLimit: 100, checkpointLimit: 100 }, 'run.get');
        same(next.snapshot, first.snapshot); same([next.highWaterItemSeq, next.highWaterJournalSeq, next.highWaterCheckpointCursor ?? null],
          [first.highWaterItemSeq, first.highWaterJournalSeq, first.highWaterCheckpointCursor ?? null]);
        check(next.nextItemSeq > page.nextItemSeq || next.nextJournalSeq > page.nextJournalSeq ||
          next.nextCheckpointCursor !== page.nextCheckpointCursor);
        items.push(...next.items); journal.push(...next.journal); checkpoints.push(...next.checkpoints); page = next;
      }
      check(items.length + journal.length + checkpoints.length <= 10_000);
      check(items.length === first.highWaterItemSeq && journal.length === first.highWaterJournalSeq);
      items.forEach((row, index) => check(row.itemSeq === index + 1)); journal.forEach((row, index) => check(row.seq === index + 1));
      check(new Set(items.map(item => item.itemId)).size === items.length && new Set(checkpoints.map(item => item.id)).size === checkpoints.length);
      check(checkpoints.some(row => row.id === first.snapshot.run.latestCheckpointId));
      const { nextCheckpointCursor: _firstNext, ...captured } = first;
      return { ...captured, items, journal, checkpoints, nextItemSeq: page.nextItemSeq, nextJournalSeq: page.nextJournalSeq,
        ...(page.nextCheckpointCursor === undefined ? {} : { nextCheckpointCursor: page.nextCheckpointCursor }) };
    }
    async function accounting(cut: Cut) {
      same(cut.snapshot.run.budgetReserved, ZERO);
      const consumed = { ...ZERO }, settlements = new Map<string, string>();
      for (const row of cut.journal) {
        if (row.budgetSettlementRef === undefined) continue;
        const key = `${row.opId}\0${row.attempt}`, previous = settlements.get(key);
        if (previous !== undefined) { check(previous === row.budgetSettlementRef); continue; }
        const settlement = decodeBudgetSettlement(await object(row.budgetSettlementRef));
        check(settlement.runId === cut.snapshot.run.id && settlement.opId === row.opId && settlement.attempt === row.attempt);
        const prepared = cut.journal[settlement.preparedJournalSeq - 1], terminal = cut.journal[settlement.terminalJournalSeq - 1];
        check(prepared?.phase === 'prepared' && prepared.opId === row.opId && prepared.attempt === row.attempt &&
          terminal?.phase === settlement.terminalPhase && terminal.opId === row.opId && terminal.attempt === row.attempt &&
          terminal.budgetSettlementRef === row.budgetSettlementRef);
        same(terminal.budgetDelta, settlement.consumed);
        settlements.set(key, row.budgetSettlementRef);
        for (const dimension of Object.keys(ZERO) as (keyof BudgetUsage)[]) {
          consumed[dimension] += settlement.consumed[dimension]; check(Number.isSafeInteger(consumed[dimension]));
        }
      }
      same(consumed, cut.snapshot.run.budgetConsumed); return consumed;
    }
    mark('execution'); await terminal(sourceRunId); const source = await fullCut(sourceRunId);
    check(source.snapshot.operation === 'agent' && source.snapshot.run.status === 'succeeded' && source.snapshot.run.terminalReason === 'verified');
    await observe(originalMath); // Private execution must leave the host untouched.
    mark('result');
    const spec = decodeRunSpec(await object(source.snapshot.run.specRef)), assembly = decodeRetainedRunAssembly(await object(spec.assemblyRef));
    same(spec.budgets, input.budgets);
    check(assembly.provider.name === input.model.provider && assembly.provider.model === input.model.model &&
      assembly.provider.endpoint.kind === 'registered' && assembly.provider.endpoint.endpointIdentityDigest === input.endpointIdentityDigest);
    const reply = await send({ protocolVersion: 1, method: 'run.result', runId: sourceRunId }, 'run.result');
    check(reply.result.ref === source.snapshot.run.resultRef);
    const result = decodeRunResult(await object(reply.result.ref)), closure = decodeVerificationClosure(await object(result.verificationClosureRef));
    check(result.runId === sourceRunId && result.baseSourceRef === spec.baseWorkspaceManifestRef && result.verificationClosureRef === reply.verificationClosureRef &&
      closure.runId === sourceRunId && closure.resultSourceRef === result.resultSourceRef && closure.verification.kind === 'local' && closure.verification.outcome === 'verified');
    if (closure.verification.kind !== 'local') throw new Error('local source check required');
    check(closure.verification.entries.length === 1);
    const entry = closure.verification.entries[0]!;
    check(entry.required && entry.verifierId === 'node-tests' && entry.disposition.kind === 'passed');
    if (entry.disposition.kind !== 'passed') throw new Error('passing required check required');
    const passed = entry.disposition, receiptRef = passed.receiptRef, receipt = decodeVerificationReceipt(await object(receiptRef));
    same(result.verificationReceiptRefs, [receiptRef]);
    check(receipt.runId === sourceRunId && receipt.verifierId === 'node-tests' && receipt.resultSourceRef === result.resultSourceRef &&
      receipt.outcome === 'passed' && receipt.exitCode === 0 && receipt.terminationReason === 'exit' && !receipt.stdoutTruncated && !receipt.stderrTruncated);
    const command = decodeVerifierCommand(await object(receipt.commandRef)), environment = decodeVerifierEnvironment(await object(receipt.environmentRef));
    check(command.executable.kind === 'guest_toolchain' && command.executable.toolId === 'node' && command.cwd === '.');
    same(command.argv, CHECK_ARGS.map(value => ({ kind: 'non_secret_literal', value })));
    check(environment.commandRef === receipt.commandRef && environment.commandDigest === command.commandDigest &&
      environment.sourceAccess === 'read_only' && environment.networkAccess === 'denied');
    same(environment.variables, []); same(environment.writableEphemeralPaths, []);
    const resultSource = decodeSourceManifest(await object(result.resultSourceRef)), entries = decodeWorkspaceEntries(await object(resultSource.entriesRef));
    check(resultSource.treeDigest === entries.treeDigest && receipt.sourceDigestBefore === resultSource.manifestDigest && receipt.sourceDigestAfter === resultSource.manifestDigest);
    same(entries.entries.map(row => row.path), ['check.test.mjs', 'math.mjs']);
    const testFile = entries.entries[0]!, mathFile = entries.entries[1]!;
    check(testFile.kind === 'file' && mathFile.kind === 'file');
    if (testFile.kind !== 'file' || mathFile.kind !== 'file') throw new Error('fixed file result required');
    check(testFile.mode === 0o644 && mathFile.mode === 0o644 && testFile.blobRef === sha256Bytes(Buffer.from(PROVIDER_JOURNEY_FILES['check.test.mjs'])));
    const fixedMath = await bytes(mathFile.blobRef); check(fixedMath.length === mathFile.size && !fixedMath.equals(originalMath));
    check((await bytes(testFile.blobRef)).equals(Buffer.from(PROVIDER_JOURNEY_FILES['check.test.mjs'])));
    const diff = decodeWorkspaceDiff(await object(result.diffRef));
    check(diff.baseSourceRef === result.baseSourceRef && diff.resultSourceRef === result.resultSourceRef && diff.operations.length === 1);
    const change = diff.operations[0]!;
    check(change.kind === 'modify' && change.path === 'math.mjs');
    if (change.kind !== 'modify') throw new Error('fixed modification required');
    check(change.before.kind === 'file' && change.before.blobRef === sha256Bytes(originalMath)); same(change.after, mathFile);
    const verifierCompletion = source.journal.find(row => row.opKind === 'verifier' && row.opId === passed.opId &&
      row.attempt === passed.attempt && row.phase === 'completed' && row.receiptRef === receiptRef);
    check(verifierCompletion && verifierCompletion.seq === passed.completedJournalSeq);
    check(source.journal.some(row => row.opKind === 'model' && row.phase === 'completed') && source.journal.some(row => row.opKind === 'tool' && row.phase === 'completed'));
    mark('accounting'); const sourceConsumed = await accounting(source);
    check(sourceConsumed.costMicros > 0 && sourceConsumed.modelTokens > 0);
    for (const dimension of Object.keys(ZERO) as (keyof BudgetUsage)[]) check(sourceConsumed[dimension] <= input.budgets[dimension]);
    mark('review');
    const review: ClientDetail[] = [];
    await presentControlArtifacts({ artifact: context.artifact }, { protocolVersion: 1, method: 'run.result', runId: sourceRunId },
      { protocolVersion: 1, ok: true, result: reply }, async detail => { review.push(detail); await context.review?.(detail); });
    check(review.length === 1 && review[0]!.artifactRef === reply.result.ref);
    mark('reconnect'); await context.reconnect(); same(await send(submit, 'run.submit'), admitted); same(await fullCut(sourceRunId), source);
    await observe(originalMath);
    mark('application');
    const apply = clientMutation({ method: 'run.apply', sourceRunId, expectedRunResultRef: reply.result.ref,
      budgets: { wallTimeMs: input.budgets.wallTimeMs, toolCalls: input.budgets.toolCalls } }, true);
    const applied = await send(apply, 'run.apply'), deliveryRunId = applied.snapshot.run.id;
    check(applied.snapshot.operation === 'delivery' && deliveryRunId !== sourceRunId);
    mark('publication'); await terminal(deliveryRunId); const delivery = await fullCut(deliveryRunId);
    check(delivery.snapshot.operation === 'delivery' && delivery.snapshot.run.status === 'succeeded' && delivery.snapshot.run.terminalReason === 'verified');
    const published = await send({ protocolVersion: 1, method: 'run.result', runId: deliveryRunId }, 'run.result');
    check(published.result.ref === delivery.snapshot.run.resultRef);
    const deliveredResult = decodeRunResult(await object(published.result.ref));
    check(deliveredResult.runId === deliveryRunId && deliveredResult.resultSourceRef === result.resultSourceRef &&
      deliveredResult.verificationClosureRef === published.verificationClosureRef && deliveredResult.deliveryTerminalProjectionEvidenceRef);
    const deliveredClosure = decodeVerificationClosure(await object(deliveredResult.verificationClosureRef));
    check(deliveredClosure.runId === deliveryRunId && deliveredClosure.resultSourceRef === result.resultSourceRef);
    if (deliveredClosure.verification.kind === 'inherited_verified') {
      check(deliveredClosure.verification.sourceRunId === sourceRunId && deliveredClosure.verification.sourceRunResultRef === reply.result.ref &&
        deliveredClosure.verification.sourceVerificationClosureRef === result.verificationClosureRef &&
        deliveredClosure.verification.inheritedProvenanceRef === deliveredResult.verificationProvenanceRef);
      const provenance = decodeInheritedVerificationProvenance(await object(deliveredClosure.verification.inheritedProvenanceRef));
      check(provenance.deliveryRunId === deliveryRunId && provenance.sourceRunId === sourceRunId && provenance.sourceRunResultRef === reply.result.ref &&
        provenance.sourceVerificationClosureRef === result.verificationClosureRef && provenance.resultSourceRef === result.resultSourceRef);
      same(provenance.verificationReceiptRefs, result.verificationReceiptRefs);
    } else check(deliveredClosure.verification.outcome === 'verified' && deliveredClosure.verification.entries.some(row => row.verifierId === 'node-tests' && row.required));
    const projection = decodeDeliveryTerminalProjectionEvidence(await object(deliveredResult.deliveryTerminalProjectionEvidenceRef!));
    check(projection.deliveryRunId === deliveryRunId && projection.observedSourceRef === result.resultSourceRef && projection.selectedBranch === 'forward_finalize');
    await observe(fixedMath);
    mark('accounting'); const deliveryConsumed = await accounting(delivery);
    check(deliveryConsumed.costMicros === 0 && deliveryConsumed.modelTokens === 0);
    mark('reconnect'); await context.reconnect(); same(await send(apply, 'run.apply'), applied);
    same(await fullCut(deliveryRunId), delivery); same(await fullCut(sourceRunId), source); await observe(fixedMath);
    return { protocolWorkflowComplete: true as const, actualProviderQualified: false as const, actualProviderBillingQualified: false as const,
      officialReleaseQualified: false as const, completeI1Qualified: false as const, completeI2Qualified: false as const,
      sourceRunId, deliveryRunId, resultRef: reply.result.ref, deliveredResultRef: published.result.ref,
      verificationClosureRef: result.verificationClosureRef, receiptRef, diffRef: result.diffRef,
      sourceConsumed, deliveryConsumed, sourceJournalEntries: source.journal.length, deliveryJournalEntries: delivery.journal.length,
      completedModelCalls: source.journal.filter(row => row.opKind === 'model' && row.phase === 'completed').length,
      hostFileDigest: mathFile.blobRef, preservedTestDigest: testFile.blobRef, reviewedArtifactRef: review[0]!.artifactRef };
  } catch {
    // Provider/tool bytes and arbitrary assertions must never become a retained
    // diagnostic, cause chain or console message in the credential-owning owner.
    throw new InstalledProviderJourneyError(stage);
  }
}
