import assert from 'node:assert/strict';
import { rootCertificates, connect } from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeHeadlessControlRecord, decodeInstalledControlResponse,
  type InstalledControlFeature, type InstalledControlRequestV1, type InstalledControlResponseFor } from '../../../src/control/v1.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { nodeTestArguments } from '../../../src/kernel/verifier.js';
import { decodeRunResult, decodeVerificationClosure, decodeWorkspaceDiff } from '../../../src/state/result-artifacts.js';
import { decodeSourceManifest } from '../../../src/state/decoders.js';
import { decodeVerifierCommand, decodeVerificationReceipt, verifierReportedLocations } from '../../../src/state/verifier-artifacts.js';
import type { ContinuationItem, Run, RunSpec, ToolResultItem, ToolResultPayloadV1, ToolResultModelContentV1 } from '../../../src/kernel/types.js';
import { INSTALLED_TOOL_NAMES } from '../../../src/tools/installed-contracts.js';
import { decodeAgentStop } from '../../../src/runtime/stop.js';
import { NPM_DATA_RECIPE } from '../../../src/sandbox/npm-data-image.js';
import { decodeDependencyFailureItem } from '../../../src/kernel/dependency.js';
import { decodeDependencyAcquisitionClosure } from '../../../src/kernel/dependency-acquisition.js';
import { decodeDependencyProcessCapture } from '../../../src/state/dependency-capture.js';
import { PR532_POLL_INTERVAL_MS } from './provider-journey-input.js';
import { PR532_CPU_DIAGNOSTIC } from './installed-cpu-diagnostic.js';
import { readInstalledTerminalCut, readInstalledStableCut } from './installed-provider-journey.js';

export const PR532_BASE = '9cce652c2a91d8484344e4794ae56576a915cc67';
export const PR532_CHECK_SOURCE = '961658fcf80116b6ef13e39cf39d901276a48c3c';
export const PR532_FILE = 'src/model/providers/openai-compatible.ts';
export const PR532_CHECK = 'src/model/providers/openai-compatible.test.ts';
export const PR532_REGISTRY = 'mirrors.tencent.com';
export const PR532_REGISTRY_BASE = '/npm';
export const PR532_REGISTRY_ID = 'pr532-public-npm-registry';

/** Bound data from the original result. Terminal failure diagnosis may retain
 * complete model-visible Bash output views within its explicit byte budget.
 * The original report secret scan gates publication of every retained byte. */
export function pr532ToolDiagnostic(item: ToolResultItem, payload: ToolResultPayloadV1, model?: ToolResultModelContentV1,
  failureOutputBytes?: number) {
  if (failureOutputBytes !== undefined)
    assert(Number.isSafeInteger(failureOutputBytes) && failureOutputBytes >= 0 && failureOutputBytes <= 1_048_576);
  assert.equal(item.schemaVersion, 1); assert.equal(payload.schemaVersion, 1);
  assert.equal(item.kind, 'tool_result');
  assert.equal(canonicalSha256(payload), item.resultRef);
  assert.equal(payload.payloadDigest, digestOmitting(payload, 'payloadDigest'));
  assert.equal(payload.format, 'cliq-tool-result-payload-v1');
  for (const key of ['runId', 'batchItemId', 'callId', 'index', 'outcome'] as const) assert.equal(payload[key], item[key]);
  const toolName = INSTALLED_TOOL_NAMES.find(name => name === payload.toolName);
  assert(toolName);
  assert(['executed', 'denied', 'error', 'batch_not_executed', 'cancelled'].includes(payload.outcome));
  if (toolName === 'bash' && payload.outcome === 'executed') {
    assert(model && model.schemaVersion === 1 && model.format === 'cliq-tool-result-model-content-v1');
    assert.equal(canonicalSha256(model), payload.modelContentRef);
    assert.equal(model.contentDigest, payload.modelContentDigest);
    assert.equal(model.contentDigest, digestOmitting(model, 'contentDigest'));
    for (const key of ['callId', 'index', 'toolName', 'outcome'] as const) assert.equal(model[key], payload[key]);
    const content = model.content as Record<string, unknown>;
    assert(content && typeof content === 'object' && !Array.isArray(content) && content.tool === 'bash');
    const terminationReason = ['exit', 'signal', 'spawn_error', 'timeout', 'resource_failure', 'controller_stop']
      .find(reason => reason === content.terminationReason);
    assert(terminationReason);
    const durationMs = content.durationMs;
    assert(typeof durationMs === 'number' && Number.isSafeInteger(durationMs) && durationMs >= 0);
    const exitCode = terminationReason === 'exit' ? content.exitCode : undefined;
    if (terminationReason === 'exit') assert(typeof exitCode === 'number' && Number.isSafeInteger(exitCode) && exitCode >= 0 && exitCode <= 255);
    const numeric = { toolName, outcome: payload.outcome, terminationReason, durationMs,
      ...(exitCode === undefined ? {} : { exitCode }) };
    if (failureOutputBytes === undefined || exitCode === 0) return numeric;
    if (failureOutputBytes === 0) return { ...numeric, failureOutput: { kind: 'omitted' as const, reason: 'diagnostic_byte_limit' as const } };
    const copy = (value: unknown) => {
      assert(value && typeof value === 'object' && !Array.isArray(value));
      const view = value as Record<string, unknown>;
      assert.equal(Object.keys(view).sort().join(','), 'byteCount,encoding,modelTruncated,nativeTruncated,text');
      assert(typeof view.text === 'string' && view.text.length <= 65_536);
      assert.equal(view.encoding, 'utf8_lossy');
      assert(typeof view.byteCount === 'number' && Number.isSafeInteger(view.byteCount) && view.byteCount >= view.text.length);
      assert(typeof view.nativeTruncated === 'boolean');
      assert.equal(view.modelTruncated, view.byteCount > 65_536);
      return { text: view.text, encoding: view.encoding, byteCount: view.byteCount,
        nativeTruncated: view.nativeTruncated, modelTruncated: view.modelTruncated };
    };
    const output = { stdout: copy(content.stdout), stderr: copy(content.stderr) };
    const byteCount = Buffer.byteLength(JSON.stringify(output));
    return { ...numeric, failureOutput: byteCount <= failureOutputBytes
      ? { kind: 'observed' as const, byteCount, ...output }
      : { kind: 'omitted' as const, reason: 'diagnostic_byte_limit' as const } };
  }
  if (payload.outcome !== 'error') return { toolName, outcome: payload.outcome };
  const code = ['TOOL_NOT_FOUND', 'TOOL_INPUT_INVALID', 'TOOL_AUTHORITY_UNAVAILABLE',
    'TOOL_EXECUTION_FAILED', 'TOOL_PROTOCOL_ERROR', 'TOOL_RESOURCE_EXHAUSTED', 'TOOL_RESULT_UNAVAILABLE',
  ].find(code => code === payload.code);
  assert(code);
  return { toolName, outcome: payload.outcome, code };
}

/** Pure projection of the original decoded Stop into bounded diagnostic data. */
export function pr532StopDiagnostic(run: Run, value: unknown) {
  const stop = decodeAgentStop(value, run);
  const base = { diagnosticOnly: true as const, origin: stop.origin, reason: stop.reason };
  if (stop.origin !== 'runtime') return base;
  if (stop.runtimeSubtype !== 'context_window_exhausted') return { ...base, runtimeSubtype: stop.runtimeSubtype };
  return { ...base, runtimeSubtype: stop.runtimeSubtype, nextPromptTokens: stop.nextPromptTokens,
    triggerThresholdTokens: stop.triggerThresholdTokens, hardPromptTokens: stop.hardPromptTokens,
    protectedTokens: stop.protectedTokens, sourceInputTokenCap: stop.sourceInputTokenCap,
    ...(stop.trigger === 'request_body_bytes' ? { trigger: stop.trigger, requestBodyBytes: stop.requestBodyBytes,
      requestBodyLimitBytes: stop.requestBodyLimitBytes } : {}) };
}

export async function readPr532PublisherInputs() {
  // Provision the disposable publisher using a CA/hostname-authenticated TLS
  // connection. The signed package and native broker still enforce the pin.
  const socket = connect({ host: PR532_REGISTRY, port: 443, servername: PR532_REGISTRY, ca: [...rootCertificates],
    rejectUnauthorized: true, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
  let pin: string | undefined;
  const deadline = setTimeout(() => socket.destroy(), 30_000);
  socket.on('error', () => { /* Only the fixed failure below leaves this producer. */ });
  socket.once('secureConnect', () => {
    try {
      if (socket.authorized && socket.getProtocol() === 'TLSv1.3')
        pin = sha256Bytes(new X509Certificate(socket.getPeerCertificate().raw).publicKey.export({ type: 'spki', format: 'der' }));
    } finally { socket.destroy(); }
  });
  await new Promise<void>(resolve => socket.once('close', () => { clearTimeout(deadline); resolve(); }));
  assert(pin, 'public npm mirror failed its TLS preflight');
  const response = await fetch(NPM_DATA_RECIPE.officialArchive, { redirect: 'error', signal: AbortSignal.timeout(60_000) });
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    assert.equal(response.status, 200); assert(response.body);
    for await (const chunk of response.body) {
      total += chunk.byteLength; assert(total <= NPM_DATA_RECIPE.archiveBytes);
      chunks.push(Buffer.from(chunk));
    }
  } finally { await response.body?.cancel(); }
  assert.equal(total, NPM_DATA_RECIPE.archiveBytes);
  return { registryPin: pin, npmArchive: Buffer.concat(chunks, total) };
}

type Result<M extends InstalledControlFeature> = Extract<InstalledControlResponseFor<M>, { ok: true }>['result'];

/** Public task data and advisory budget context, shared by both model modes. */
export function pr532TaskObjective(input: {
  originalBytes: Buffer; testBytes: Buffer; budgets: RunSpec['budgets']; modelRequestCostMicros?: number;
}): string {
  const files = [
    { path: PR532_FILE, bytes: input.originalBytes },
    { path: PR532_CHECK, bytes: input.testBytes },
  ].map(({ path, bytes }) => ({ path, sha256: sha256Bytes(bytes),
    contentUtf8: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) }));
  return [
    'Fix the DeepSeek compatibility regression in src/model/providers/openai-compatible.ts.',
    'DeepSeek Chat Completions rejects json_schema, enables thinking by default, and can take longer than the generic 20-second timeout.',
    'Keep behavior for other compatible endpoints.',
    'Edit only src/model/providers/openai-compatible.ts and keep all tests and dependency files unchanged.',
    'The original source and test are included below as repository data. They preserve the unfixed source and original assertions.',
    '\nOriginal repository files:\n' + canonicalJsonBytes({ files }).toString('utf8') + '\nEnd of original repository files.\n',
    ...(input.modelRequestCostMicros === undefined ? [] : [
      `This Run can afford at most ${Math.floor(input.budgets.costMicros / input.modelRequestCostMicros)} fully charged model calls, including the first turn, repair and compaction.`,
    ]),
    'Finish the first model turn immediately with plain text, no tool calls and no edits, so the kernel runs the required original check against the unchanged baseline.',
    'After that check fails, use the provided files, its failure locations and focused inspection to implement the requested changes as one coherent patch. Group independent tool calls.',
    'End the turn after the candidate edits to submit them to the configured original check. Keep model calls for check-driven repair. Use its actual diagnostics for any further repair.',
  ].join(' ');
}

export async function runInstalledPr532Journey(input: {
  workspace: string; sessionId: string; alias: string; budgets: RunSpec['budgets'];
  originalBytes: Buffer; testBytes: Buffer; lockBytes: Buffer; modelRequestCostMicros?: number;
}, context: {
  command(args: readonly string[]): Promise<{ stdout: Buffer }>;
  send(req: InstalledControlRequestV1, timeoutMs: number): Promise<unknown>;
  artifact(ref: string): Promise<Buffer>;
  retained(ref: string): Promise<Buffer>;
  reconnect(): Promise<void>;
  authorizeGitSource(): Promise<{ sourceInspectionGrantId: string; ignoreReadGrantIds: string[] }>;
  verifyHost(expected: Buffer): Promise<void>;
  progress(cut: Result<'run.get'>): void;
  dependencyFailure(value: Record<string, unknown>): void;
  verifierObservation(value: Record<string, unknown>): void;
  runtimeFailure(value: Record<string, unknown>): void;
  toolActivity(value: Record<string, unknown>): void;
  controlRefusal(value: Record<string, unknown>): void;
  mark(phase: string): void;
}) {
  const read = async <M extends InstalledControlFeature>(request: InstalledControlRequestV1, method: M) => {
    const response = decodeInstalledControlResponse(await context.send(request, 30_000), request);
    if (!response.ok) try {
      context.controlRefusal({ diagnosticOnly: true, method, code: response.error.code, retryable: response.error.retryable });
    } catch { /* Diagnosis cannot replace the original refusal. */ }
    assert(response.ok && response.result.method === method);
    return response.result as Result<M>;
  };
  const artifact = async (ref: string) => {
    const bytes = await context.artifact(ref); assert.equal(sha256Bytes(bytes), ref); return bytes;
  };
  const object = async (ref: string) => {
    const bytes = await artifact(ref), data = parseJsonStrict(bytes.toString('utf8'));
    assert.deepEqual(canonicalJsonBytes(data), bytes); return data;
  };
  const retained = async (ref: string) => {
    const bytes = await context.retained(ref); assert.equal(sha256Bytes(bytes), ref);
    const data = parseJsonStrict(bytes.toString('utf8')); assert.deepEqual(canonicalJsonBytes(data), bytes);
    return data;
  };
  const describeDependencyFailure = async (cut: Result<'run.get'>) => {
    const entry = cut.journal.findLast(row => row.opKind === 'tool' && row.target === 'builtin:dependency-acquire' && row.phase === 'failed');
    if (!entry?.evidenceRef) return;
    const source = cut.items.at(-1);
    if (!source) return;
    const failure = decodeDependencyFailureItem(await retained(source.payloadRef));
    if (failure.runId !== entry.runId || failure.opId !== entry.opId || failure.attempt !== entry.attempt || failure.receiptRef !== entry.errorRef) return;
    const elapsedMs = Date.parse(failure.createdAt) - Date.parse(cut.snapshot.run.createdAt);
    const evidence = await retained(entry.evidenceRef);
    if (failure.failureKind === 'acquisition_failed') {
      const { closure, evidenceDigest, runId, opId, attempt } = decodeDependencyAcquisitionClosure(evidence);
      assert.equal(runId, entry.runId); assert.equal(opId, entry.opId); assert.equal(attempt, entry.attempt);
      assert.equal(evidenceDigest, entry.evidenceDigest);
      const { connectionCount, requestCount, transferredBytes } = closure;
      context.dependencyFailure({ kind: failure.failureKind, elapsedMs, connectionCount, requestCount, transferredBytes });
    } else {
      const capture = decodeDependencyProcessCapture(evidence);
      assert.equal(capture.runId, entry.runId); assert.equal(capture.opId, entry.opId); assert.equal(capture.attempt, entry.attempt);
      assert.equal(capture.captureDigest, entry.evidenceDigest);
      const stderr = capture.stderrByteCount > 0 && capture.stderrByteCount <= 65_536
        ? await context.retained(capture.stderrRef) : undefined;
      const npmCode = stderr?.toString('utf8').match(/\bnpm (?:ERR!|error) code (EACCES|ENOSPC|ENOENT|ECONNRESET|EINTEGRITY|ENOTCACHED|EEXIST|EPERM)\b/u)?.[1];
      context.dependencyFailure({ kind: failure.failureKind, elapsedMs, termination: capture.terminationReason,
        durationMs: capture.durationMs, ...(capture.terminationReason === 'exit' ? { exitCode: capture.exitCode } : {}),
        ...(capture.terminationReason === 'spawn_error' ? { nativeErrorCode: capture.nativeErrorCode } : {}), ...(npmCode ? { npmCode } : {}) });
    }
  };
  const admitted = async <M extends 'run.submit' | 'run.apply'>(args: readonly string[], method: M) => {
    const { stdout } = await context.command(args);
    const matches = stdout.toString('utf8').trimEnd().split('\n').map(line => decodeHeadlessControlRecord(parseJsonStrict(line)))
      .filter(record => record.type === 'response' && record.response.ok && record.response.result.method === method);
    assert.equal(matches.length, 1);
    const response = matches[0]!;
    assert(response.type === 'response' && response.response.ok);
    return response.response.result as Result<M>;
  };
  const describeToolActivity = async (cut: Result<'run.get'>, completeCut = false) => {
    const results = [];
    let remaining = completeCut ? 1_048_576 : 0;
    for (const row of cut.items) {
      const item = await retained(row.payloadRef) as ContinuationItem;
      assert.equal(item.runId, cut.snapshot.run.id); assert.equal(item.itemId, row.itemId);
      if (item.kind !== 'tool_result') continue;
      const payload = await retained(item.resultRef) as ToolResultPayloadV1;
      const model = payload.toolName === 'bash' && payload.outcome === 'executed'
        ? await retained(payload.modelContentRef) as ToolResultModelContentV1 : undefined;
      const diagnostic = pr532ToolDiagnostic(item, payload, model, completeCut ? remaining : undefined);
      if ('failureOutput' in diagnostic && diagnostic.failureOutput?.kind === 'observed') remaining -= diagnostic.failureOutput.byteCount;
      results.push({ itemSeq: row.itemSeq, ...diagnostic });
    }
    if (results.length) context.toolActivity({ diagnosticOnly: true,
      afterItemSeq: cut.items[0]!.itemSeq - 1, throughItemSeq: cut.nextItemSeq,
      highWaterItemSeq: cut.highWaterItemSeq, completeStableCut: completeCut,
      completeTerminalCut: completeCut && ['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(cut.snapshot.run.status), results });
  };
  const finish = async (runId: string) => {
    const deadline = Date.now() + input.budgets.wallTimeMs;
    let journalHighWater = 0, itemCursor = 0;
    for (;;) {
      const cut = await read({ protocolVersion: 1, method: 'run.get', runId, afterItemSeq: itemCursor, itemLimit: 8,
        afterJournalSeq: Math.max(0, journalHighWater - 6), journalLimit: 8, checkpointLimit: 1 }, 'run.get');
      journalHighWater = cut.highWaterJournalSeq;
      itemCursor = cut.nextItemSeq;
      context.progress(cut);
      try { await describeToolActivity(cut); }
      catch { /* Keep the last observed tool batch if later diagnosis is unavailable. */ }
      const run = cut.snapshot.run;
      if (PR532_CPU_DIAGNOSTIC && (run.status === 'succeeded' || run.budgetConsumed.toolCalls >= 8 ||
          Date.now() - Date.parse(run.createdAt) >= 15 * 60_000)) {
        context.mark('pr532_cpu_diagnostic_stop');
        throw new Error('CPU diagnostic intentionally stops before complete qualification');
      }
      if (run.status === 'succeeded') {
        assert(Date.now() < deadline, 'installed Run reached the preview observation deadline');
        return readInstalledTerminalCut(runId, request => read(request, 'run.get'));
      }
      const dependencyFailed = cut.journal.some(row => row.target === 'builtin:dependency-acquire' && row.phase === 'failed');
      if (dependencyFailed || (run.status !== 'queued' && run.status !== 'running') || Date.now() >= deadline) {
        let stopped = await read({ protocolVersion: 1, method: 'run.get', runId,
          afterItemSeq: Math.max(0, cut.highWaterItemSeq - 8), itemLimit: 8, checkpointLimit: 1,
          afterJournalSeq: Math.max(0, cut.highWaterJournalSeq - 8), journalLimit: 8 }, 'run.get');
        let completeCut = false;
        try {
          stopped = await readInstalledStableCut(runId, request => read(request, 'run.get'));
          completeCut = true;
        } catch { /* Keep the original failure and last bounded page if the complete cut is unavailable. */ }
        context.progress(stopped);
        try {
          const original = stopped.snapshot.run;
          if (original.stopIntentRef) context.runtimeFailure(pr532StopDiagnostic(original, await retained(original.stopIntentRef)));
        } catch { /* Optional diagnosis preserves the original task failure. */ }
        try { await describeDependencyFailure(stopped); }
        catch { /* Unavailable optional diagnostics do not replace the original failed workflow. */ }
        try { await describeToolActivity(stopped, completeCut); }
        catch { /* Missing result diagnosis preserves the original task failure. */ }
        try {
          const entry = stopped.journal.findLast(row => row.opKind === 'verifier' && row.phase === 'completed' && row.receiptRef);
          if (entry?.receiptRef) {
            const receipt = decodeVerificationReceipt(await retained(entry.receiptRef));
            assert.equal(receipt.runId, entry.runId); assert.equal(receipt.attempt, entry.attempt);
            const command = decodeVerifierCommand(await retained(receipt.commandRef));
            assert.deepEqual(command.argv.map(arg => arg.value), nodeTestArguments(PR532_CHECK));
            context.verifierObservation({ journalSeq: entry.seq, outcome: receipt.outcome, terminationReason: receipt.terminationReason,
              ...(receipt.exitCode === undefined ? {} : { exitCode: receipt.exitCode }), durationMs: receipt.durationMs });
          }
        } catch { /* Missing diagnostic data keeps the original failure. */ }
      }
      assert(!dependencyFailed, 'installed Run owns a failed dependency acquisition or npm process');
      assert(run.status === 'queued' || run.status === 'running', `installed Run stopped at ${run.status}/${run.nextStep}`);
      assert(Date.now() < deadline, 'installed Run reached the preview observation deadline');
      // A ninety-minute Run uses at most 720 timed polls within the original
      // 1024-frame lifetime. Delivery uses a genuinely reauthenticated client.
      await delay(Math.min(PR532_POLL_INTERVAL_MS, Math.max(0, deadline - Date.now())));
    }
  };

  context.mark('pr532_submit');
  const sourceConsent = await context.authorizeGitSource();
  const objective = pr532TaskObjective(input);
  const { modelTokens, costMicros, ...budgets } = input.budgets;
  const run = await admitted(['run', objective, '--workspace', input.workspace, '--model', input.alias, '--policy', 'yolo',
    '--session', input.sessionId, '--trust-workspace', '--check-node', PR532_CHECK, '--budget-tokens', String(modelTokens),
    '--budget-usd', (costMicros / 1_000_000).toFixed(6), '--detach', '--json', '--options', JSON.stringify({
      ...sourceConsent, budgets, maxChangedPaths: 1, maxChangedBytes: 65_536,
      dependency: { mode: 'locked', registryEndpointIds: [PR532_REGISTRY_ID], credentialGrantIds: [], allowInstallScripts: false },
    })], 'run.submit');
  const runId = run.snapshot.run.id;
  assert.equal(Date.parse(run.snapshot.run.deadlineAt) - Date.parse(run.snapshot.run.createdAt), input.budgets.wallTimeMs);
  context.mark('pr532_reconnect');
  await context.reconnect(); // Detached CLI child and its original pipes have already joined.
  context.mark('pr532_check_and_repair');
  const cut = await finish(runId);
  assert(cut.snapshot.run.repairCount > 0);
  assert.equal(cut.nextJournalSeq, cut.highWaterJournalSeq);
  assert.equal(cut.journal.filter(row => row.target === 'builtin:dependency-acquire' && row.phase === 'dispatch_claimed').length, 1);
  const receiptRows = cut.journal.filter(row => row.opKind === 'verifier' && row.phase === 'completed' && row.receiptRef !== undefined);
  assert(receiptRows.length >= 2 && receiptRows[0]!.seq < receiptRows.at(-1)!.seq);
  const first = decodeVerificationReceipt(await object(receiptRows[0]!.receiptRef!));
  const last = decodeVerificationReceipt(await object(receiptRows.at(-1)!.receiptRef!));
  const command = decodeVerifierCommand(await object(first.commandRef));
  assert.deepEqual(command.argv.map(arg => arg.value), nodeTestArguments(PR532_CHECK));
  assert.equal(first.outcome, 'assertion_failed'); assert.equal(first.exitCode, 1);
  assert.equal(last.outcome, 'passed'); assert.equal(last.exitCode, 0);
  const diagnostic = verifierReportedLocations(command, await artifact(first.stdoutRef));
  assert(diagnostic?.reportedLines.length && !first.stdoutTruncated, 'original test reported no usable failure location');
  const repairClaim = cut.journal.find(row => row.opKind === 'model' && row.phase === 'prepared' && row.seq > receiptRows[0]!.seq);
  assert(repairClaim && cut.journal.some(row => row.opId === repairClaim.opId && row.attempt === repairClaim.attempt && row.phase === 'completed'));
  const repairRequest = await retained(repairClaim.requestRef) as { promptProjectionRef: string };
  const repairPrompt = await retained(repairRequest.promptProjectionRef) as { messages: Array<{ sourceKind: string; contentUtf8: string }> };
  const locations = canonicalJsonBytes({ path: diagnostic.path, lines: diagnostic.reportedLines }).toString('utf8');
  assert(repairPrompt.messages.some(message => message.sourceKind === 'verifier_repair' && message.contentUtf8.includes(locations)));

  context.mark('pr532_review');
  await context.verifyHost(input.originalBytes);
  const answer = await read({ protocolVersion: 1, method: 'run.result', runId }, 'run.result');
  assert.equal(answer.result.ref, cut.snapshot.run.resultRef);
  const result = decodeRunResult(await object(answer.result.ref));
  assert.equal(result.runId, runId);
  assert.equal(decodeSourceManifest(await object(first.resultSourceRef)).treeDigest,
    decodeSourceManifest(await object(result.baseSourceRef)).treeDigest);
  assert.equal(last.resultSourceRef, result.resultSourceRef);
  assert(result.verificationReceiptRefs.includes(receiptRows.at(-1)!.receiptRef!));
  const closure = decodeVerificationClosure(await object(result.verificationClosureRef));
  assert(closure.verification.kind === 'local' && closure.verification.outcome === 'verified');
  assert(closure.dependency.kind === 'ready' && closure.dependency.origin === 'reused_acquired');
  const diff = decodeWorkspaceDiff(await object(result.diffRef));
  assert.equal(diff.operations.length, 1);
  const change = diff.operations[0]!;
  assert(change.kind === 'modify' && change.path === PR532_FILE && change.before.kind === 'file' && change.after.kind === 'file');
  assert.equal(change.before.blobRef, sha256Bytes(input.originalBytes));
  const fixed = await artifact(change.after.blobRef);
  const reviewed = await context.command(['result', runId, '--wait']);
  assert(reviewed.stdout.includes(answer.result.ref) && reviewed.stdout.includes(PR532_FILE));

  context.mark('pr532_apply');
  const deliveryConsent = await context.authorizeGitSource();
  const applied = await admitted(['apply', runId, '--result', answer.result.ref, '--detach', '--json', '--options',
    JSON.stringify({ ...deliveryConsent, budgets: { wallTimeMs: input.budgets.wallTimeMs, toolCalls: input.budgets.toolCalls } })], 'run.apply');
  const deliveryId = applied.snapshot.run.id;
  assert.equal(Date.parse(applied.snapshot.run.deadlineAt) - Date.parse(applied.snapshot.run.createdAt), input.budgets.wallTimeMs);
  await context.reconnect();
  const delivery = await finish(deliveryId);
  assert.equal(delivery.snapshot.run.terminalReason, 'verified');
  const delivered = decodeRunResult(await object(delivery.snapshot.run.resultRef!));
  assert.equal(delivered.resultSourceRef, result.resultSourceRef);
  await context.verifyHost(fixed);
  return { runId, deliveryId, resultRef: answer.result.ref, originalExitCode: first.exitCode,
    repairedExitCode: last.exitCode, failureLines: diagnostic.reportedLines, modelCostMicros: cut.snapshot.run.budgetConsumed.costMicros,
    toolCalls: cut.snapshot.run.budgetConsumed.toolCalls,
    testDigest: sha256Bytes(input.testBytes), lockDigest: sha256Bytes(input.lockBytes), appliedFileDigest: change.after.blobRef,
    appliedFileUtf8: new TextDecoder('utf-8', { fatal: true }).decode(fixed), reviewOutputUtf8: reviewed.stdout.toString('utf8') };
}
