// Exact immutable server-launch data for CLI/TUI consent. Display creates no
// permission, identity consumption, launch, native owner or effect authority.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { controlWireInteger, controlWireRecord, controlWireRef, decodeWireRun } from '../kernel/control-wire-data.js';
import { sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeMcpServerApprovalWait, decodeMcpServerLaunchRequest, decodeMcpServerLaunchTarget,
  decodeMcpServerPolicyChannelEvidence, mcpServerLaunchSubject } from '../kernel/mcp-server-authorization.js';
import { decodeMcpStdioExecutableIdentity } from '../kernel/mcp-stdio.js';
import type { RunSnapshotV1 } from '../kernel/types.js';

type Reader = { artifact(ref: string, options: { maxBytes: number; signal?: AbortSignal }): Promise<Buffer> };
export async function readMcpServerWaitingPresentation(app: Reader, snapshot: RunSnapshotV1, value: unknown, signal?: AbortSignal) {
  signal?.throwIfAborted();
  const run = decodeWireRun(snapshot.run), wait = decodeMcpServerApprovalWait(value);
  if (snapshot.operation !== 'agent' || run.status !== 'waiting' || run.waitingReason !== 'approval' || run.cancelRequested || run.stopIntentRef ||
      canonicalSha256(wait) !== run.waitingOnRef || wait.runId !== run.id || wait.frontierRef !== run.frontierRef ||
      wait.createdFromRevision >= run.revision || wait.createdAt < run.createdAt || wait.createdAt > run.updatedAt || wait.createdAt >= run.deadlineAt)
    throw new TypeError('MCP server launch approval differs from its captured Run and original wait');
  async function json(ref: string) {
    signal?.throwIfAborted(); controlWireRef(ref);
    const bytes = await app.artifact(ref, { maxBytes: 64 * 1024 * 1024, signal }); signal?.throwIfAborted();
    if (sha256Bytes(bytes) !== ref) throw new TypeError('MCP server presentation lost its complete original artifact bytes');
    const data = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (!canonicalJsonBytes(data).equals(bytes)) throw new TypeError('MCP server presentation artifact is not canonical JSON');
    return data;
  }
  const subject = wait.subject, evidence = decodeMcpServerPolicyChannelEvidence(await json(subject.policyChannelEvidenceRef));
  const request = decodeMcpServerLaunchRequest(await json(evidence.requestRef)), target = decodeMcpServerLaunchTarget(await json(subject.target));
  const executable = decodeMcpStdioExecutableIdentity(await json(target.executableIdentityRef));
  const frontier = controlWireRecord(await json(wait.frontierRef), ['schemaVersion', 'kind', 'batchItemId', 'orderedCallIds', 'nextCallIndex']);
  const spec = controlWireRecord(await json(run.specRef), ['schemaVersion', 'operation', 'objectiveRef', 'admittedContextRef', 'baseWorkspaceManifestRef',
    'sourceProjectionRef', 'assemblyRef', 'policyRef', 'sandboxProfileRef', 'verifierSpecRef', 'credentialGrantRefs', 'budgets'], ['dependencyPolicyRef', 'unverifiedConsentRef']);
  if (evidence.effectiveDisposition !== 'ask' || evidence.evidenceDigest !== subject.policyChannelEvidenceDigest || evidence.runId !== run.id ||
      evidence.frontierRef !== wait.frontierRef || evidence.opId !== subject.opId || evidence.evaluatedAt !== wait.createdAt ||
      evidence.policyRef !== spec.policyRef || evidence.targetRef !== subject.target || evidence.targetDigest !== target.targetDigest ||
      evidence.requestDigest !== request.requestDigest || canonicalSha256(evidence.namedAction) !== canonicalSha256(mcpServerLaunchSubject(target)) ||
      request.runId !== run.id || target.runId !== run.id || request.opId !== subject.opId || request.frontierRef !== wait.frontierRef ||
      request.assemblyRef !== spec.assemblyRef || request.targetRef !== subject.target || request.targetDigest !== target.targetDigest ||
      target.registryRevisionRef !== subject.registryRevisionRef || target.registryManifestDigest !== subject.registryManifestDigest ||
      target.lifecycleSeq !== subject.lifecycleSeq || target.batchItemId !== subject.originatingBatchItemId || target.callId !== subject.originatingCallId ||
      target.callIndex !== subject.originatingCallIndex || target.toolRequestRef !== request.toolRequestRef || target.toolRequestDigest !== request.toolRequestDigest ||
      request.registryRevisionRef !== target.registryRevisionRef || request.registryManifestDigest !== target.registryManifestDigest ||
      request.lifecycleSeq !== target.lifecycleSeq || request.batchItemId !== target.batchItemId || request.callId !== target.callId || request.callIndex !== target.callIndex ||
      target.executableIdentityDigest !== canonicalSha256(executable) || spec.schemaVersion !== 1 || spec.operation !== 'agent' ||
      frontier.schemaVersion !== 1 || frontier.kind !== 'tool' || frontier.batchItemId !== target.batchItemId ||
      !Array.isArray(frontier.orderedCallIds) || frontier.orderedCallIds[target.callIndex] !== target.callId ||
      controlWireInteger(frontier.nextCallIndex, 0) !== target.callIndex)
    throw new TypeError('MCP server launch approval substitutes its original call, executable, policy or ordered frontier');
  signal?.throwIfAborted();
  return Object.freeze({ waitingOnRef: run.waitingOnRef!, text:
    `Launch MCP server ${JSON.stringify(target.registrationId)} for this exact call?\n` +
    `Executable: ${JSON.stringify(executable.executableId)}\nSHA-256: ${executable.executableDigest}\n` +
    `Signed bundle: ${executable.runtimeBundleRef}\nArguments: ${target.argv.map(arg => JSON.stringify(arg)).join(' ')}\n` +
    `Original call: ${JSON.stringify(target.callId)} · batch ${JSON.stringify(target.batchItemId)} · index ${target.callIndex}\n` +
    `Scope: isolated empty root, no network; at most ${target.maxLaunches} original launch claim${target.maxLaunches === 1 ? '' : 's'} for this call.\n` +
    `Each claimed server launch uses one tool call. The tool effect has its own permission and charge.\n` +
    'Deny skips this call without launching the server or executing its tool effect.' });
}
