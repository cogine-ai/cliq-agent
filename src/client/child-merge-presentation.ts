// Human-readable original approval data only. This reader cannot grant,
// claim, merge or decide whether the server will accept an approval.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, decodeWireRun } from '../kernel/control-wire-data.js';
import { CHILD_MERGE_BINDING_KEYS, decodeChildMergeApprovalWait, decodeChildMergePolicyEvidence,
  decodeChildMergeRequest, decodeChildMergeTarget } from '../kernel/child-merge.js';
import { sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { RunSnapshotV1 } from '../kernel/types.js';

type Reader = { artifact(ref: string, options: { maxBytes: number; signal?: AbortSignal }): Promise<Buffer> };
export async function readChildMergeWaitingPresentation(app: Reader, snapshot: RunSnapshotV1, value: unknown, signal?: AbortSignal) {
  signal?.throwIfAborted();
  assertControlWireJson(snapshot);
  const wait = decodeChildMergeApprovalWait(value), run = Object.freeze({ ...decodeWireRun(snapshot.run) });
  if (snapshot.operation !== 'agent' || run.status !== 'waiting' || run.waitingReason !== 'approval' || !run.waitingOnRef || canonicalSha256(wait) !== run.waitingOnRef ||
      wait.runId !== run.id || wait.frontierRef !== run.frontierRef || wait.createdFromRevision >= run.revision)
    throw new TypeError('child merge presentation differs from its captured approval wait');
  const json = async (ref: string) => {
    signal?.throwIfAborted(); const bytes = await app.artifact(ref, { maxBytes: 64 * 1024 * 1024, signal }); signal?.throwIfAborted();
    if (sha256Bytes(bytes) !== ref) throw new TypeError('child merge presentation lost its complete original bytes');
    const data = parseJsonStrict(new TextDecoder('utf8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (!canonicalJsonBytes(data).equals(bytes)) throw new TypeError('child merge presentation is not canonical JSON');
    return data;
  };
  const evidence = decodeChildMergePolicyEvidence(await json(wait.subject.policyChannelEvidenceRef));
  const request = decodeChildMergeRequest(await json(evidence.requestRef));
  const target = decodeChildMergeTarget(await json(wait.subject.target));
  if (evidence.runId !== run.id || evidence.opId !== wait.subject.opId || evidence.frontierRef !== wait.frontierRef ||
      evidence.evidenceDigest !== wait.subject.policyChannelEvidenceDigest || evidence.effectiveDisposition !== 'ask' ||
      request.opId !== wait.subject.opId || request.frontierRef !== wait.frontierRef || request.requestDigest !== evidence.requestDigest ||
      request.targetRef !== wait.subject.target || evidence.targetRef !== request.targetRef || request.targetDigest !== target.targetDigest || evidence.targetDigest !== target.targetDigest ||
      target.changedPathsDigest !== wait.subject.changedPathsDigest || canonicalSha256(evidence.canonicalRootRelativePaths) !== target.changedPathsDigest ||
      CHILD_MERGE_BINDING_KEYS.some(key => request[key] !== wait.subject[key] || target[key] !== wait.subject[key]))
    throw new TypeError('child merge presentation substitutes its original child, request, target or changed paths');
  const paths = evidence.canonicalRootRelativePaths;
  const text = `Merge completed child ${JSON.stringify(wait.subject.childRunId)}.\nScope: private parent workspace.\n` +
    `Changed paths (${paths.length}):\n` + (paths.length ? paths.map(path => `  ${JSON.stringify(path)}`).join('\n') : '  No changed file paths.');
  return Object.freeze({ waitingOnRef: run.waitingOnRef, text });
}
