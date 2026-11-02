// One pure risk projection for text CLI, TUI and embedding consumers. This
// describes the original immutable wait; it grants no settlement authority.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeWireRun } from '../kernel/control-wire-data.js';
import { decodeManualInvocationWait } from '../kernel/mcp.js';
import type { RunSnapshotV1 } from '../kernel/types.js';

export function manualInvocationPresentation(snapshot: RunSnapshotV1, value: unknown) {
  const run = decodeWireRun(snapshot.run), wait = decodeManualInvocationWait(value);
  if (snapshot.operation !== 'agent' || run.status !== 'waiting' || run.waitingReason !== 'reconciliation' ||
      canonicalSha256(wait) !== run.waitingOnRef || wait.runId !== run.id || wait.frontierRef !== run.frontierRef ||
      wait.createdFromRevision >= run.revision || wait.createdAt < run.createdAt || wait.createdAt > run.updatedAt)
    throw new TypeError('manual reconciliation differs from its exact captured Run and wait');
  return Object.freeze({ waitingOnRef: run.waitingOnRef!, reconciliation: 'manual' as const, text:
    `Unknown ${wait.subject.opKind} operation ${JSON.stringify(wait.subject.opId)} · attempt ${wait.subject.attempt}\n` +
    'The external effect may have occurred. Its result will not be used. Acknowledgement stops this Run and retains its original charge.\n' +
    `Acknowledge this exact risk with: reconcile ${JSON.stringify(run.id)} --revision ${run.revision} --wait ${run.waitingOnRef} --resolution abandon_run --acknowledge-exact-risk` });
}
