import { canonicalJsonBytes } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { controlWireRecord } from '../kernel/control-wire-data.js';
import type { InstalledControlRequestV1, InstalledControlResponseFor, InstalledControlFeature } from '../control/v1.js';
// These original closed result decoders are pure data functions. They load no
// Store, SQL connection, native handle, permission or recovery service.
import { decodeRunResult, decodeWorkspaceDiff, decodeVerificationClosure, decodeInheritedVerificationProvenance } from '../state/result-artifacts.js';
import { verifyModelText } from '../model/attempt.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import type { ClientApplication } from './actions.js';
import { renderWorkspaceReview } from './review.js';
export type ClientDetail = Readonly<{ label: string; artifactRef: string; text: string }>;
const utf8 = (bytes: Uint8Array) => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);

/** Fully verified source bytes; rendering is disposable and grants no right
 * to execute/apply. Larger artifacts fail explicitly, never truncate. */
export async function presentControlArtifacts(app: Pick<ClientApplication, 'artifact'>,
  request: InstalledControlRequestV1, response: InstalledControlResponseFor<InstalledControlFeature>,
  present: (detail: ClientDetail) => void | Promise<void>, signal?: AbortSignal): Promise<void> {
  if (!response.ok) return;
  const result = response.result;
  async function read(ref: string, size?: number) {
    const bytes = await app.artifact(ref, { maxBytes: 64 * 1024 * 1024, signal }); signal?.throwIfAborted();
    if (size !== undefined && bytes.length !== size) throw new TypeError('artifact differs from its captured descriptor');
    return bytes;
  }
  async function json(ref: string, size?: number) {
    const bytes = await read(ref, size), text = utf8(bytes), value = parseJsonStrict(text);
    if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('detail artifact is not canonical JSON');
    return { value, text };
  }
  if (result.method === 'run.diff') {
    if (request.method !== result.method || request.runId !== result.runId) throw new TypeError('diff differs from its original request');
    const data = await json(result.diff.ref, result.diff.sizeBytes), diff = decodeWorkspaceDiff(data.value);
    await present({ label: 'Workspace diff', artifactRef: result.diff.ref,
      text: await renderWorkspaceReview(diff, app.artifact.bind(app), signal) + `\nComplete diff artifact: ${result.diff.ref}\n` });
  } else if (result.method === 'run.result') {
    if (request.method !== result.method || request.runId !== result.runId) throw new TypeError('result differs from its original request');
    const raw = await json(result.result.ref, result.result.sizeBytes), value = decodeRunResult(raw.value);
    if (value.runId !== result.runId || value.verificationClosureRef !== result.verificationClosureRef)
      throw new TypeError('result detail substitutes its original selection');
    const closureData = await json(value.verificationClosureRef), closure = decodeVerificationClosure(closureData.value);
    if (closure.runId !== value.runId || closure.resultSourceRef !== value.resultSourceRef)
      throw new TypeError('result closure differs from its original result');
    if ((closure.verification.kind === 'inherited_verified') !== (value.verificationProvenanceRef !== undefined))
      throw new TypeError('result inherited verification is missing its original provenance');
    const lines = [`Run ${JSON.stringify(value.runId)}`, `Result: ${result.result.ref}`, `Source: ${value.resultSourceRef}`];
    if (value.verificationProvenanceRef !== undefined) {
      const data = await json(value.verificationProvenanceRef), provenance = decodeInheritedVerificationProvenance(data.value);
      if (closure.verification.kind !== 'inherited_verified' || closure.verification.inheritedProvenanceRef !== value.verificationProvenanceRef ||
          provenance.deliveryRunId !== value.runId || provenance.resultSourceRef !== value.resultSourceRef)
        throw new TypeError('inherited provenance differs from its result');
      lines.push(`Inherited verification from Run ${JSON.stringify(provenance.sourceRunId)}`, `Inherited provenance: ${value.verificationProvenanceRef}`);
    }
    const summary = (await json(value.summaryRef)).value as ModelTextV1; verifyModelText(summary);
    lines.push('', 'Summary', summary.utf8, '', 'Verification');
    if (closure.verification.kind === 'local') {
      lines.push(closure.verification.outcome === 'verified' ? 'Required checks passed for this exact result.' : 'UNVERIFIED: no required checks were configured.');
      for (const entry of closure.verification.entries) {
        const disposition = entry.disposition;
        lines.push(`${JSON.stringify(entry.verifierId)} (${entry.required ? 'required' : 'advisory'}): ` +
          (disposition.kind === 'passed' ? 'passed' : disposition.kind === 'advisory_skipped' ? 'skipped' : disposition.outcome) +
          ('receiptRef' in disposition ? ` · receipt ${disposition.receiptRef}` : ''));
      }
    } else lines.push(`Inherited required checks from Run ${JSON.stringify(closure.verification.sourceRunId)} for the unchanged result source.`);
    lines.push(`Verification evidence: ${value.verificationClosureRef}`);
    const diffData = await json(value.diffRef), diff = decodeWorkspaceDiff(diffData.value);
    if (diff.baseSourceRef !== value.baseSourceRef || diff.resultSourceRef !== value.resultSourceRef)
      throw new TypeError('review diff differs from its original result sources');
    lines.push('', 'Changes', await renderWorkspaceReview(diff, app.artifact.bind(app), signal),
      `Complete diff artifact: ${value.diffRef}`, `Summary artifact: ${value.summaryRef}`, '',
      `Apply this exact result with the same signed client, using these arguments:\napply ${JSON.stringify(value.runId)} --result ${result.result.ref}`);
    await present({ label: 'Result review', artifactRef: result.result.ref, text: lines.join('\n') });
  } else if (result.method === 'session.handoff.create') {
    if (request.method !== result.method) throw new TypeError('handoff differs from its original request');
    const raw = await json(result.json.ref, result.json.sizeBytes);
    // The owning server validates the complete immutable lineage. The display
    // binds the exact captured identity/digest; it cannot import a handoff.
    const value = controlWireRecord(raw.value, ['schemaVersion', 'format', 'sessionId', 'workspaceIdentityRef', 'workspaceIdentityDigest',
      'contextRevision', 'throughItemSeq', 'contextProjectionRef', 'contextProjectionDigest', 'entries', 'excludedRanges', 'handoffDigest']);
    if (value.schemaVersion !== 1 || value.format !== 'cliq-session-handoff-v1' || value.sessionId !== request.sessionId ||
        value.contextRevision !== request.expectedContextRevision || request.throughItemSeq !== undefined && value.throughItemSeq !== request.throughItemSeq ||
        value.handoffDigest !== digestOmitting(value, 'handoffDigest')) throw new TypeError('handoff differs from its original cut');
    const markdown = await read(result.markdown.ref, result.markdown.sizeBytes);
    await present({ label: 'Session handoff', artifactRef: result.markdown.ref, text: utf8(markdown) });
  }
}

/** A viewport ceiling does not alter or qualify the verified source artifact. */
export function detailViewport(detail: ClientDetail): ClientDetail {
  if (detail.text.length <= 65536) return detail;
  let text = detail.text.slice(0, 65536);
  if (/[\uD800-\uDBFF]$/u.test(text)) text = text.slice(0, -1);
  return { ...detail, text: text + '\n… [view clipped; export the original artifact for all bytes]' };
}
export function artifactText(bytes: Buffer): string {
  try { return utf8(bytes); }
  catch { return 'Binary artifact. Export the original verified bytes with artifact <ref> redirected to a file.'; }
}
