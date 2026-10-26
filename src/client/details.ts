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
    const data = await json(result.diff.ref, result.diff.sizeBytes); decodeWorkspaceDiff(data.value);
    await present({ label: 'Workspace diff', artifactRef: result.diff.ref, text: data.text });
  } else if (result.method === 'run.result') {
    if (request.method !== result.method || request.runId !== result.runId) throw new TypeError('result differs from its original request');
    const raw = await json(result.result.ref, result.result.sizeBytes), value = decodeRunResult(raw.value);
    if (value.runId !== result.runId || value.verificationClosureRef !== result.verificationClosureRef)
      throw new TypeError('result detail substitutes its original selection');
    await present({ label: 'Immutable Run result', artifactRef: result.result.ref, text: raw.text });
    const closureData = await json(value.verificationClosureRef), closure = decodeVerificationClosure(closureData.value);
    if (closure.runId !== value.runId || closure.resultSourceRef !== value.resultSourceRef)
      throw new TypeError('result closure differs from its original result');
    await present({ label: 'Verification provenance', artifactRef: value.verificationClosureRef, text: closureData.text });
    if (value.verificationProvenanceRef !== undefined) {
      const data = await json(value.verificationProvenanceRef), provenance = decodeInheritedVerificationProvenance(data.value);
      if (closure.verification.kind !== 'inherited_verified' || closure.verification.inheritedProvenanceRef !== value.verificationProvenanceRef ||
          provenance.deliveryRunId !== value.runId || provenance.resultSourceRef !== value.resultSourceRef)
        throw new TypeError('inherited provenance differs from its result');
      await present({ label: 'Inherited provenance', artifactRef: value.verificationProvenanceRef, text: data.text });
    }
    const summary = (await json(value.summaryRef)).value as ModelTextV1; verifyModelText(summary);
    await present({ label: 'Summary', artifactRef: value.summaryRef, text: summary.utf8 });
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
