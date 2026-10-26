import { canonicalJsonBytes } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting } from '../kernel/identity.js';
import type { AdmittedContextManifest, ContextManifest, ContinuationItem, Run, RunAssemblyV1, RunSpec } from '../kernel/types.js';
import type { DelegateRequest } from '../kernel/children.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { projectModelVisiblePrompt } from '../model/request.js';
import { verifyModelText } from '../model/attempt.js';
import { readCanonicalArtifact, readChildParentModelContext, loadInstructionText, readText } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeAdmittedContext } from './decoders.js';
import { frozenSessionCompactionIndex } from './session-context.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { KernelStorageError } from './errors.js';

/** Immutable model-visible capture, never a caller-selected CAS or authority
 * traversal. The child admission owns the exact parent CP and SQL revision. */
export async function planChildAdmittedContext(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  parent: Run; parentSpec: RunSpec; assembly: RunAssemblyV1; context: ContextManifest; request: DelegateRequest;
}) {
  const { parent, parentSpec, assembly, context, request } = input;
  const admitted = decodeAdmittedContext(await readCanonicalArtifact(artifacts, parentSpec.admittedContextRef));
  const readableText = new Set([...admitted.parentContextRefs, ...admitted.additionalArtifactRefs]);
  for (const segment of context.segments) {
    if (segment.kind === 'summary') readableText.add(segment.summaryRef);
    if (segment.kind === 'raw') for (const source of segment.items) {
      const item = await readCanonicalArtifact<ContinuationItem>(artifacts, source.itemRef);
      if (item.runId !== parent.id) throw new TypeError('child context includes an item owned by another Run');
      if (item.kind === 'model_turn') readableText.add(item.textRef);
    }
  }
  for (const ref of request.context.additionalArtifactRefs) {
    if (!readableText.has(ref)) throw new KernelStorageError('INVALID_REQUEST', 'child additional context is not in the parent model-visible text closure');
    await readText(artifacts, ref);
  }
  const textPlans = [];
  let parentTextRef: string;
  if (request.context.source === 'parent_summary') {
    const summary = context.segments.filter(segment => segment.kind === 'summary').at(-1);
    if (!summary || summary.kind !== 'summary') throw new KernelStorageError('INVALID_REQUEST', 'parent_summary requires a real retained parent compaction summary');
    await readText(artifacts, summary.summaryRef, summary.summaryDigest);
    parentTextRef = summary.summaryRef;
  } else {
    const visible = await readChildParentModelContext({ artifacts, run: parent, spec: parentSpec, assembly, context,
      systemInstruction: await loadInstructionText(artifacts, assembly), tools: [],
      sessionCompactionIndex: projection => frozenSessionCompactionIndex(driver, projection.sessionId, projection.throughItemSeq) });
    // The existing projector discards all audit/source ids and manifests. The
    // original pending tool arguments remain data; no artificial tool result
    // or closed-batch history is synthesized to make this snapshot possible.
    const utf8 = canonicalJsonBytes({ messages: projectModelVisiblePrompt(visible, assembly.provider.negotiation.mode).messages }).toString('utf8');
    const text: ModelTextV1 = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8, byteCount: Buffer.byteLength(utf8), textDigest: '' };
    text.textDigest = digestOmitting(text, 'textDigest'); verifyModelText(text);
    // This is bounded child input, not permission to truncate a parent prompt
    // or request an implicit paid summary when the snapshot does not fit.
    if (text.byteCount > 1_048_576) throw new KernelStorageError('INVALID_REQUEST', 'parent context exceeds the original child input byte limit');
    const plan = planCanonicalArtifact(text, text.format); textPlans.push(plan); parentTextRef = plan.ref;
  }
  const child: AdmittedContextManifest = { ...admitted, parentContextRefs: [parentTextRef],
    additionalArtifactRefs: [...request.context.additionalArtifactRefs], contextDigest: '' };
  child.contextDigest = digestOmitting(child, 'contextDigest');
  return Object.freeze({ value: child, plan: planCanonicalArtifact(child, child.format), textPlans: Object.freeze(textPlans) });
}
