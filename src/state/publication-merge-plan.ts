import { setImmediate as yieldToEventLoop } from 'node:timers/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import type { DeliveryPlan } from '../kernel/publication.js';
import type { WorkspaceStateManifest } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import type { DeliverySourcePlan } from './delivery-source.js';
import { KernelStorageError } from './errors.js';
import { planDeliveryPublication } from './publication-plan.js';

export type PreparedDeliveryMergePlan = Readonly<{
  source: Extract<DeliverySourcePlan, { kind: 'ready' }>; plan: DeliveryPlan; planRef: string;
  workspaceState: WorkspaceStateManifest; workspaceStateRef: string; metadata: PublishedArtifact[];
}>;

/** One already-computed deterministic source plan, one artifact-first CAS
 * preparation. A retry retains that original plan and does not re-run diff3.
 * CAS orphans after failure grant no authority: the owning same-cut SQL
 * transaction still creates the candidate, merge item and ready Checkpoint.
 * The owner separately bounds retained planned-blob memory and joins close. */
export async function prepareDeliveryMergePlan(artifacts: ArtifactCatalog, selected: Extract<DeliverySourcePlan, { kind: 'ready' }>,
  input: Readonly<{ deliveryRunId: string; sourceRunResultRef: string; captureTopologyRef: string; sandboxProfileRef?: string;
    privateGitStateRef?: string }>, signal?: AbortSignal): Promise<PreparedDeliveryMergePlan> {
  input = immutableSnapshot(input);
  signal?.throwIfAborted();
  // PlannedArtifact deliberately owns a byte-copy getter: recursively cloning
  // or freezing it would materialize and retain every blob on the heap. Freeze
  // the ordinary graph, retain that existing immutable byte-owner separately,
  // and verify each exact ref again at its sequential CAS publication.
  const { publications, ...graph } = selected;
  const source = { ...immutableSnapshot(graph), publications: [...publications] };
  Object.freeze(source.publications); Object.freeze(source);
  if (source.kind !== 'ready' || source.sourceRef !== canonicalSha256(source.source) || source.diffRef !== canonicalSha256(source.diff) ||
      source.summaryRef !== canonicalSha256(source.summary) || source.source.entriesRef !== canonicalSha256(source.entries) ||
      source.diff.baseSourceRef !== source.input.capturedWorkspaceRef || source.diff.resultSourceRef !== source.sourceRef)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'delivery merge preparation differs from its original immutable source plan');
  assertArtifactRef(input.sourceRunResultRef); assertArtifactRef(input.captureTopologyRef);
  const metadata = new Map(source.metadata.map(artifact => [artifact.ref, artifact]));
  for (const artifact of source.publications) {
    signal?.throwIfAborted();
    const bytes = artifact.bytes;
    async function* chunks() {
      for (let offset = 0; offset < bytes.byteLength; offset += 65536) {
        await yieldToEventLoop(); signal?.throwIfAborted(); yield bytes.subarray(offset, offset + 65536);
      }
    }
    const published = await artifacts.publishChunks(chunks(), artifact.mediaType, artifact.schemaKind, bytes.byteLength);
    signal?.throwIfAborted();
    if (published.ref !== artifact.ref || published.byteLength !== bytes.byteLength)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'delivery merge CAS publication substituted its planned bytes');
    metadata.set(published.ref, published);
  }
  if (!!source.source.git !== !!input.privateGitStateRef) throw new KernelStorageError('ARTIFACT_MISMATCH', 'delivery merge lost captured A private Git state');
  const planned = await planDeliveryPublication(artifacts, { deliveryRunId: input.deliveryRunId, sourceRunResultRef: input.sourceRunResultRef,
    captureTopologyRef: input.captureTopologyRef, ...source.input, desiredSourceRef: source.sourceRef, diffRef: source.diffRef }, signal, input.sandboxProfileRef);
  for (const artifact of planned.publications) {
    signal?.throwIfAborted(); const published = await artifacts.publishBytes(artifact.bytes, artifact.mediaType, artifact.schemaKind);
    signal?.throwIfAborted();
    if (published.ref !== artifact.ref) throw new KernelStorageError('ARTIFACT_MISMATCH', 'delivery publication Plan CAS bytes differ');
    metadata.set(published.ref, published);
  }
  const workspaceState: WorkspaceStateManifest = {
    schemaVersion: 1, format: 'cliq-workspace-state-v1', runId: input.deliveryRunId,
    baseWorkspaceManifestRef: source.input.capturedWorkspaceRef, entriesRef: source.source.entriesRef,
    invalidatedEphemeralPaths: [], sourceProjectionDigest: source.source.sourceProjectionDigest,
    ...(input.privateGitStateRef ? { privateGitStateRef: input.privateGitStateRef } : {}), stateDigest: ''
  };
  workspaceState.stateDigest = digestOmitting(workspaceState, 'stateDigest');
  signal?.throwIfAborted(); const workspace = await artifacts.publishCanonical(workspaceState, workspaceState.format); signal?.throwIfAborted();
  for (const artifact of planned.metadata) metadata.set(artifact.ref, artifact);
  metadata.set(workspace.ref, workspace);
  return { source, plan: planned.plan, planRef: planned.planRef, workspaceState: immutableSnapshot(workspaceState),
    workspaceStateRef: workspace.ref, metadata: [...metadata.values()] };
}
