import { encodeSessionHandoffJson, encodeSessionHandoffMarkdown } from '../kernel/session-handoff-encoding.js';
import { decodeSessionContinuityRequest } from '../kernel/session-continuity.js';
import { decodeWireArtifactDescriptor } from '../kernel/control-wire-data.js';
import type { ArtifactDescriptorV1 } from '../kernel/types.js';
import { walkSessionContextSegments } from '../kernel/session-context-page-reader.js';
import { immutableSnapshot } from '../model/immutable.js';
import { validateControlChannelClosure, assertCurrentControlFrame, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeRetainedWorkspaceIdentity } from './decoders.js';
import { advanceTimeFence, readTimeFence } from './canonical-time.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { KernelStorageError } from './errors.js';
import { assertCurrentSessionContextGraph, readBoundedSessionContextJson, readCurrentSessionContextGraph,
  readSessionContextEntryStream } from './session-context-stream.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { coalesceSessionHandoffPublication } from './session-handoff-publication.js';

function corrupt(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
/** Same original full JSON/Markdown export, streamed rather than assembled as
 * a giant v1 projection/entries array/string. Export bodies are user data, not
 * new Kernel authority pages. The existing CAS source/EOF/fsync/real-join path
 * still publishes them; bounded chunks do not claim bounded fsync wall time. */
export async function createStreamedSessionHandoff(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: unknown, identity: AuthenticatedControlIdentity, signal?: AbortSignal) {
  const request = decodeSessionContinuityRequest(input);
  if (request.method !== 'session.handoff.create') throw new TypeError('Session handoff method is invalid');
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const channel = await validateControlChannelClosure(reads, owner, identity);
  const current = () => { signal?.throwIfAborted(); reads.assertReadActive();
    if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, identity); };
  current(); assertActiveStateOwner(driver, owner);
  const context = await readCurrentSessionContextGraph(driver, reads, identity.principalId, request.sessionId,
    request.expectedContextRevision, { signal });
  const through = request.throughItemSeq ?? context.projection.throughItemSeq;
  let boundary = through === 0;
  for await (const segment of walkSessionContextSegments(reads, context.projection, { signal }))
    if (segment.throughItemSeq === through) boundary = true;
  if (!boundary) throw new KernelStorageError('INVALID_REQUEST', 'Session handoff cursor must end a complete current segment');
  const workspace = decodeRetainedWorkspaceIdentity(await readBoundedSessionContextJson(reads, context.cut.session.workspaceIdentityRef));
  if (workspace.ownerPrincipalId !== identity.principalId) return corrupt('Session handoff workspace belongs to another principal');
  const source = { driver, cut: context.cut };
  const header = { contextProjectionDigest: context.projection.projectionDigest, contextProjectionRef: context.cut.session.contextProjectionRef,
    contextRevision: context.projection.contextRevision, sessionId: context.cut.session.id, throughItemSeq: through,
    workspaceIdentityDigest: workspace.identityDigest, workspaceIdentityRef: context.cut.session.workspaceIdentityRef };
  async function* visibleEntries() {
    let index = 0;
    for await (const entry of readSessionContextEntryStream(reads, context.projection, { source, signal })) {
      if (entry.throughItemSeq > through) continue;
      const { sourceItemId: _id, ...data } = entry;
      yield { ...data, index: index++ };
    }
  }
  async function* ranges() {
    for await (const segment of walkSessionContextSegments(reads, context.projection, { signal }))
      if (segment.kind === 'excluded_control' && segment.throughItemSeq <= through)
        yield { fromItemSeq: segment.fromItemSeq, throughItemSeq: segment.throughItemSeq, sourceItemsDigest: segment.sourceItemsDigest };
  }
  const finalCheck = () => { current(); driver.readSnapshot(connection => { assertActiveStateOwner(connection, owner);
    assertCurrentSessionContextGraph(connection, context.cut); }); };
  async function* json(): AsyncIterableIterator<Buffer> {
    for await (const bytes of encodeSessionHandoffJson(header, visibleEntries(), ranges(), signal)) { current(); yield bytes; }
    // Source EOF is observed only after this exact owner/head/index recheck.
    // A failed check still fails/joins the real CAS publication, never returns
    // a descriptor for a partial or concurrently retargeted source.
    finalCheck();
  }
  const jsonArtifact = await reads.publishChunks(coalesceSessionHandoffPublication(json(), signal), 'application/json', 'cliq-session-handoff-v1', Number.MAX_SAFE_INTEGER);
  current();
  async function* markdown(): AsyncIterableIterator<Buffer> {
    for await (const bytes of encodeSessionHandoffMarkdown(header, visibleEntries(), ranges(), signal)) { current(); yield bytes; }
    finalCheck();
  }
  const rendered = await reads.publishChunks(coalesceSessionHandoffPublication(markdown(), signal), 'text/markdown; charset=utf-8', 'cliq-session-handoff-markdown-v1', Number.MAX_SAFE_INTEGER);
  current(); let regressed = false, descriptors: { json: ArtifactDescriptorV1; markdown: ArtifactDescriptorV1 } | undefined;
  driver.transaction(connection => {
    current(); assertActiveStateOwner(connection, owner);
    if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { regressed = true; return; }
    assertCurrentSessionContextGraph(connection, context.cut);
    for (const artifact of [...channel.metadata, jsonArtifact, rendered]) insertArtifactMetadata(connection, artifact, readTimeFence(connection)!.lastAcceptedAt);
    const descriptor = (artifact: PublishedArtifact): ArtifactDescriptorV1 => {
      const stored = connection.prepare('SELECT byte_length,media_type FROM artifacts WHERE ref=?').get<{ byte_length: bigint; media_type: string }>(artifact.ref);
      if (!stored || stored.byte_length !== BigInt(artifact.byteLength)) return corrupt('Session handoff catalog length differs from complete publication');
      return decodeWireArtifactDescriptor({ schemaVersion: 1, ref: artifact.ref, digest: artifact.ref, sizeBytes: artifact.byteLength, mediaType: stored.media_type });
    };
    descriptors = { json: descriptor(jsonArtifact), markdown: descriptor(rendered) };
  });
  if (regressed) throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; Session handoff registration is paused');
  if (!descriptors) return corrupt('Session handoff registered no complete descriptors');
  return immutableSnapshot({ method: 'session.handoff.create' as const, ...descriptors });
}
