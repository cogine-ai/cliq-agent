import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, normalizeBoundedText, parseCanonicalTime } from '../kernel/identity.js';
import { controlWireRecord, decodeWireSession, decodeWireArtifactDescriptor, decodeWireSessionItem } from '../kernel/control-wire-data.js';
import { decodeSessionContinuityRequest, normalizeSessionSummary, type SessionCompactRequestV1, type SessionForkRequestV1,
  type SessionHandoffRequestV1, type SessionCompactionItem, type SessionContinuityResultV1, type SessionHandoffV1 } from '../kernel/session-continuity.js';
import type { Session, SessionContextProjection, ArtifactDescriptorV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { assertCurrentControlFrame, validateControlChannelClosure, readRetainedControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeWorkspaceIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { insertControlRequest, readAdmissionReplay, readControlRequest } from './rows.js';
import { assertSessionContextCut, decodeSessionContext, readSessionContextCut, readFrozenSessionContextCut, sessionSourceItemsDigest, wholeSessionPrefix } from './session-context.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';

type Mutation = SessionForkRequestV1 | SessionCompactRequestV1;
type MutationResult = Extract<SessionContinuityResultV1, { method: 'session.fork' | 'session.compact' }>;
type Response = { protocolVersion: 1; ok: true; result: MutationResult };
function corrupt(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function core(request: Mutation) { const { requestDigest: _digest, ...data } = request; return data; }
function forkIntent(request: SessionForkRequestV1, principalId: string): string {
  return canonicalSha256({ principalId, method: request.method, request: { method: request.method, sessionId: request.sessionId,
    expectedContextRevision: request.expectedContextRevision, throughItemSeq: request.throughItemSeq,
    ...(request.name === undefined ? {} : { name: normalizeBoundedText(request.name, 1, 256) }) } });
}
async function readCanonical(artifacts: ArtifactCatalog, ref: string): Promise<unknown> {
  const data = await artifacts.readCanonical(ref);
  if (canonicalSha256(data) !== ref) return corrupt('Session original artifact changed');
  return data;
}
async function response(artifacts: ArtifactCatalog, ref: string, method: Mutation['method']): Promise<Response> {
  const value = controlWireRecord(await readCanonical(artifacts, ref), ['protocolVersion', 'ok', 'result']);
  const result = controlWireRecord(value.result, ['method', 'snapshot']);
  const snapshot = controlWireRecord(result.snapshot, ['schemaVersion', 'session']);
  if (value.protocolVersion !== 1 || value.ok !== true || result.method !== method || snapshot.schemaVersion !== 1)
    return corrupt('Session original response is invalid');
  return immutableSnapshot({ protocolVersion: 1, ok: true, result: { method, snapshot: { schemaVersion: 1, session: decodeWireSession(snapshot.session) } } });
}
function compactProjection(previous: SessionContextProjection, payload: SessionCompactionItem, itemId: string, itemSeq: number): SessionContextProjection {
  const next: SessionContextProjection = { ...previous, contextRevision: previous.contextRevision + 1, throughItemSeq: itemSeq, projectionDigest: '',
    segments: [...previous.segments.filter(segment => segment.throughItemSeq < payload.fromItemSeq),
      { kind: 'summary', fromItemSeq: payload.fromItemSeq, throughItemSeq: payload.throughItemSeq, compactionItemId: itemId,
        sourceItemsDigest: payload.sourceItemsDigest, summaryRef: payload.summaryRef, summaryDigest: payload.summaryDigest, retainedItemIds: [...payload.retainedItemIds] },
      ...previous.segments.filter(segment => segment.fromItemSeq > payload.throughItemSeq),
      { kind: 'excluded_control', fromItemSeq: itemSeq, throughItemSeq: itemSeq, sourceItemsDigest: sessionSourceItemsDigest([{ itemSeq, kind: 'compaction', payloadRef: canonicalSha256(payload) }]) }] };
  next.projectionDigest = digestOmitting(next, 'projectionDigest'); decodeSessionContext(next); return next;
}
type ControlRow = NonNullable<ReturnType<typeof readControlRequest>>;
async function auditReplay(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, request: Mutation, principalId: string,
  retained: ControlRow, current: () => void): Promise<Response> {
  current(); driver.readSnapshot(connection => assertActiveStateOwner(connection, owner));
  const retainedChannel = await readRetainedControlChannelClosure(artifacts, owner, { principalId, channelIdentityRef: retained.channelIdentityRef, channelIdentityDigest: retained.channelIdentityDigest });
  const originalCore = await readCanonical(artifacts, retained.requestDigest);
  if (canonicalSha256(originalCore) !== canonicalSha256(core(request))) return corrupt('Session retained request differs from its original public bytes');
  const saved = await response(artifacts, retained.responseRef, request.method), session = saved.result.snapshot.session;
  parseCanonicalTime(retained.committedAt);
  if (session.updatedAt > retained.committedAt || retainedChannel.channel.openedAt > retained.committedAt) return corrupt('Session response predates its original mutation or channel');
  let firstRequest: ControlRow | undefined, firstRequestId: string | undefined;
  if (request.method === 'session.fork') {
    const admission = readAdmissionReplay(driver, 'sessions', principalId, request.method, request.admissionKey);
    const id = identityHash('cliq-session-id-v1', principalId, request.method, request.admissionKey);
    if (!admission || admission.id !== id || admission.admissionIntentDigest !== forkIntent(request, principalId) || !admission.admissionRequestId ||
        session.id !== id || session.parentSessionId !== request.sessionId || session.forkedThroughItemSeq !== request.throughItemSeq ||
        session.contextRevision !== 1 || session.latestItemSeq !== request.throughItemSeq || session.createdAt !== session.updatedAt ||
        session.name !== (request.name === undefined ? undefined : normalizeBoundedText(request.name, 1, 256))) return corrupt('Session fork response differs from its original immutable admission');
    firstRequestId = admission.admissionRequestId; firstRequest = readControlRequest(driver, principalId, request.method, firstRequestId);
    if (!firstRequest || firstRequest.responseRef !== retained.responseRef || firstRequest.committedAt > retained.committedAt || session.createdAt > firstRequest.committedAt)
      return corrupt('Session fork response is not the original admission response');
    parseCanonicalTime(firstRequest.committedAt);
    const firstChannel = await readRetainedControlChannelClosure(artifacts, owner, { principalId, channelIdentityRef: firstRequest.channelIdentityRef, channelIdentityDigest: firstRequest.channelIdentityDigest });
    if (firstChannel.channel.openedAt > session.createdAt) return corrupt('Session fork original channel postdates its creation');
    const initialCore = await readCanonical(artifacts, firstRequest.requestDigest);
    const initialRequest = decodeSessionContinuityRequest({ ...(initialCore as object), requestDigest: firstRequest.requestDigest });
    if (initialRequest.method !== request.method || initialRequest.requestId !== firstRequestId || initialRequest.admissionKey !== request.admissionKey ||
        forkIntent(initialRequest, principalId) !== admission.admissionIntentDigest) return corrupt('Session fork original request link changed');
  } else {
    const itemId = identityHash('cliq-session-compaction-item-v1', request.sessionId, request.requestId);
    const row = driver.prepare('SELECT item_id,session_id,item_seq,kind,payload_ref,created_at FROM items WHERE item_id=?')
      .get<{ item_id: string; session_id: string; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(itemId);
    if (!row || row.item_seq > BigInt(Number.MAX_SAFE_INTEGER)) return corrupt('Session original compaction item is missing');
    const metadata = decodeWireSessionItem({ schemaVersion: 1, itemId: row.item_id, sessionId: row.session_id, itemSeq: Number(row.item_seq),
      kind: row.kind, payloadRef: row.payload_ref, createdAt: row.created_at });
    const payload = controlWireRecord(await readCanonical(artifacts, metadata.payloadRef), ['schemaVersion', 'kind', 'fromItemSeq', 'throughItemSeq',
      'sourceItemsDigest', 'summaryRef', 'summaryDigest', 'retainedItemIds', 'previousProjectionRef', 'createdAt']) as unknown as SessionCompactionItem;
    if (metadata.sessionId !== request.sessionId || metadata.kind !== 'compaction' || session.id !== request.sessionId || session.contextRevision !== request.expectedContextRevision + 1 ||
        session.latestItemSeq !== metadata.itemSeq || session.updatedAt !== metadata.createdAt || payload.createdAt !== metadata.createdAt || payload.schemaVersion !== 1 || payload.kind !== 'compaction')
      return corrupt('Session compaction response differs from its original immutable item');
    if (retainedChannel.channel.openedAt > metadata.createdAt) return corrupt('Session compaction original channel postdates its item');
    const previous = decodeSessionContext(await readCanonical(artifacts, payload.previousProjectionRef));
    const selected = previous.segments.filter(segment => segment.throughItemSeq >= request.fromItemSeq && segment.fromItemSeq <= request.throughItemSeq);
    if (previous.sessionId !== request.sessionId || previous.contextRevision !== request.expectedContextRevision || previous.throughItemSeq !== metadata.itemSeq - 1 ||
        !selected.length || selected[0]!.fromItemSeq !== request.fromItemSeq || selected.at(-1)!.throughItemSeq !== request.throughItemSeq || selected.some(segment => segment.kind !== 'raw'))
      return corrupt('Session compaction original frozen source range changed');
    const sources = selected.flatMap(segment => segment.kind === 'raw' ? segment.items : []), kept = sources.filter(source => request.retainedItemIds.includes(source.itemId));
    const utf8 = normalizeSessionSummary(request.summaryMarkdown), textCore = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8, byteCount: Buffer.byteLength(utf8) };
    const text = { ...textCore, textDigest: canonicalSha256(textCore) };
    const expectedPayload = { schemaVersion: 1, kind: 'compaction', fromItemSeq: request.fromItemSeq, throughItemSeq: request.throughItemSeq,
      sourceItemsDigest: sessionSourceItemsDigest(sources), summaryRef: canonicalSha256(text), summaryDigest: text.textDigest,
      retainedItemIds: kept.map(source => source.itemId), previousProjectionRef: payload.previousProjectionRef, createdAt: metadata.createdAt };
    if (kept.length !== request.retainedItemIds.length || canonicalSha256(payload) !== canonicalSha256(expectedPayload) ||
        canonicalSha256(compactProjection(previous, payload, itemId, metadata.itemSeq)) !== session.contextProjectionRef)
      return corrupt('Session compaction response changed its original summary or replacement projection');
  }
  await readFrozenSessionContextCut(driver, artifacts, principalId, session, connection => { current(); assertActiveStateOwner(connection, owner); });
  driver.readSnapshot(connection => {
    current(); assertActiveStateOwner(connection, owner);
    if (canonicalSha256(readControlRequest(connection, principalId, request.method, request.requestId) ?? null) !== canonicalSha256(retained) ||
        firstRequest && canonicalSha256(readControlRequest(connection, principalId, request.method, firstRequestId!) ?? null) !== canonicalSha256(firstRequest))
      return corrupt('Session original control response link changed during historical validation');
  });
  return saved;
}
async function originalReplay(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, request: Mutation, principalId: string,
  current: () => void): Promise<Response | undefined> {
  const retained = driver.readSnapshot(connection => { current(); assertActiveStateOwner(connection, owner); return readControlRequest(connection, principalId, request.method, request.requestId); });
  if (!retained) return;
  if (retained.requestDigest !== request.requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'Session requestId has different bytes');
  return auditReplay(driver, artifacts, owner, request, principalId, retained, current);
}
/** Session operations own context only. All state publication uses the original
 * Store owner, authenticated frame, canonical fence and one final transaction. */
export async function mutateSessionContext(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: unknown, identity: AuthenticatedControlIdentity, signal?: AbortSignal): Promise<Response> {
  const request = decodeSessionContinuityRequest(input);
  if (request.method !== 'session.fork' && request.method !== 'session.compact') throw new TypeError('Session mutation method is invalid');
  const channel = await validateControlChannelClosure(artifacts, owner, identity);
  const current = () => { signal?.throwIfAborted(); if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, identity); };
  current(); assertActiveStateOwner(driver, owner);
  const replay = await originalReplay(driver, artifacts, owner, request, identity.principalId, current); if (replay) { current(); return replay; }
  const intent = request.method === 'session.fork' ? forkIntent(request, identity.principalId) : undefined;
  const admission = request.method === 'session.fork' ? readAdmissionReplay(driver, 'sessions', identity.principalId, request.method, request.admissionKey) : undefined;
  if (admission) {
    if (admission.admissionIntentDigest !== intent) throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'Session admissionKey has a different intent');
    if (!admission.admissionRequestId) return corrupt('Session fork has no original response link');
    const original = readControlRequest(driver, identity.principalId, request.method, admission.admissionRequestId);
    if (!original) return corrupt('Session fork original response is missing');
    const originalCore = await readCanonical(artifacts, original.requestDigest);
    const originalRequest = decodeSessionContinuityRequest({ ...(originalCore as object), requestDigest: original.requestDigest });
    if (originalRequest.method !== 'session.fork' || originalRequest.requestId !== admission.admissionRequestId ||
        originalRequest.admissionKey !== (request as SessionForkRequestV1).admissionKey || forkIntent(originalRequest, identity.principalId) !== intent)
      return corrupt('Session fork original request does not bind its admission');
    const retained = await auditReplay(driver, artifacts, owner, originalRequest, identity.principalId, original, current);
    if (retained.result.snapshot.session.id !== admission.id) return corrupt('Session fork original response names another Session');
    const requestArtifact = await artifacts.publishCanonical(core(request), 'cliq-session-fork-request-core-v1');
    if (requestArtifact.ref !== request.requestDigest) return corrupt('Session fork public core changed');
    let regressed = false;
    driver.transaction(connection => {
      current(); assertActiveStateOwner(connection, owner);
      const raced = readControlRequest(connection, identity.principalId, request.method, request.requestId);
      if (raced) {
        if (raced.requestDigest !== request.requestDigest || raced.responseRef !== original.responseRef)
          throw new KernelStorageError('REQUEST_ID_CONFLICT', 'Session request replay raced with another binding');
        return;
      }
      const actual = readAdmissionReplay(connection, 'sessions', identity.principalId, request.method, (request as SessionForkRequestV1).admissionKey);
      const actualOriginal = readControlRequest(connection, identity.principalId, request.method, admission.admissionRequestId!);
      if (canonicalSha256(actual ?? null) !== canonicalSha256(admission) || canonicalSha256(actualOriginal ?? null) !== canonicalSha256(original))
        return corrupt('Session fork original immutable response link changed');
      if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { regressed = true; return; }
      const committedAt = readTimeFence(connection)!.lastAcceptedAt;
      for (const artifact of [...channel.metadata, requestArtifact]) insertArtifactMetadata(connection, artifact, committedAt);
      insertControlRequest(connection, { ...identity, method: request.method, requestId: request.requestId,
        requestDigest: request.requestDigest, responseRef: original.responseRef, committedAt });
    });
    if (regressed) throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; Session alias binding is paused');
    current(); return retained;
  }
  const context = await readSessionContextCut(driver, artifacts, identity.principalId, request.sessionId, request.expectedContextRevision);
  current(); const now = sampleCanonicalNow(), original = context.cut.session;
  const published: PublishedArtifact[] = [...channel.metadata];
  const requestArtifact = await artifacts.publishCanonical(core(request), `cliq-${request.method.replace('.', '-')}-request-core-v1`);
  if (requestArtifact.ref !== request.requestDigest) return corrupt('Session mutation public core changed');
  published.push(requestArtifact);
  let session: Session, projection: SessionContextProjection, compaction: { itemId: string; itemSeq: number; payloadRef: string } | undefined;
  if (request.method === 'session.fork') {
    const id = identityHash('cliq-session-id-v1', identity.principalId, request.method, request.admissionKey);
    projection = { schemaVersion: 1, format: 'cliq-session-context-v1', sessionId: id, contextRevision: 1,
      throughItemSeq: request.throughItemSeq, segments: wholeSessionPrefix(context.projection, request.throughItemSeq), projectionDigest: '' };
    session = { schemaVersion: 1, id, workspaceIdentityRef: original.workspaceIdentityRef, parentSessionId: original.id,
      forkedThroughItemSeq: request.throughItemSeq, contextRevision: 1, latestItemSeq: request.throughItemSeq,
      contextProjectionRef: '', createdAt: now, updatedAt: now, ...(request.name === undefined ? {} : { name: normalizeBoundedText(request.name, 1, 256) }) };
  } else {
    const selected = context.projection.segments.filter(segment => segment.throughItemSeq >= request.fromItemSeq && segment.fromItemSeq <= request.throughItemSeq);
    if (!selected.length || selected[0]!.fromItemSeq !== request.fromItemSeq || selected.at(-1)!.throughItemSeq !== request.throughItemSeq || selected.some(segment => segment.kind !== 'raw'))
      throw new KernelStorageError('INVALID_REQUEST', 'Session compaction requires whole raw segments');
    const sources = selected.flatMap(segment => segment.kind === 'raw' ? segment.items : []), retained = sources.filter(source => request.retainedItemIds.includes(source.itemId));
    if (retained.length !== request.retainedItemIds.length) throw new KernelStorageError('INVALID_REQUEST', 'Session retained item is outside the raw range');
    const utf8 = normalizeSessionSummary(request.summaryMarkdown), textCore = { schemaVersion: 1 as const, format: 'cliq-model-text-v1' as const, utf8, byteCount: Buffer.byteLength(utf8) };
    const text: ModelTextV1 = { ...textCore, textDigest: canonicalSha256(textCore) };
    const summary = await artifacts.publishCanonical(text, text.format); published.push(summary);
    const payload: SessionCompactionItem = { schemaVersion: 1, kind: 'compaction', fromItemSeq: request.fromItemSeq, throughItemSeq: request.throughItemSeq,
      sourceItemsDigest: sessionSourceItemsDigest(sources), summaryRef: summary.ref, summaryDigest: text.textDigest,
      retainedItemIds: retained.map(source => source.itemId), previousProjectionRef: original.contextProjectionRef, createdAt: now };
    const payloadArtifact = await artifacts.publishCanonical(payload, 'cliq-session-compaction-v1'); published.push(payloadArtifact);
    const itemSeq = original.latestItemSeq + 1;
    if (!Number.isSafeInteger(itemSeq) || !Number.isSafeInteger(original.contextRevision + 1)) return corrupt('Session sequence is exhausted');
    compaction = { itemId: identityHash('cliq-session-compaction-item-v1', original.id, request.requestId), itemSeq, payloadRef: payloadArtifact.ref };
    projection = compactProjection(context.projection, payload, compaction.itemId, itemSeq);
    session = { ...original, contextRevision: projection.contextRevision, latestItemSeq: itemSeq, contextProjectionRef: '', updatedAt: now };
  }
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest'); decodeSessionContext(projection);
  const projectionArtifact = await artifacts.publishCanonical(projection, projection.format); published.push(projectionArtifact);
  session.contextProjectionRef = projectionArtifact.ref; decodeWireSession(session);
  const result: Response = { protocolVersion: 1, ok: true, result: { method: request.method, snapshot: { schemaVersion: 1, session } } };
  const resultArtifact = await artifacts.publishCanonical(result, 'cliq-control-response-v1'); published.push(resultArtifact);
  current(); let regressed = false, committed = false;
  driver.transaction(connection => {
    current(); assertActiveStateOwner(connection, owner);
    const raced = readControlRequest(connection, identity.principalId, request.method, request.requestId);
    if (raced) { if (raced.requestDigest !== request.requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'Session requestId has different bytes'); return; }
    if (request.method === 'session.fork') {
      const existing = readAdmissionReplay(connection, 'sessions', identity.principalId, request.method, request.admissionKey);
      if (existing) { if (existing.admissionIntentDigest !== intent) throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'Session admissionKey has a different intent'); return; }
    }
    if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { regressed = true; return; }
    const committedAt = readTimeFence(connection)!.lastAcceptedAt;
    if (now > committedAt || now < original.updatedAt) throw new KernelStorageError('INVALID_REQUEST', 'Session preparation time is noncausal');
    assertSessionContextCut(connection, context.cut);
    for (const artifact of published) insertArtifactMetadata(connection, artifact, committedAt);
    if (request.method === 'session.fork') {
      connection.prepare(`INSERT INTO sessions(id,workspace_identity_ref,name,parent_session_id,forked_through_item_seq,context_revision,latest_item_seq,
        context_projection_ref,created_at,updated_at,principal_id,admission_method,admission_key,admission_intent_digest,admission_request_id)
        VALUES(?,?,?,?,?,1,?,?,?,?,?,'session.fork',?,?,?)`).run(session.id, session.workspaceIdentityRef, session.name ?? null, original.id,
        request.throughItemSeq, session.latestItemSeq, session.contextProjectionRef, now, now, identity.principalId, request.admissionKey, intent!, request.requestId);
    } else {
      connection.prepare('INSERT INTO items(item_id,session_id,item_seq,kind,payload_ref,created_at) VALUES(?,?,?,\'compaction\',?,?)')
        .run(compaction!.itemId, original.id, compaction!.itemSeq, compaction!.payloadRef, now);
      connection.prepare('UPDATE sessions SET context_revision=?,latest_item_seq=?,context_projection_ref=?,updated_at=? WHERE id=? AND principal_id=? AND context_revision=? AND context_projection_ref=?')
        .run(session.contextRevision, session.latestItemSeq, session.contextProjectionRef, now, original.id, identity.principalId, original.contextRevision, original.contextProjectionRef);
    }
    insertControlRequest(connection, { ...identity, method: request.method, requestId: request.requestId,
      requestDigest: request.requestDigest, responseRef: resultArtifact.ref, committedAt }); committed = true;
  });
  if (regressed) throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; Session mutation is paused');
  if (committed) return immutableSnapshot(result);
  // A concurrent request can only contribute its original committed response.
  return mutateSessionContext(driver, artifacts, owner, request, identity, signal);
}

export async function createSessionHandoff(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: unknown, identity: AuthenticatedControlIdentity, signal?: AbortSignal) {
  const request = decodeSessionContinuityRequest(input);
  if (request.method !== 'session.handoff.create') throw new TypeError('Session handoff method is invalid');
  const channel = await validateControlChannelClosure(artifacts, owner, identity);
  const current = () => { signal?.throwIfAborted(); if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, identity); };
  current(); const context = await readSessionContextCut(driver, artifacts, identity.principalId, request.sessionId, request.expectedContextRevision);
  const through = request.throughItemSeq ?? context.projection.throughItemSeq, segments = wholeSessionPrefix(context.projection, through);
  const workspace = decodeWorkspaceIdentity(await readCanonical(artifacts, context.cut.session.workspaceIdentityRef));
  if (workspace.ownerPrincipalId !== identity.principalId) return corrupt('Session handoff workspace belongs to another principal');
  const handoff: SessionHandoffV1 = { schemaVersion: 1, format: 'cliq-session-handoff-v1', sessionId: context.cut.session.id,
    workspaceIdentityRef: context.cut.session.workspaceIdentityRef, workspaceIdentityDigest: workspace.identityDigest,
    contextRevision: context.projection.contextRevision, throughItemSeq: through, contextProjectionRef: context.cut.session.contextProjectionRef,
    contextProjectionDigest: context.projection.projectionDigest, entries: context.entries.filter(entry => entry.throughItemSeq <= through)
      .map(({ sourceItemId: _id, ...entry }, index) => ({ ...entry, index })), excludedRanges: segments.filter(segment => segment.kind === 'excluded_control')
      .map(({ fromItemSeq, throughItemSeq, sourceItemsDigest }) => ({ fromItemSeq, throughItemSeq, sourceItemsDigest })), handoffDigest: '' };
  const complete = { ...handoff, handoffDigest: digestOmitting(handoff, 'handoffDigest') };
  const json = await artifacts.publishCanonical(complete, complete.format); current();
  let markdown = '# Cliq Session Handoff\n\n' + `Session: ${canonicalJsonBytes(complete.sessionId).toString('utf8')}\nContext revision: ${complete.contextRevision}\nThrough item: ${through}\n`;
  for (const entry of complete.entries) markdown += `\n## Entry ${entry.index + 1}: ${entry.sourceKind}\n\n` + entry.contentUtf8.split('\n').map(line => `    ${line}`).join('\n') + '\n';
  markdown += `\nExcluded control ranges: ${complete.excludedRanges.length}\n`;
  const rendered = await artifacts.publishBytes(Buffer.from(markdown), 'text/markdown; charset=utf-8', 'cliq-session-handoff-markdown-v1'); current();
  let regressed = false, descriptors: { json: ArtifactDescriptorV1; markdown: ArtifactDescriptorV1 } | undefined;
  driver.transaction(connection => {
    current(); assertActiveStateOwner(connection, owner);
    if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { regressed = true; return; }
    assertSessionContextCut(connection, context.cut);
    for (const artifact of [...channel.metadata, json, rendered]) insertArtifactMetadata(connection, artifact, readTimeFence(connection)!.lastAcceptedAt);
    const descriptor = (artifact: PublishedArtifact): ArtifactDescriptorV1 => {
      const stored = connection.prepare('SELECT byte_length,media_type FROM artifacts WHERE ref=?').get<{ byte_length: bigint; media_type: string }>(artifact.ref);
      if (!stored || stored.byte_length !== BigInt(artifact.byteLength)) return corrupt('Session handoff original catalog length differs');
      return decodeWireArtifactDescriptor({ schemaVersion: 1, ref: artifact.ref, digest: artifact.ref, sizeBytes: artifact.byteLength, mediaType: stored.media_type });
    };
    descriptors = { json: descriptor(json), markdown: descriptor(rendered) };
  });
  if (regressed) throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; Session handoff registration is paused');
  if (!descriptors) return corrupt('Session handoff registered no descriptors');
  return immutableSnapshot({ method: 'session.handoff.create' as const, ...descriptors });
}
