import assert from 'node:assert/strict';
import path from 'node:path';
import { rm, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import ts from 'typescript';
import test from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeInstalledControlResponse } from '../kernel/control-wire.js';
import type { SessionContextProjection } from '../kernel/types.js';
import { readTimeFence, recoverRegressedTimeFence } from './canonical-time.js';
import { ListCutCapacityError } from './list-read-cut.js';
import { insertArtifactMetadata } from './artifacts.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { readSessionContextCut, frozenSessionCompactionIndex, readSessionContextEntries } from './session-context.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { admissionKey, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';
import { listFixture, stopActualListChild } from './testing/list-fixture.js';

const mutation = <T extends object>(value: T) => {
  const { requestDigest: _digest, ...core } = value as T & { requestDigest?: string };
  return { ...core, requestDigest: canonicalSha256(core) };
};

test('real terminal publication, whole compaction, retained context, immutable fork and first responses close across reopen', async () => {
  const fixture = await createAgentFixture('session-continuity', undefined, { mode: 'plan' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    let identity = await publishInProcessChannel(fixture.store);
    const run = fixture.store.getRun(fixture.runId), originalSession = fixture.store.getSession(run.sessionId);
    const originalProjection = await fixture.store.artifacts.readCanonical<SessionContextProjection>(originalSession.contextProjectionRef);
    const stopped = await fixture.agent.cancelRun({ ...identity, requestId: uuidv7(), expectedRunRevision: run.revision });
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    await fixture.agent.commitTerminalStop({ expectedRunRevision: fixture.store.getRun(run.id).revision, checkpoint: proof.checkpoint });
    const terminal = await fixture.store.readControl({ protocolVersion: 1, method: 'session.get', sessionId: run.sessionId }, identity);
    assert(terminal.method === 'session.get'); assert.equal(terminal.items.length, 1); assert.equal(terminal.items[0]!.kind, 'run_terminal');
    const parent = terminal.snapshot.session, item = terminal.items[0]!;
    const fork = mutation({ protocolVersion: 1, method: 'session.fork', requestId: uuidv7(), admissionKey: admissionKey('continuity-before'),
      sessionId: parent.id, expectedContextRevision: parent.contextRevision, throughItemSeq: 1, name: 'Frozen raw child' });
    const childReply = await fixture.store.sessionContinuity(fork, identity); assert(childReply.result.method === 'session.fork');
    const child = childReply.result.snapshot.session;
    assert.equal(driver.prepare('SELECT count(*) AS n FROM items WHERE session_id=?').get<{ n: bigint }>(child.id)!.n, 0n);
    const compact = mutation({ protocolVersion: 1, method: 'session.compact', requestId: uuidv7(), sessionId: parent.id,
      expectedContextRevision: parent.contextRevision, fromItemSeq: 1, throughItemSeq: 1, summaryMarkdown: 'Cafe\u0301\r\nsummary\rline', retainedItemIds: [item.itemId] });
    const compactReply = await fixture.store.sessionContinuity(compact, identity); assert(compactReply.result.method === 'session.compact');
    const compacted = compactReply.result.snapshot.session;
    assert.equal(compacted.contextRevision, parent.contextRevision + 1); assert.equal(compacted.latestItemSeq, 2);
    const exportedContext = await readSessionContextCut(driver, fixture.store.artifacts, identity.principalId, parent.id);
    const workspaceIdentity = await fixture.store.artifacts.readCanonical<any>(parent.workspaceIdentityRef);
    const expectedHandoff = { schemaVersion: 1, format: 'cliq-session-handoff-v1', sessionId: parent.id,
      workspaceIdentityRef: parent.workspaceIdentityRef, workspaceIdentityDigest: workspaceIdentity.identityDigest,
      contextRevision: compacted.contextRevision, throughItemSeq: compacted.latestItemSeq, contextProjectionRef: compacted.contextProjectionRef,
      contextProjectionDigest: exportedContext.projection.projectionDigest,
      entries: exportedContext.entries.map(({ sourceItemId: _id, ...entry }) => entry),
      excludedRanges: exportedContext.projection.segments.filter(segment => segment.kind === 'excluded_control')
        .map(({ fromItemSeq, throughItemSeq, sourceItemsDigest }) => ({ fromItemSeq, throughItemSeq, sourceItemsDigest })), handoffDigest: '' };
    expectedHandoff.handoffDigest = digestOmitting(expectedHandoff, 'handoffDigest');
    const earlierUse = await fixture.store.artifacts.publishCanonical(expectedHandoff, expectedHandoff.format);
    driver.transaction(connection => insertArtifactMetadata(connection, { ...earlierUse, mediaType: 'application/octet-stream', schemaKind: 'cliq-source-file-blob-v1' }, compacted.updatedAt));
    const handoffRequest = { protocolVersion: 1, method: 'session.handoff.create', sessionId: parent.id, expectedContextRevision: compacted.contextRevision } as const;
    const exported = await fixture.store.sessionContinuity(handoffRequest, identity); assert(exported.result.method === 'session.handoff.create');
    const handoff = await fixture.store.artifacts.readCanonical<any>(exported.result.json.ref);
    assert.equal(exported.result.json.ref, earlierUse.ref); assert.equal(exported.result.json.mediaType, 'application/octet-stream', 'the first same-byte descriptor remains unchanged');
    const retrieved = await fixture.store.readControl({ protocolVersion: 1, method: 'artifact.get', digest: earlierUse.ref, offset: 0, length: 65536 }, identity);
    assert(retrieved.method === 'artifact.get'); assert.deepEqual(retrieved.artifact, exported.result.json);
    assert.equal(handoff.handoffDigest, digestOmitting(handoff, 'handoffDigest'));
    assert.deepEqual(handoff.entries.map((entry: any) => entry.sourceKind), ['summary', 'run_terminal']);
    assert.equal(handoff.entries[0].contentUtf8, 'Café\nsummary\nline');
    assert.deepEqual(handoff.excludedRanges.map((range: any) => [range.fromItemSeq, range.throughItemSeq]), [[2, 2]]);
    const markdown = (await fixture.store.artifacts.readBytes(exported.result.markdown.ref)).toString('utf8');
    assert(markdown.includes('    Café\n    summary\n    line\n')); assert(!markdown.includes('terminalDetailRef'));
    assert.deepEqual(await fixture.store.sessionContinuity(handoffRequest, identity), exported);
    const summaryFork = mutation({ ...fork, requestId: uuidv7(), admissionKey: admissionKey('continuity-summary'), expectedContextRevision: compacted.contextRevision, name: 'Summary child' });
    // Recompute from the complete original public core, never a digest of a digest.
    const { requestDigest: _old, ...summaryCore } = summaryFork;
    const summaryReply = await fixture.store.sessionContinuity(mutation(summaryCore), identity); assert(summaryReply.result.method === 'session.fork');
    const summaryChild = summaryReply.result.snapshot.session;
    const readSummary = await readSessionContextCut(driver, fixture.store.artifacts, identity.principalId, summaryChild.id);
    assert.equal(readSummary.cut.items.length, 1, 'source compaction metadata beyond the fork cursor is not a logical child item');
    assert.deepEqual(readSummary.entries.map(entry => entry.sourceKind), ['summary', 'run_terminal']);
    const projected = await readSessionContextEntries(fixture.store.artifacts, readSummary.projection,
      frozenSessionCompactionIndex(driver, summaryChild.id, 1));
    assert.deepEqual(projected, readSummary.entries);
    const currentChild = fixture.store.getSession(summaryChild.id);
    driver.transaction(connection => connection.prepare('UPDATE sessions SET context_revision=0,latest_item_seq=-1,context_projection_ref=? WHERE id=?').run('f'.repeat(64), summaryChild.id));
    assert.deepEqual(await readSessionContextEntries(fixture.store.artifacts, readSummary.projection,
      frozenSessionCompactionIndex(driver, summaryChild.id, 1)), projected,
      'admitted context depends only on immutable lineage/index, even when today mutable Session head cannot decode');
    assert.deepEqual(await fixture.store.sessionContinuity(mutation(summaryCore), identity), summaryReply,
      'historical first response is audited against its original graph, not today mutable child head');
    driver.transaction(connection => connection.prepare('UPDATE sessions SET context_revision=?,latest_item_seq=?,context_projection_ref=? WHERE id=?')
      .run(currentChild.contextRevision, currentChild.latestItemSeq, currentChild.contextProjectionRef, currentChild.id));
    const summarySegment = readSummary.projection.segments[0]!; assert(summarySegment.kind === 'summary');
    const compactionRow = driver.prepare('SELECT payload_ref FROM items WHERE item_id=?').get<{ payload_ref: string }>(summarySegment.compactionItemId)!;
    const justification = await fixture.store.artifacts.readCanonical<any>(compactionRow.payload_ref);
    const previous = await fixture.store.artifacts.readCanonical<SessionContextProjection>(justification.previousProjectionRef);
    const changedPrevious = structuredClone(previous); assert(changedPrevious.segments[0]!.kind === 'raw');
    changedPrevious.segments[0]!.items[0]!.sourceSessionId = 'unrelated-same-bytes';
    changedPrevious.projectionDigest = digestOmitting(changedPrevious, 'projectionDigest');
    const changedPreviousArtifact = await fixture.store.artifacts.publishCanonical(changedPrevious, changedPrevious.format);
    const changedJustification = await fixture.store.artifacts.publishCanonical({ ...justification, previousProjectionRef: changedPreviousArtifact.ref }, 'cliq-session-compaction-v1');
    assert.throws(() => driver.transaction(connection => connection.prepare('UPDATE items SET payload_ref=? WHERE item_id=?').run(changedJustification.ref, summarySegment.compactionItemId)), /items are immutable/);
    const actualIndex = frozenSessionCompactionIndex(driver, summaryChild.id, 1);
    // Malformed data-candidate seam only: the real immutable index still checks
    // every supplied source tuple. No reducer, Run or native proof is minted.
    await assert.rejects(readSessionContextEntries(fixture.store.artifacts, readSummary.projection,
      (id, sources) => { const value = actualIndex(id, sources); return { ...value, item: { ...value.item, payloadRef: changedJustification.ref } }; }),
      { code: 'RECOVERY_REQUIRED' }, 'equal content cannot adopt an unrelated source Session');
    assert.deepEqual(await readSessionContextEntries(fixture.store.artifacts, originalProjection), [], 'an old admitted projection remains unchanged');
    const rawChild = await readSessionContextCut(driver, fixture.store.artifacts, identity.principalId, child.id);
    assert.equal(rawChild.projection.segments[0]!.kind, 'raw'); assert.equal(rawChild.entries[0]!.sourceItemId, item.itemId);
    const contenders = ['first', 'second'].map(summaryMarkdown => mutation({ protocolVersion: 1, method: 'session.compact', requestId: uuidv7(),
      sessionId: child.id, expectedContextRevision: 1, fromItemSeq: 1, throughItemSeq: 1, summaryMarkdown, retainedItemIds: [] }));
    const competed = await Promise.allSettled(contenders.map(request => fixture.store.sessionContinuity(request, identity)));
    assert.equal(competed.filter(result => result.status === 'fulfilled').length, 1);
    const refused = competed.find(result => result.status === 'rejected'); assert(refused?.status === 'rejected'); assert.equal(refused.reason.code, 'REVISION_CONFLICT');
    const winner = competed.findIndex(result => result.status === 'fulfilled');
    assert.deepEqual(await fixture.store.sessionContinuity(contenders[winner], identity), (competed[winner] as PromiseFulfilledResult<unknown>).value);
    assert.equal(driver.prepare('SELECT count(*) AS n FROM items WHERE session_id=?').get<{ n: bigint }>(child.id)!.n, 1n);
    for (const [originalRequest, otherRequest] of [[fork, mutation(summaryCore)], [compact, contenders[winner]!]]) {
      const read = (request: typeof originalRequest) => driver.prepare('SELECT response_ref FROM control_requests WHERE principal_id=? AND method=? AND request_id=?')
        .get<{ response_ref: string }>(identity.principalId, request.method, request.requestId)!;
      const originalLink = read(originalRequest), otherLink = read(otherRequest);
      assert.notEqual(originalLink.response_ref, otherLink.response_ref);
      driver.transaction(connection => connection.prepare('UPDATE control_requests SET response_ref=? WHERE principal_id=? AND method=? AND request_id=?')
        .run(otherLink.response_ref, identity.principalId, originalRequest.method, originalRequest.requestId));
      await assert.rejects(fixture.store.sessionContinuity(originalRequest, identity), { code: 'RECOVERY_REQUIRED' },
        'a valid same-principal/same-method response cannot replace the original immutable mutation');
      driver.transaction(connection => connection.prepare('UPDATE control_requests SET response_ref=? WHERE principal_id=? AND method=? AND request_id=?')
        .run(originalLink.response_ref, identity.principalId, originalRequest.method, originalRequest.requestId));
    }
    const originalAuthority = await fixture.store.readRecoveryClosure(run.id), spec = originalAuthority.runSpec;
    const source = await fixture.store.artifacts.readCanonical<{ frozenIgnoreRulesRef: string }>(spec.sourceProjectionRef);
    const resumed = await fixture.store.admitRun({ ...identity, requestId: uuidv7(), admissionKey: admissionKey('continuity-second-terminal'),
      sessionId: child.id, expectedContextRevision: fixture.store.getSession(child.id).contextRevision, workspacePath: fixture.workspace,
      objective: 'Publish another genuine undispatched terminal.', allowUnverified: true, assemblyRef: spec.assemblyRef, policyRef: spec.policyRef,
      sandboxProfileRef: spec.sandboxProfileRef, verifierSpecRef: spec.verifierSpecRef, sourceProjectionRef: spec.sourceProjectionRef,
      baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef, frozenIgnoreRulesRef: source.frozenIgnoreRulesRef,
      credentialGrantRefs: spec.credentialGrantRefs, budgets: spec.budgets });
    const resumedAgent = await fixture.store.loadAgentRun({ runId: resumed.run.id, material: fixture.authority.material, releaseKeys: fixture.signed.releaseKeys });
    const resumedStop = await resumedAgent.cancelRun({ ...identity, requestId: uuidv7(), expectedRunRevision: resumed.run.revision });
    await resumedAgent.commitTerminalStop({ expectedRunRevision: resumedStop.run.revision });
    const beforeSecondCompact = fixture.store.getSession(child.id);
    const secondCompact = mutation({ protocolVersion: 1, method: 'session.compact', requestId: uuidv7(), sessionId: child.id,
      expectedContextRevision: beforeSecondCompact.contextRevision, fromItemSeq: beforeSecondCompact.latestItemSeq,
      throughItemSeq: beforeSecondCompact.latestItemSeq, summaryMarkdown: 'A later independent terminal.', retainedItemIds: [] });
    await fixture.store.sessionContinuity(secondCompact, identity);
    const winningRequest = contenders[winner]!;
    const originalVersion = driver.prepare('SELECT response_ref FROM control_requests WHERE method=? AND request_id=?').get<{ response_ref: string }>('session.compact', winningRequest.requestId)!;
    const laterVersion = driver.prepare('SELECT response_ref FROM control_requests WHERE method=? AND request_id=?').get<{ response_ref: string }>('session.compact', secondCompact.requestId)!;
    driver.transaction(connection => connection.prepare('UPDATE control_requests SET response_ref=? WHERE method=? AND request_id=?').run(laterVersion.response_ref, 'session.compact', winningRequest.requestId));
    await assert.rejects(fixture.store.sessionContinuity(winningRequest, identity), { code: 'RECOVERY_REQUIRED' }, 'a later legal same-Session compact response cannot replace the original version');
    driver.transaction(connection => connection.prepare('UPDATE control_requests SET response_ref=? WHERE method=? AND request_id=?').run(originalVersion.response_ref, 'session.compact', winningRequest.requestId));
    assert.deepEqual(await fixture.store.sessionContinuity(winningRequest, identity), (competed[winner] as PromiseFulfilledResult<unknown>).value);
    await assert.rejects(fixture.store.sessionContinuity(mutation({ ...summaryCore, requestId: uuidv7(), admissionKey: admissionKey('bad-cursor'), throughItemSeq: 3 }), identity), { code: 'INVALID_REQUEST' });
    await assert.rejects(fixture.store.sessionContinuity(mutation({ ...compact, requestId: uuidv7(), expectedContextRevision: compacted.contextRevision }), identity));
    await assert.rejects(fixture.store.sessionContinuity(mutation({ ...compact, summaryMarkdown: 'changed' }), identity), { code: 'REQUEST_ID_CONFLICT' });
    await fixture.store.close(); fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    identity = await publishInProcessChannel(fixture.store);
    assert.deepEqual(await fixture.store.sessionContinuity(compact, identity), compactReply);
    assert.deepEqual(await fixture.store.sessionContinuity(fork, identity), childReply);
    const { requestDigest: _originalDigest, ...forkCore } = fork;
    assert.deepEqual(await fixture.store.sessionContinuity(mutation({ ...forkCore, requestId: uuidv7() }), identity), childReply,
      'fork admission alias replays the first snapshot before consulting the changed parent revision');
    assert.deepEqual(await fixture.store.sessionContinuity(handoffRequest, identity), exported);
    assert.equal(driver.prepare('SELECT count(*) AS n FROM items WHERE session_id=?').get<{ n: bigint }>(parent.id)!.n, 2n);
    assert.deepEqual(decodeInstalledControlResponse(exported, handoffRequest), exported);
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('materialized list freezes full membership/values, authenticates issued pages and survives restart', async () => {
  const fixture = await listFixture('list');
  try {
    const first = await fixture.create('first'), second = await fixture.create('second'), third = await fixture.create('third');
    fixture.driver.transaction(connection => connection.prepare('UPDATE sessions SET created_at=?,updated_at=?').run(first.createdAt, third.updatedAt));
    const request = { protocolVersion: 1, method: 'session.list', workspacePath: fixture.workspace, limit: 1 } as const;
    const initial = await fixture.store.sessionContinuity(request, fixture.identity); assert(initial.result.method === 'session.list');
    const expected = [first.id, second.id, third.id].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    assert.equal(initial.result.sessions[0]!.id, expected[0]); assert(initial.result.nextCursor);
    const cursorRequest = { ...request, cursor: initial.result.nextCursor };
    const next = await fixture.store.sessionContinuity(cursorRequest, fixture.identity); assert(next.result.method === 'session.list');
    fixture.driver.transaction(connection => connection.prepare('UPDATE sessions SET name=? WHERE id=?').run('later live name', next.result.method === 'session.list' ? next.result.sessions[0]!.id : ''));
    await fixture.create('fourth'); await fixture.reopen();
    assert.deepEqual(await fixture.store.sessionContinuity(cursorRequest, fixture.identity), next);
    assert(next.result.nextCursor);
    const last = await fixture.store.sessionContinuity({ ...request, cursor: next.result.nextCursor }, fixture.identity); assert(last.result.method === 'session.list');
    assert.equal(last.result.sessions[0]!.id, expected[2]); assert.equal(last.result.nextCursor, undefined);
    for (const changed of [{ ...cursorRequest, limit: 2 }, { ...cursorRequest, workspacePath: path.dirname(fixture.workspace) },
      { ...cursorRequest, cursor: initial.result.nextCursor + '=' }, { ...cursorRequest, cursor: 'AAAA' }])
      await assert.rejects(fixture.store.sessionContinuity(changed, fixture.identity), { code: 'INVALID_REQUEST' });
    const raw = JSON.parse(Buffer.from(initial.result.nextCursor, 'base64url').toString('utf8'));
    raw.afterOrdinal = 3;
    await assert.rejects(fixture.store.sessionContinuity({ ...request, cursor: canonicalJsonBytes(raw).toString('base64url') }, fixture.identity), { code: 'INVALID_REQUEST' });
    const fresh = await fixture.store.sessionContinuity({ ...request, limit: 100 }, fixture.identity); assert(fresh.result.method === 'session.list'); assert.equal(fresh.result.sessions.length, 4);
    assert.deepEqual(decodeInstalledControlResponse(fresh, { ...request, limit: 100 }), fresh);
  } finally { await fixture.close(); }
});

test('yielded list preparation rechecks the complete source set and old entry bytes before publication', async t => {
  const fixture = await listFixture('cut-races');
  try {
    const first = await fixture.create('race-first'); await fixture.create('race-second'); await fixture.create('race-third');
    const prototype = Object.getPrototypeOf(fixture.driver), original = prototype.transaction;
    let change: 'value' | 'membership' | 'entry' | undefined, originalPayload: string | undefined, cutId: string | undefined;
    t.mock.method(prototype, 'transaction', function (this: unknown, ...args: unknown[]) {
      const result = Reflect.apply(original, this, args);
      const source = typeof result === 'number';
      const old = result && typeof result === 'object' && 'row' in result && (result as any).row.cut_id === cutId;
      if (change && (source && change !== 'entry' || old && change === 'entry')) {
        const mutation = change; change = undefined;
        queueMicrotask(() => fixture.driver.transaction(connection => {
          if (mutation === 'value') connection.prepare('UPDATE sessions SET name=? WHERE id=?').run('changed after the source cut', first.id);
          else if (mutation === 'membership') {
            // Query display metadata only, never an admissible context graph
            // or a Run/native proof; exercise the complete membership check.
            connection.prepare(`INSERT INTO sessions(id,workspace_identity_ref,name,parent_session_id,forked_through_item_seq,context_revision,latest_item_seq,
              context_projection_ref,created_at,updated_at,principal_id,admission_method,admission_key,admission_intent_digest,admission_request_id)
              SELECT 'inserted-after-cut',workspace_identity_ref,'new display member',NULL,NULL,1,0,context_projection_ref,created_at,updated_at,
              principal_id,'display_fixture','inserted-after-cut',admission_intent_digest,NULL FROM sessions WHERE id=?`).run(first.id);
          } else {
            originalPayload = connection.prepare('SELECT payload_json FROM list_read_cut_entries WHERE cut_id=? AND ordinal=2').get<{ payload_json: string }>(cutId!)!.payload_json;
            const data = JSON.parse(originalPayload); data.value.name = 'changed cache bytes';
            connection.prepare('UPDATE list_read_cut_entries SET payload_json=? WHERE cut_id=? AND ordinal=2').run(canonicalJsonBytes(data).toString('utf8'), cutId!);
          }
        }));
      }
      return result;
    });
    const request = { protocolVersion: 1, method: 'session.list', limit: 100 } as const;
    change = 'value';
    const values = await fixture.store.sessionContinuity(request, fixture.identity); assert(values.result.method === 'session.list');
    assert.equal(values.result.sessions.find(session => session.id === first.id)!.name, 'changed after the source cut');
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get<{ n: bigint }>()!.n, 1n);
    change = 'membership';
    const members = await fixture.store.sessionContinuity(request, fixture.identity); assert(members.result.method === 'session.list');
    assert.equal(members.result.sessions.length, 4); assert(members.result.sessions.some(session => session.id === 'inserted-after-cut'));
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get<{ n: bigint }>()!.n, 2n);
    const cuts = fixture.driver.prepare(`SELECT count(e.ordinal) AS n,min(e.ordinal) AS first,max(e.ordinal) AS last
      FROM list_read_cuts c JOIN list_read_cut_entries e ON e.cut_id=c.cut_id GROUP BY c.cut_id`)
      .all<{ n: bigint; first: bigint; last: bigint }>();
    assert.deepEqual(cuts.map(cut => cut.n).sort(), [3n, 4n]);
    for (const cut of cuts) {
      assert.equal(cut.first, 1n);
      assert.equal(cut.last, cut.n, 'source changes must restart the complete contiguous cut, never retain scratch ordinals');
    }
    const firstPage = await fixture.store.sessionContinuity({ ...request, limit: 1 }, fixture.identity); assert(firstPage.result.method === 'session.list' && firstPage.result.nextCursor);
    cutId = JSON.parse(Buffer.from(firstPage.result.nextCursor, 'base64url').toString('utf8')).cutId;
    const cursor = { ...request, limit: 1, cursor: firstPage.result.nextCursor };
    change = 'entry';
    await assert.rejects(fixture.store.sessionContinuity(cursor, fixture.identity), { code: 'RECOVERY_REQUIRED' });
    assert(originalPayload);
    fixture.driver.transaction(connection => connection.prepare('UPDATE list_read_cut_entries SET payload_json=? WHERE cut_id=? AND ordinal=2').run(originalPayload!, cutId!));
    assert.equal((await fixture.store.sessionContinuity(cursor, fixture.identity)).result.method, 'session.list', 'the exact restored original entry remains replayable');
  } finally { t.mock.restoreAll(); await fixture.close(); }
});

test('native list snapshot bounds every copied text field before sorting and rejects malformed original rows', async t => {
  const fixture = await listFixture('bounded-native-copy');
  try {
    const original = await fixture.create('original display source'), actual = Reflect.get(fixture.store, 'driver');
    const columns = ['id', 'workspace_identity_ref', 'name', 'parent_session_id', 'created_at', 'updated_at'] as const;
    const bounds = [128, 64, 256, 128, 24, 24];
    const row = fixture.driver.prepare('SELECT ' + columns.join(',') + ' FROM sessions WHERE id=?').get<Record<string, string | null>>(original.id)!;
    const prototype = Object.getPrototypeOf(actual), transaction = prototype.transaction;
    let copies = 0;
    t.mock.method(prototype, 'transaction', function (this: unknown, ...args: unknown[]) {
      const value = Reflect.apply(transaction, this, args);
      if (this === actual && typeof value === 'number') {
        const lengths = actual.prepare('SELECT ' + columns.map(column => 'max(length(CAST(' + column + ' AS BLOB))) AS ' + column).join(',') + ' FROM temp.cliq_list_source').get();
        for (let index = 0; index < columns.length; index++)
          assert(lengths[columns[index]!] === null || lengths[columns[index]!] <= BigInt(bounds[index]!));
        copies++;
      }
      return value;
    });
    const oversized = 'x'.repeat(1_048_576);
    for (const column of columns) {
      const display = { ...row, id: 'malformed-display-' + column, [column]: oversized };
      // Display-only rejection input, like the capacity fixture. No accepted
      // Session graph, Run, StateOwner or native proof is fabricated; immutable
      // admission guards remain enabled and the malformed row is deleted.
      fixture.driver.transaction(connection => connection.prepare(`INSERT INTO sessions(id,workspace_identity_ref,name,parent_session_id,
        forked_through_item_seq,context_revision,latest_item_seq,context_projection_ref,created_at,updated_at,principal_id,
        admission_method,admission_key,admission_intent_digest,admission_request_id)
        VALUES(?,?,?,?,NULL,1,0,?,?,?,?,'display_fixture',?,?,NULL)`).run(display.id!, display.workspace_identity_ref!, display.name!,
          display.parent_session_id!, original.contextProjectionRef, display.created_at!, display.updated_at!, fixture.identity.principalId,
          'malformed-display-' + column, original.contextProjectionRef));
      try {
        await assert.rejects(fixture.store.sessionContinuity({ protocolVersion: 1, method: 'session.list', limit: 100 }, fixture.identity), { code: 'RECOVERY_REQUIRED' });
        assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get<{ n: bigint }>()!.n, 0n);
      } finally {
        fixture.driver.transaction(connection => connection.prepare('DELETE FROM sessions WHERE id=?').run(display.id!));
      }
    }
    assert.equal(copies, columns.length);
    const restored = await fixture.store.sessionContinuity({ protocolVersion: 1, method: 'session.list', limit: 100 }, fixture.identity);
    assert(restored.result.method === 'session.list'); assert.equal(restored.result.sessions[0]!.id, original.id);
  } finally { t.mock.restoreAll(); await fixture.close(); }
});

test('native list source copy rejects malformed UTF-8 rather than presenting replacement text', async () => {
  const fixture = await listFixture('native-source-utf8');
  try {
    const session = await fixture.create('original valid display name');
    fixture.driver.transaction(connection => connection.prepare("UPDATE sessions SET name=CAST(x'f09f98' AS TEXT) WHERE id=?").run(session.id));
    try {
      await assert.rejects(fixture.store.sessionContinuity({ protocolVersion: 1, method: 'session.list', limit: 1 }, fixture.identity), { code: 'RECOVERY_REQUIRED' });
      assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get<{ n: bigint }>()!.n, 0n);
    } finally {
      fixture.driver.transaction(connection => connection.prepare('UPDATE sessions SET name=? WHERE id=?').run(session.name!, session.id));
    }
  } finally { await fixture.close(); }
});

test('native retained page rejects changed UTF-8 bytes even when replacement decoding would preserve its digest', async () => {
  const fixture = await listFixture('native-retained-utf8');
  try {
    await fixture.create('a valid replacement character: \ufffd'); await fixture.create('second entry');
    const first = await fixture.store.sessionContinuity({ protocolVersion: 1, method: 'session.list', limit: 1 }, fixture.identity);
    assert(first.result.method === 'session.list' && first.result.nextCursor);
    const request = { protocolVersion: 1, method: 'session.list', limit: 1, cursor: first.result.nextCursor } as const;
    const before = await fixture.store.sessionContinuity(request, fixture.identity);
    const cutId = JSON.parse(Buffer.from(first.result.nextCursor, 'base64url').toString('utf8')).cutId;
    const row = fixture.driver.prepare("SELECT ordinal,payload_json FROM list_read_cut_entries WHERE cut_id=? AND instr(payload_json,?)>0")
      .get<{ ordinal: bigint; payload_json: string }>(cutId, '\ufffd')!;
    const bytes = Buffer.from(row.payload_json), index = bytes.indexOf(Buffer.from('\ufffd')); assert(index >= 0);
    const changed = Buffer.from(bytes); changed.set([0xf0, 0x9f, 0x98], index);
    assert.equal(changed.toString('utf8'), bytes.toString('utf8'), 'default replacement decoding cannot identify these changed bytes');
    fixture.driver.transaction(connection => connection.prepare('UPDATE list_read_cut_entries SET payload_json=CAST(? AS TEXT) WHERE cut_id=? AND ordinal=?').run(changed, cutId, row.ordinal));
    try { await assert.rejects(fixture.store.sessionContinuity(request, fixture.identity), { code: 'RECOVERY_REQUIRED' }); }
    finally { fixture.driver.transaction(connection => connection.prepare('UPDATE list_read_cut_entries SET payload_json=? WHERE cut_id=? AND ordinal=?').run(row.payload_json, cutId, row.ordinal)); }
    assert.deepEqual(canonicalJsonBytes(await fixture.store.sessionContinuity(request, fixture.identity)), canonicalJsonBytes(before));
  } finally { await fixture.close(); }
});

test('native list text decoding preserves a legal leading BOM from actual Session creation and frozen page replay', async () => {
  const fixture = await listFixture('native-source-bom');
  try {
    const original = await fixture.create('\ufefforiginal name'); await fixture.create('second entry');
    assert.equal(original.name, '\ufefforiginal name');
    const all = await fixture.store.sessionContinuity({ protocolVersion: 1, method: 'session.list', limit: 100 }, fixture.identity);
    assert(all.result.method === 'session.list');
    assert.equal(all.result.sessions.find(session => session.id === original.id)!.name, original.name);
    const first = await fixture.store.sessionContinuity({ protocolVersion: 1, method: 'session.list', limit: 1 }, fixture.identity);
    assert(first.result.method === 'session.list' && first.result.nextCursor);
    const request = { protocolVersion: 1, method: 'session.list', limit: 1, cursor: first.result.nextCursor } as const;
    const next = await fixture.store.sessionContinuity(request, fixture.identity); assert(next.result.method === 'session.list');
    assert.equal([...first.result.sessions, ...next.result.sessions].find(session => session.id === original.id)!.name, original.name);
    assert.deepEqual(canonicalJsonBytes(await fixture.store.sessionContinuity(request, fixture.identity)), canonicalJsonBytes(next));
  } finally { await fixture.close(); }
});

test('fork publishes atomically and retained first response remains replayable while new aliases obey sticky canonical time', async () => {
  const fixture = await listFixture('fork-time'), actualNow = Date.now;
  try {
    const parent = await fixture.create('fork-time-parent'), at = Date.now() + 1000; Date.now = () => at;
    const core = { protocolVersion: 1, method: 'session.fork', requestId: uuidv7(), admissionKey: admissionKey('fork-time-child'),
      sessionId: parent.id, expectedContextRevision: 1, throughItemSeq: 0 };
    const request = mutation(core);
    fixture.driver.exec(`CREATE TRIGGER fail_continuity BEFORE INSERT ON control_requests WHEN NEW.method='session.fork' BEGIN SELECT RAISE(ABORT,'original response commit refused'); END`);
    await assert.rejects(fixture.store.sessionContinuity(request, fixture.identity), /original response commit refused/);
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM sessions').get<{ n: bigint }>()!.n, 1n);
    assert.equal(fixture.driver.prepare("SELECT count(*) AS n FROM control_requests WHERE method='session.fork'").get<{ n: bigint }>()!.n, 0n);
    fixture.driver.exec('DROP TRIGGER fail_continuity');
    const original = await fixture.store.sessionContinuity(request, fixture.identity); assert(original.result.method === 'session.fork');
    const retainedChannel = fixture.driver.prepare("SELECT channel_identity_digest FROM control_requests WHERE method='session.fork' AND request_id=?")
      .get<{ channel_identity_digest: string }>(request.requestId)!;
    fixture.driver.transaction(connection => connection.prepare("UPDATE control_requests SET channel_identity_digest=? WHERE method='session.fork' AND request_id=?").run('f'.repeat(64), request.requestId));
    await assert.rejects(fixture.store.sessionContinuity(request, fixture.identity), { code: 'ARTIFACT_MISMATCH' }, 'today authenticated channel cannot repair changed original historical channel');
    fixture.driver.transaction(connection => connection.prepare("UPDATE control_requests SET channel_identity_digest=? WHERE method='session.fork' AND request_id=?").run(retainedChannel.channel_identity_digest, request.requestId));
    const alias = mutation({ ...core, requestId: uuidv7() });
    Date.now = () => at - 1;
    assert.deepEqual(await fixture.store.sessionContinuity(request, fixture.identity), original, 'retained replay requires no new permission or time observation');
    await assert.rejects(fixture.store.sessionContinuity(alias, fixture.identity), { code: 'INVALID_REQUEST' });
    assert.equal(readTimeFence(fixture.driver)!.state, 'clock_regressed');
    assert.equal(fixture.driver.prepare("SELECT count(*) AS n FROM control_requests WHERE method='session.fork'").get<{ n: bigint }>()!.n, 1n);
    Date.now = () => at + 1; await fixture.reopen();
    assert.deepEqual(await fixture.store.sessionContinuity(request, fixture.identity), original);
    await assert.rejects(fixture.store.sessionContinuity(alias, fixture.identity), { code: 'INVALID_REQUEST' });
    assert.equal(readTimeFence(fixture.driver)!.state, 'clock_regressed');
  } finally { Date.now = actualNow; await fixture.close(); }
});

test('canonical clock regression commits sticky fence; expiry at exactly fifteen minutes never revives after rollback or reopen', async () => {
  const fixture = await listFixture('clock'), originalNow = Date.now;
  try {
    await fixture.create('clock-first'); await fixture.create('clock-second');
    const at = Date.now() + 1000;
    Date.now = () => at;
    const request = { protocolVersion: 1, method: 'session.list', limit: 1 } as const;
    const first = await fixture.store.sessionContinuity(request, fixture.identity); assert(first.result.method === 'session.list' && first.result.nextCursor);
    const cursor = { ...request, cursor: first.result.nextCursor };
    Date.now = () => at - 1;
    await assert.rejects(fixture.store.sessionContinuity(cursor, fixture.identity), { code: 'INVALID_REQUEST' });
    assert.equal(readTimeFence(fixture.driver)!.state, 'clock_regressed');
    Date.now = () => at + 1;
    await assert.rejects(fixture.store.sessionContinuity(cursor, fixture.identity), { code: 'INVALID_REQUEST' });
    await fixture.reopen(); assert.equal(readTimeFence(fixture.driver)!.state, 'clock_regressed');
    fixture.driver.transaction(connection => recoverRegressedTimeFence(connection, fixture.store.ownerEpoch, new Date(at + 1).toISOString()));
    assert.equal((await fixture.store.sessionContinuity(cursor, fixture.identity)).result.method, 'session.list');
    Date.now = () => at + 15 * 60 * 1000;
    await assert.rejects(fixture.store.sessionContinuity(cursor, fixture.identity), { code: 'INVALID_REQUEST' });
    assert.equal(readTimeFence(fixture.driver)!.lastAcceptedAt, new Date(at + 15 * 60 * 1000).toISOString());
    Date.now = () => at + 1;
    await assert.rejects(fixture.store.sessionContinuity(cursor, fixture.identity), { code: 'INVALID_REQUEST' });
    assert.equal(readTimeFence(fixture.driver)!.state, 'clock_regressed', 'an expired-page refusal must commit its real high-water before throwing');
    Date.now = () => at + 15 * 60 * 1000;
    fixture.driver.transaction(connection => recoverRegressedTimeFence(connection, fixture.store.ownerEpoch, new Date(Date.now()).toISOString()));
    const fresh = await fixture.store.sessionContinuity(request, fixture.identity); assert(fresh.result.method === 'session.list');
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get<{ n: bigint }>()!.n, 1n, 'only expired cache rows are collected');
    Date.now = () => at + 1;
    await assert.rejects(fixture.store.sessionContinuity(cursor, fixture.identity), { code: 'INVALID_REQUEST' });
    assert.equal(readTimeFence(fixture.driver)!.state, 'clock_regressed');
  } finally { Date.now = originalNow; await fixture.close(); }
});

test('complete list cut enforces actual 100000-row and 64 MiB boundaries without publishing a partial cache', async t => {
  const fixture = await listFixture('capacity');
  let stage = 'fixture_seed'; const samples: Array<{ stage: string; operation: string; synchronousMs: number }> = [];
  const prototype = Object.getPrototypeOf(fixture.driver);
  for (const operation of ['transaction', 'readSnapshot', 'exec']) {
    const original = prototype[operation];
    t.mock.method(prototype, operation, function (this: unknown, ...args: unknown[]) {
      const start = process.hrtime.bigint();
      try { return Reflect.apply(original, this, args); }
      finally { samples.push({ stage, operation, synchronousMs: Number(process.hrtime.bigint() - start) / 1e6 }); }
    });
  }
  try {
    const original = await fixture.create('capacity-source');
    // Typed display metadata only. These rows create no Run, native proof,
    // context graph, execution lease or right to admit; production Store SQL
    // still performs the complete public cut and its fixed capacity checks.
    fixture.driver.transaction(connection => {
      connection.prepare(`WITH RECURSIVE counter(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM counter WHERE n<100000)
        INSERT INTO sessions(id,workspace_identity_ref,name,parent_session_id,forked_through_item_seq,context_revision,latest_item_seq,context_projection_ref,
        created_at,updated_at,principal_id,admission_method,admission_key,admission_intent_digest,admission_request_id)
        SELECT printf('display-%06d',n),?,NULL,NULL,NULL,1,0,?,?,?,?,'display_fixture',printf('display-%06d',n),?,NULL FROM counter`)
        .run(original.workspaceIdentityRef, original.contextProjectionRef, original.createdAt, original.updatedAt, fixture.identity.principalId, original.contextProjectionRef);
    });
    const list = { protocolVersion: 1, method: 'session.list', limit: 100 } as const;
    stage = 'row_limit_refusal';
    await assert.rejects(fixture.store.sessionContinuity(list, fixture.identity), error => error instanceof ListCutCapacityError);
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get<{ n: bigint }>()!.n, 0n);
    stage = 'fixture_update'; fixture.driver.transaction(connection => connection.prepare('DELETE FROM sessions WHERE id=?').run(original.id));
    stage = 'exact_capacity_materialization';
    const exact = await fixture.store.sessionContinuity(list, fixture.identity); assert(exact.result.method === 'session.list' && exact.result.nextCursor);
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cut_entries').get<{ n: bigint }>()!.n, 100000n);
    const cutCount = fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get<{ n: bigint }>()!.n;
    stage = 'exact_capacity_old_page';
    const page = await fixture.store.sessionContinuity({ ...list, cursor: exact.result.nextCursor }, fixture.identity); assert(page.result.method === 'session.list');
    assert.equal(page.result.sessions.length, 100); assert.equal(page.result.sessions[0]!.id, 'display-000101');
    stage = 'fixture_update';
    const sample = { ...exact.result.sessions[0]!, name: 'n', parentSessionId: 'p'.repeat(128) };
    const fixedBytes = canonicalJsonBytes({ method: 'session.list', value: sample }).length - 1;
    const nameBytes = Math.floor((64 * 1024 * 1024) / 100000) - fixedBytes;
    assert(nameBytes >= 1 && nameBytes < 256);
    const extra = 64 * 1024 * 1024 - 100000 * (fixedBytes + nameBytes);
    fixture.driver.transaction(connection => {
      connection.prepare('UPDATE sessions SET name=?,parent_session_id=?,forked_through_item_seq=0').run('n'.repeat(nameBytes), 'p'.repeat(128));
      connection.prepare('UPDATE sessions SET name=name||? WHERE id IN(SELECT id FROM sessions ORDER BY id LIMIT ?)').run('x', extra);
    });
    stage = 'exact_byte_capacity_materialization';
    const exactBytes = await fixture.store.sessionContinuity(list, fixture.identity); assert(exactBytes.result.method === 'session.list' && exactBytes.result.nextCursor);
    const exactCut = JSON.parse(Buffer.from(exactBytes.result.nextCursor, 'base64url').toString('utf8')).cutId;
    assert.equal(fixture.driver.prepare('SELECT sum(length(CAST(payload_json AS BLOB))) AS bytes FROM list_read_cut_entries WHERE cut_id=?').get<{ bytes: bigint }>(exactCut)!.bytes, 64n * 1024n * 1024n);
    const beforeByteRefusal = fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get<{ n: bigint }>()!.n;
    assert.equal(beforeByteRefusal, cutCount + 1n);
    stage = 'fixture_update'; fixture.driver.transaction(connection => connection.prepare("UPDATE sessions SET name=name||'x' WHERE id='display-100000'").run());
    stage = 'byte_limit_refusal';
    await assert.rejects(fixture.store.sessionContinuity(list, fixture.identity), error => error instanceof ListCutCapacityError);
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cuts').get<{ n: bigint }>()!.n, beforeByteRefusal);
    assert.equal(fixture.driver.prepare('SELECT count(*) AS n FROM list_read_cut_entries').get<{ n: bigint }>()!.n, 200000n);
    // Execute the original production read-only digest expression against a
    // real 100000-ref SQL index. Opaque data refs qualify this loop only, not
    // 100000 physical workspace identities or execution permission.
    const sourceText = await readFile(new URL('./list-read-cut.ts', import.meta.url), 'utf8');
    const parsed = ts.createSourceFile('list-read-cut.ts', sourceText, ts.ScriptTarget.Latest, true);
    const digestFunction = parsed.statements.find((node): node is ts.FunctionDeclaration => ts.isFunctionDeclaration(node) && node.name?.text === 'workspaceRefDigest');
    assert(digestFunction);
    const invoke = Function('createHash', 'canonicalJsonBytes', 'corrupt', ts.transpileModule(digestFunction.getText(parsed) + ';return workspaceRefDigest;',
      { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText)(createHash, canonicalJsonBytes,
        () => { throw new Error('original distinct-ref digest refused its real data fixture'); }) as (connection: any, principal: string) => string;
    stage = 'fixture_update'; fixture.driver.transaction(connection => connection.exec("UPDATE sessions SET workspace_identity_ref=printf('%064x',CAST(substr(id,9) AS INTEGER))"));
    stage = 'filtered_100000_distinct_ref_digest';
    const refDigest = fixture.driver.readSnapshot(connection => invoke(connection, fixture.identity.principalId));
    assert.equal(refDigest, canonicalSha256(Array.from({ length: 100000 }, (_, index) => (index + 1).toString(16).padStart(64, '0'))));
    stage = 'fixture_restore'; fixture.driver.transaction(connection => {
      connection.prepare('UPDATE sessions SET workspace_identity_ref=?').run(original.workspaceIdentityRef);
      connection.prepare("UPDATE sessions SET name=substr(name,1,length(name)-1) WHERE id='display-100000'").run();
    });
    stage = 'filtered_exact_byte_capacity_materialization';
    const filtered = await fixture.store.sessionContinuity({ ...list, workspacePath: fixture.workspace }, fixture.identity);
    assert(filtered.result.method === 'session.list' && filtered.result.nextCursor); assert.equal(filtered.result.sessions.length, 100);
    t.diagnostic(JSON.stringify({ diagnosticOnly: true, kind: 'session_list_actual_synchronous_segments', nodeVersion: process.version, samples,
      hostLoadControlled: false, twoSecondInstalledStopQualified: false }));
    t.mock.restoreAll(); await fixture.store.close();
    const stops = [];
    for (const phase of ['capture', 'prepare', 'final'] as const) {
      const stopped = await stopActualListChild(fixture.stateRoot, phase, text => t.diagnostic(text)); stops.push(stopped);
      assert.equal(fixture.driver.prepare('SELECT state FROM state_owners WHERE owner_epoch=?').get(stopped.ownerEpoch)?.state, 'terminal');
      assert.equal(fixture.driver.prepare("SELECT count(*) AS n FROM state_owners WHERE state='active'").get<{ n: bigint }>()!.n, 0n);
      for (const cut of fixture.driver.prepare('SELECT c.cut_id,count(e.ordinal) AS n FROM list_read_cuts c LEFT JOIN list_read_cut_entries e ON e.cut_id=c.cut_id GROUP BY c.cut_id').all<{ cut_id: string; n: bigint }>())
        assert.equal(cut.n, 100000n, 'real cancellation never publishes a partial list cut');
    }
    t.diagnostic(JSON.stringify({ diagnosticOnly: true, kind: 'session_list_actual_sigterm_join', hostLoadControlled: false, stops,
      twoSecondInstalledStopQualified: false }));
  } finally { t.mock.restoreAll(); await fixture.close(); }
});
