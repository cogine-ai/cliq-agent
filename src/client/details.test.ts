import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { ContentAddressedStore } from '../state/cas.js';
import type { InstalledControlResponseFor } from '../control/v1.js';
import { artifactText, detailViewport, presentControlArtifacts, type ClientDetail } from './details.js';

// Real source bytes/CAS and existing production closed data decoders only.
// These fixtures create no accepted Run, grant, verifier or native proof.
async function fixture() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-client-details-')), objects = path.join(home, 'objects');
  await mkdir(objects, { mode: 0o700 }); const cas = new ContentAddressedStore(objects), ref = canonicalSha256('inert source');
  const store = async (value: unknown) => cas.publish(canonicalJsonBytes(value));
  const summaryCore = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8: 'Actual committed summary.', byteCount: 25 };
  const summary = { ...summaryCore, textDigest: canonicalSha256(summaryCore) };
  const summaryRef = await store(summary);
  const diffCore = { schemaVersion: 1, format: 'cliq-workspace-diff-v1', baseSourceRef: ref, resultSourceRef: ref, operations: [] };
  const diff = { ...diffCore, diffDigest: canonicalSha256(diffCore) }, diffRef = await store(diff);
  const closureCore = { schemaVersion: 1, format: 'cliq-verification-closure-v1', runId: 'run', candidateItemId: 'candidate',
    resultSourceRef: ref, verifierPlanRef: ref, dependency: { kind: 'none' },
    verification: { kind: 'local', outcome: 'unverified', entries: [], unverifiedConsentRef: ref }, createdAt: '2026-10-26T00:00:00.000Z' };
  const closure = { ...closureCore, closureDigest: canonicalSha256(closureCore) }, closureRef = await store(closure);
  const result = { schemaVersion: 1, runId: 'run', baseSourceRef: ref, resultSourceRef: ref, diffRef,
    verificationClosureRef: closureRef, verificationReceiptRefs: [], summaryRef, createdAt: closure.createdAt }, resultRef = await store(result);
  const descriptor = async (ref: string) => ({ schemaVersion: 1 as const, ref, digest: ref, sizeBytes: (await cas.read(ref)).length, mediaType: 'application/json' });
  const app = { artifact: async (ref: string, options: { maxBytes: number; signal?: AbortSignal }) => {
    const bytes = await cas.read(ref, options.signal); assert(bytes.length <= options.maxBytes); return bytes;
  } };
  return { home, cas, ref, store, summary, summaryRef, diffRef, closure, closureRef, result, resultRef, descriptor, app };
}

test('result detail reads complete original CAS, its strict closure and committed summary without making authority', async () => {
  const f = await fixture();
  try {
    const response = { protocolVersion: 1, ok: true, result: { method: 'run.result', runId: 'run', result: await f.descriptor(f.resultRef),
      verificationClosureRef: f.closureRef } } as const;
    const shown: ClientDetail[] = [];
    await presentControlArtifacts(f.app, { protocolVersion: 1, method: 'run.result', runId: 'run' }, response, value => { shown.push(value); });
    assert.deepEqual(shown.map(value => value.artifactRef), [f.resultRef, f.closureRef, f.summaryRef]);
    assert.equal(shown.at(-1)!.text, f.summary.utf8);
    assert.equal(shown[0]!.text, canonicalJsonBytes(f.result).toString('utf8'));
    const wrong = { ...response, result: { ...response.result, result: { ...response.result.result, sizeBytes: 1 } } };
    await assert.rejects(presentControlArtifacts(f.app, { protocolVersion: 1, method: 'run.result', runId: 'run' }, wrong, () => {}), /descriptor/u);
    const foreign = { ...f.result, runId: 'foreign' }, foreignRef = await f.store(foreign);
    await assert.rejects(presentControlArtifacts(f.app, { protocolVersion: 1, method: 'run.result', runId: 'run' },
      { ...response, result: { ...response.result, result: await f.descriptor(foreignRef) } }, () => {}), /original selection/u);
    const diff: InstalledControlResponseFor<'run.diff'> = { protocolVersion: 1, ok: true, result: { method: 'run.diff', runId: 'run', diff: await f.descriptor(f.diffRef) } };
    await presentControlArtifacts(f.app, { protocolVersion: 1, method: 'run.diff', runId: 'run' }, diff, value => { assert.equal(value.artifactRef, f.diffRef); });
  } finally { await rm(f.home, { recursive: true, force: true }); }
});

test('handoff display binds the captured Session revision and original downloaded Markdown bytes', async () => {
  const f = await fixture();
  try {
    const core = { schemaVersion: 1, format: 'cliq-session-handoff-v1', sessionId: 'session', workspaceIdentityRef: f.ref,
      workspaceIdentityDigest: f.ref, contextRevision: 3, throughItemSeq: 0, contextProjectionRef: f.ref,
      contextProjectionDigest: f.ref, entries: [], excludedRanges: [] };
    const handoff = { ...core, handoffDigest: canonicalSha256(core) }, jsonRef = await f.store(handoff);
    const markdown = '# Cliq Session Handoff\n\nOriginal fixed bytes.\n', markdownRef = await f.cas.publish(Buffer.from(markdown));
    const response = { protocolVersion: 1, ok: true, result: { method: 'session.handoff.create', json: await f.descriptor(jsonRef), markdown: await f.descriptor(markdownRef) } } as const;
    const request = { protocolVersion: 1, method: 'session.handoff.create', sessionId: 'session', expectedContextRevision: 3 } as const;
    await presentControlArtifacts(f.app, request, response, value => { assert.equal(value.text, markdown); assert.equal(value.artifactRef, markdownRef); });
    await assert.rejects(presentControlArtifacts(f.app, { ...request, expectedContextRevision: 4 }, response, () => {}), /original cut/u);
    const changed = { ...handoff, sessionId: 'foreign' }; changed.handoffDigest = digestOmitting(changed, 'handoffDigest');
    await assert.rejects(presentControlArtifacts(f.app, request, { ...response, result: { ...response.result, json: await f.descriptor(await f.store(changed)) } }, () => {}), /original cut/u);
    const viewport = detailViewport({ label: 'large', artifactRef: f.ref, text: 'x'.repeat(65535) + '😀trailing' });
    assert.match(viewport.text, /view clipped/u); assert.doesNotThrow(() => canonicalJsonBytes(viewport));
    assert.match(artifactText(Buffer.from([255])), /Binary artifact/u);
    assert.equal(artifactText(Buffer.from('\ufefftext')), '\ufefftext');
  } finally { await rm(f.home, { recursive: true, force: true }); }
});
