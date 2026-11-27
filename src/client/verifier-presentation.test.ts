import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { readWaitingPresentation } from './artifacts.js';
import { readVerifierWaitingPresentation } from './verifier-presentation.js';
import { verifierPresentationData } from './testing/verifier-presentation-data.js';

// These exercise actual bounded, content-addressed display reads over inert
// DTOs, not native execution, registered authorization or installed evidence.
for (const operation of ['agent', 'delivery'] as const) for (const required of [true, false])
  test(`${operation} ${required ? 'required' : 'advisory'} verifier wait shows its original command, exact source and denial consequence`, async () => {
    const fixture = verifierPresentationData({ operation, required });
    const view = await readWaitingPresentation(fixture.app, fixture.snapshot);
    assert.equal(view.waitingOnRef, fixture.snapshot.run.waitingOnRef);
    assert.match(view.text, /Command: node "--test" "--test-concurrency=1" "test\/check.mjs"/u);
    assert.match(view.text, /Candidate: "inert-candidate"/u);
    assert.match(view.text, new RegExp(`Source SHA-256: ${'a'.repeat(64)}`, 'u'));
    assert.match(view.text, /read-only source, no network; up to 1 dispatched attempt for this candidate/u);
    assert.match(view.text, required ? /Deny cancels this Run/u : /Deny skips this advisory check/u);
    assert.equal(new Set(fixture.reads).size, fixture.reads.length, 'one captured display does not reopen its immutable graph');
  });

for (const [kind, changed] of [
  ['evidence', { effectiveDisposition: 'allow' }], ['evidence', { principalId: 'different-principal' }],
  ['evidence', { namedAction: { kind: 'verifier', candidateItemId: 'different-candidate', verifierPlanRef: 'a'.repeat(64), verifierId: 'node-tests' } }],
  ['request', { assemblyRef: 'b'.repeat(64) }], ['request', { candidateItemId: 'different-candidate' }],
  ['target', { required: false }], ['target', { verifierVersion: 'different-version' }], ['target', { maxAttempts: 2 }],
  ['target', { resultSourceRef: 'b'.repeat(64) }], ['frontier', { nextVerifierIndex: 1 }], ['frontier', { afterPass: 'delivery_approval' }],
  ['entry', { gate: 'advisory' }], ['entry', { timeoutMs: 999 }], ['policy', { principalId: 'different-principal' }],
  ['command', { argv: [{ kind: 'non_secret_literal', value: '-e' }] }],
  ['command', { argv: ['--test', '--test-concurrency=1', '../outside.mjs'].map(value => ({ kind: 'non_secret_literal', value })) }],
  ['command', { extra: 'not a declared command field' }], ['environment', { variables: [{ name: 'SECRET', value: { kind: 'non_secret_literal', value: 'untrusted' } }] }],
  ['environment', { networkAccess: 'allowed' }], ['environment', { sourceProjectionRef: 'b'.repeat(64) }],
  ['environment', { guestToolchainManifestDigest: 'b'.repeat(64) }]
] as Array<[string, Record<string, unknown>]>)
  test(`verifier display rejects a rehashed ${kind} substitution ${Object.keys(changed).join(',')}`, async () => {
    const fixture = verifierPresentationData({ change: (node, value) => node === kind ? { ...value, ...changed } : value });
    await assert.rejects(readVerifierWaitingPresentation(fixture.app, fixture.snapshot, fixture.wait), TypeError);
  });

test('verifier presentation rejects replacement bytes and a changed snapshot without permitting an automatic approval', async () => {
  const fixture = verifierPresentationData();
  fixture.objects.set(fixture.refs.command!, canonicalJsonBytes({ ...fixture.values.command, cwd: 'elsewhere' }));
  await assert.rejects(readWaitingPresentation(fixture.app, fixture.snapshot), /complete original bytes/u);
  fixture.objects.set(fixture.refs.command!, canonicalJsonBytes(fixture.values.command));
  await assert.rejects(readVerifierWaitingPresentation(fixture.app, { ...fixture.snapshot,
    run: { ...fixture.snapshot.run, frontierRef: 'b'.repeat(64) } }, fixture.wait), /captured Run/u);
  const abort = new AbortController(), reason = new Error('original client closed'); abort.abort(reason);
  const before = fixture.reads.length;
  await assert.rejects(readVerifierWaitingPresentation(fixture.app, fixture.snapshot, fixture.wait, abort.signal), error => error === reason);
  assert.equal(fixture.reads.length, before);
});
