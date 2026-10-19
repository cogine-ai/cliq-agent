// Closed retained data only, not verifier execution/retirement qualification.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { InheritedVerificationProvenanceV1, VerificationClosureV1 } from '../kernel/result.js';
import { decodeInheritedVerificationProvenance, decodeRunResult, decodeVerificationClosure } from './result-artifacts.js';

function closure(required = true): VerificationClosureV1 {
  const ref = canonicalSha256;
  const value: VerificationClosureV1 = { schemaVersion: 1, format: 'cliq-verification-closure-v1', runId: 'run', candidateItemId: 'candidate',
    resultSourceRef: ref('result'), verifierPlanRef: ref('plan'), dependency: { kind: 'none' }, verification: { kind: 'local',
      outcome: required ? 'verified' : 'unverified', ...(required ? {} : { unverifiedConsentRef: ref('consent') }), entries: [{
        verifierIndex: 0, verifierId: 'tests', verifierSpecDigest: ref('spec-digest'), verifierEntryDigest: ref('entry-digest'), required,
        disposition: { kind: 'passed', verifierResultItemId: 'result-item', opId: 'op', attempt: 0, completedJournalSeq: 7, receiptRef: ref('receipt') }
      }] }, createdAt: '2026-10-18T00:00:00.000Z', closureDigest: '' };
  value.closureDigest = digestOmitting(value, 'closureDigest'); return value;
}
test('local verification closure admits exact required passes and consent-backed advisory outcomes in plan order', () => {
  const verified = closure(); assert.deepEqual(decodeVerificationClosure(verified), verified);
  const unverified = closure(false);
  if (unverified.verification.kind !== 'local') assert.fail();
  unverified.verification.entries[0]!.disposition = { kind: 'advisory_nonpassing', outcome: 'infra_failed', verifierResultItemId: 'result-item',
    opId: 'op', attempt: 0, terminalJournalSeq: 7, receiptRef: canonicalSha256('receipt') };
  unverified.closureDigest = digestOmitting(unverified, 'closureDigest');
  assert.deepEqual(decodeVerificationClosure(unverified), unverified);
  const result = { schemaVersion: 1, runId: 'run', baseSourceRef: canonicalSha256('base'), resultSourceRef: verified.resultSourceRef,
    diffRef: canonicalSha256('diff'), verificationClosureRef: canonicalSha256(verified), verificationReceiptRefs: [canonicalSha256('receipt')],
    summaryRef: canonicalSha256('summary'), createdAt: verified.createdAt };
  assert.deepEqual(decodeRunResult(result), result);
  assert.throws(() => decodeRunResult({ ...result, verificationReceiptRefs: [...result.verificationReceiptRefs, ...result.verificationReceiptRefs] }));
});
test('verification closure rejects contradictory status, nonpassed required evidence and duplicate/unordered ownership', () => {
  const mutations: Array<(value: any) => void> = [
    value => { value.verification.outcome = 'unverified'; },
    value => { value.verification.unverifiedConsentRef = canonicalSha256('consent'); },
    value => { value.verification.entries[0].required = false; },
    value => { value.verification.entries[0].verifierIndex = 1; },
    value => { value.verification.entries[0].disposition.completedJournalSeq = 0; },
    value => { value.verification.entries[0].disposition.extraAuthority = true; },
    value => { value.verification.entries[0].disposition = { kind: 'advisory_nonpassing', outcome: 'assertion_failed',
      verifierResultItemId: 'result-item', opId: 'op', attempt: 0, terminalJournalSeq: 7, receiptRef: canonicalSha256('receipt') }; },
    value => { value.verification.entries.push({ ...value.verification.entries[0], verifierIndex: 1 }); },
    value => { value.verification.entries[0].disposition = { kind: 'advisory_skipped', verifierSkipItemId: 'skip', decisionRef: canonicalSha256('decision') }; },
  ];
  for (const mutate of mutations) { const value = structuredClone(closure()); mutate(value); value.closureDigest = digestOmitting(value, 'closureDigest');
    assert.throws(() => decodeVerificationClosure(value)); }
  const noConsent = closure(false);
  if (noConsent.verification.kind !== 'local') assert.fail();
  delete noConsent.verification.unverifiedConsentRef; noConsent.closureDigest = digestOmitting(noConsent, 'closureDigest');
  assert.throws(() => decodeVerificationClosure(noConsent));
});

test('delivery inherited closure and provenance retain exact closed source identities without relabeling receipts', () => {
  const reference = canonicalSha256;
  const provenance: InheritedVerificationProvenanceV1 = { schemaVersion: 1, format: 'cliq-inherited-verification-provenance-v1',
    deliveryRunId: 'delivery', sourceRunId: 'source', sourceRunResultRef: reference('result'), sourceRunResultDigest: reference('result'),
    sourceVerificationClosureRef: reference('source-closure'), sourceVerificationClosureDigest: reference('closure-digest'),
    resultSourceRef: reference('source'), verifierSpecRef: reference('spec'), verifierSpecDigest: reference('spec-digest'),
    verificationReceiptRefs: [reference('receipt')], verificationReceiptDigests: [reference('receipt-digest')],
    createdAt: '2026-10-18T00:00:00.000Z', provenanceDigest: '' };
  provenance.provenanceDigest = digestOmitting(provenance, 'provenanceDigest');
  assert.deepEqual(decodeInheritedVerificationProvenance(provenance), provenance);
  const inherited: VerificationClosureV1 = { ...closure(), runId: 'delivery', verification: { kind: 'inherited_verified',
    sourceRunId: provenance.sourceRunId, sourceRunResultRef: provenance.sourceRunResultRef,
    sourceVerificationClosureRef: provenance.sourceVerificationClosureRef, inheritedProvenanceRef: reference(provenance) } };
  inherited.closureDigest = digestOmitting(inherited, 'closureDigest');
  assert.deepEqual(decodeVerificationClosure(inherited), inherited);
  for (const changed of [{ ...provenance, sourceRunId: 'delivery' }, { ...provenance, verificationReceiptDigests: [] },
    { ...provenance, verificationReceiptRefs: [...provenance.verificationReceiptRefs, ...provenance.verificationReceiptRefs],
      verificationReceiptDigests: [...provenance.verificationReceiptDigests, ...provenance.verificationReceiptDigests] },
    { ...provenance, sourceRunResultDigest: reference('other') }, { ...provenance, extra: true }]) {
    changed.provenanceDigest = digestOmitting(changed, 'provenanceDigest');
    assert.throws(() => decodeInheritedVerificationProvenance(changed));
  }
  for (const verification of [{ ...inherited.verification, sourceRunId: 'delivery' },
    { ...inherited.verification, entries: [] }, { ...inherited.verification, unverifiedConsentRef: reference('consent') }]) {
    const changed = { ...inherited, verification }; changed.closureDigest = digestOmitting(changed, 'closureDigest');
    assert.throws(() => decodeVerificationClosure(changed));
  }
  let observed = false;
  const accessor = Object.defineProperty({}, 'kind', { enumerable: true, get() { observed = true; return 'inherited_verified'; } });
  assert.throws(() => decodeVerificationClosure({ ...inherited, verification: accessor }));
  assert.equal(observed, false);
  const hidden = Object.defineProperty({ ...provenance }, 'sourceRunId', { value: 'source', enumerable: false });
  assert.throws(() => decodeInheritedVerificationProvenance(hidden));
  const sparse = { ...provenance, verificationReceiptDigests: Array(1) };
  assert.throws(() => decodeInheritedVerificationProvenance(sparse));
});

test('RunResult admits only exact optional delivery proof refs, never fields that imply source authority', () => {
  const reference = canonicalSha256;
  const result = { schemaVersion: 1, runId: 'delivery', baseSourceRef: reference('base'), resultSourceRef: reference('result'),
    diffRef: reference('diff'), verificationClosureRef: reference('closure'), verificationReceiptRefs: [reference('receipt')],
    verificationProvenanceRef: reference('provenance'), deliveryTerminalProjectionEvidenceRef: reference('projection'),
    summaryRef: reference('summary'), createdAt: '2026-10-18T00:00:00.000Z' };
  assert.deepEqual(decodeRunResult(result), result);
  for (const changed of [{ ...result, deliveryTerminalProjectionEvidenceRef: 'not-a-ref' }, { ...result, verificationProvenanceRef: undefined },
    { ...result, sourceRunId: 'source' }, { ...result, dependencyPlanRef: reference('unsupported-dependency') }])
    assert.throws(() => decodeRunResult(changed));
});
