// Closed retained data only, not verifier execution/retirement qualification.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { VerificationClosureV1 } from '../kernel/result.js';
import { decodeRunResult, decodeVerificationClosure } from './result-artifacts.js';

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
