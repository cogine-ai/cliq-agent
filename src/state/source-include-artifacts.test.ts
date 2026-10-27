import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { AuthorizationConsumptionReceiptV1 } from '../kernel/authorization.js';
import { decodeSourceIncludeAuthorization, readSourceIncludeGrantReceipt } from './source-include-artifacts.js';

const ref = (letter: string) => letter.repeat(64);
const createdAt = '2026-10-27T00:00:00.000Z';
const common = { schemaVersion: 1, format: 'cliq-source-include-authorization-v1', principalId: 'principal',
  inspectionId: 'inspection', runId: 'run', sessionId: 'session', workspaceIdentityRef: ref('a'), workspaceIdentityDigest: ref('b'),
  selector: { path: 'ignored/source', scope: 'subtree' },
  selectorDigest: canonicalSha256({ path: 'ignored/source', scope: 'subtree' }),
  admissionIntentDigest: ref('c'), capturedEntriesRef:ref('8'), capturedTreeDigest:ref('9'), createdAt };
const seal = <T extends object>(core: T) => ({ ...core,
  authorizationDigest: digestOmitting({ ...core, authorizationDigest: '' }, 'authorizationDigest') });
const receipt = (changes: Partial<AuthorizationConsumptionReceiptV1> = {}): AuthorizationConsumptionReceiptV1 => {
  const value: AuthorizationConsumptionReceiptV1 = { schemaVersion: 1, grantId: 'read-grant', ownerPrincipalId: common.principalId,
    targetDigest: ref('d'), consumer: { kind: 'source_inspection', inspectionId: common.inspectionId, admissionIntentDigest: common.admissionIntentDigest },
    consumedAt: createdAt, receiptDigest: '', ...changes };
  value.receiptDigest = digestOmitting(value, 'receiptDigest'); return value;
};
const grantAuthorization = (value = receipt()) => seal({ ...common, kind: 'consumed_user_read_grant',
  authorizationGrantId: value.grantId, authorizationGrantTargetDigest: value.targetDigest,
  consumedGrantSnapshotRef:ref('0'),
  consumptionReceiptRef: canonicalSha256(value), consumptionReceiptDigest: value.receiptDigest });

test('include authorization retains the two exact data branches and cannot claim capture or execution authority', () => {
  const builtin = seal({ ...common, kind: 'builtin_nonignored', frozenIgnoreRulesRef: ref('e'), frozenIgnoreRulesDigest: ref('f'),
    classification: 'tracked_or_nonignored_in_root', classificationEvidenceRef: ref('1'), classificationEvidenceDigest: ref('2') });
  for (const value of [builtin, grantAuthorization()]) {
    assert.deepEqual(decodeSourceIncludeAuthorization(value), value);
    assert(Object.isFrozen(decodeSourceIncludeAuthorization(value).selector));
    for (const field of ['nativeProof', 'trusted', 'readGrantId', 'execute', 'classificationEvidenceRef']) {
      if (field in value) continue;
      assert.throws(() => decodeSourceIncludeAuthorization(seal({ ...value, [field]: true })), TypeError);
    }
  }
  assert.throws(() => decodeSourceIncludeAuthorization(seal({ ...builtin,
    authorizationGrantId: 'read-grant', consumptionReceiptRef: ref('3') })), TypeError);
  assert.throws(() => decodeSourceIncludeAuthorization({ ...builtin, authorizationDigest: ref('4') }), TypeError);
});

test('include selectors are exact source paths, never Git metadata, external paths, or altered selector digests', () => {
  const base = grantAuthorization();
  for (const path of ['../secret', '/outside', '.git/config', 'nested/.GIT/objects', 'a\\b', 'a//b', 'a/', 'e\u0301']) {
    const selector = { path, scope: 'entry' };
    assert.throws(() => decodeSourceIncludeAuthorization(seal({ ...base, selector, selectorDigest: canonicalSha256(selector) })), TypeError);
  }
  assert.throws(() => decodeSourceIncludeAuthorization(seal({ ...base, selectorDigest: ref('5') })), TypeError);
  assert.throws(() => decodeSourceIncludeAuthorization(seal({ ...base,
    selector: { ...base.selector, readGrantId: 'caller' } })), TypeError);
});

test('a user include binds both full receipt bytes and its semantic digest to this exact original capture', () => {
  const value = receipt(), authorization = grantAuthorization(value);
  assert.deepEqual(readSourceIncludeGrantReceipt(authorization, value), value);
  const changes: Partial<AuthorizationConsumptionReceiptV1>[] = [
    { grantId: 'other' }, { ownerPrincipalId: 'other' }, { targetDigest: ref('6') },
    { consumer: { kind: 'source_inspection', inspectionId: 'other', admissionIntentDigest: common.admissionIntentDigest } },
    { consumer: { kind: 'source_inspection', inspectionId: common.inspectionId, admissionIntentDigest: ref('7') } },
    { consumer: { kind: 'run_admission', runId: common.runId, admissionIntentDigest: common.admissionIntentDigest } },
    { consumedAt: '2026-10-27T00:00:00.001Z' }
  ];
  for (const change of changes) {
    const changed = receipt(change);
    const rebound = seal({ ...authorization, consumptionReceiptRef: canonicalSha256(changed), consumptionReceiptDigest: changed.receiptDigest });
    assert.doesNotThrow(() => decodeSourceIncludeAuthorization(rebound));
    assert.throws(() => readSourceIncludeGrantReceipt(rebound, changed), TypeError);
  }
  assert.throws(() => readSourceIncludeGrantReceipt(seal({ ...authorization,
    consumptionReceiptRef: value.receiptDigest }), value), TypeError, 'semantic digest is not the full CAS ref');
  assert.throws(() => readSourceIncludeGrantReceipt(seal({ ...authorization,
    consumptionReceiptDigest: canonicalSha256(value) }), value), TypeError);
  assert.deepEqual(readSourceIncludeGrantReceipt(seal({ ...authorization,
    createdAt: '2026-10-27T00:00:00.005Z' }), value), value,
  'the real capture transaction may follow its original receipt preparation');
});

test('include data rejects proxies and accessors without invoking them', () => {
  let accessed = 0;
  const value = grantAuthorization(), accessor = { ...value };
  Object.defineProperty(accessor, 'selector', { enumerable: true, get() { accessed++; return value.selector; } });
  assert.throws(() => decodeSourceIncludeAuthorization(accessor), TypeError);
  const proxy = new Proxy(value, { get() { accessed++; return undefined; },
    getPrototypeOf() { accessed++; return Object.prototype; }, ownKeys() { accessed++; return []; } });
  assert.throws(() => decodeSourceIncludeAuthorization(proxy), TypeError);
  assert.throws(() => readSourceIncludeGrantReceipt(value, new Proxy(receipt(), {
    ownKeys() { accessed++; return []; } })), TypeError);
  assert.equal(accessed, 0);
});
