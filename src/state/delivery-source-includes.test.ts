// Immutable selection data only. These values do not consume a grant or
// create a captured source, verified Delivery, Run or native proof.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeSourceIncludeAuthorization } from './source-include-artifacts.js';
import { deliverySourceIncludes } from './delivery-source-includes.js';
import type { SourceProjectionSpec } from '../kernel/types.js';

const ref = 'a'.repeat(64);
function authorization(path: string, user: boolean) {
  const common = { schemaVersion: 1, format: 'cliq-source-include-authorization-v1', principalId: 'principal',
    inspectionId: 'original', runId: 'planned-original', sessionId: 'session', workspaceIdentityRef: ref,
    workspaceIdentityDigest: ref, selector: { path, scope: 'entry' }, selectorDigest: canonicalSha256({ path, scope: 'entry' }),
    admissionIntentDigest: ref, capturedEntriesRef:ref, capturedTreeDigest:ref,
    createdAt: '2026-10-27T00:00:00.000Z', authorizationDigest: '' };
  const value = user ? { ...common, kind: 'consumed_user_read_grant', authorizationGrantId: `old-${path}`,
    authorizationGrantTargetDigest: ref, consumedGrantSnapshotRef:ref, consumptionReceiptRef: ref, consumptionReceiptDigest: ref }
    : { ...common, kind: 'builtin_nonignored', frozenIgnoreRulesRef: ref, frozenIgnoreRulesDigest: ref,
      classification: 'tracked_or_nonignored_in_root', classificationEvidenceRef: ref, classificationEvidenceDigest: ref };
  value.authorizationDigest = digestOmitting(value, 'authorizationDigest');
  return decodeSourceIncludeAuthorization(value);
}
const authorizations = [authorization('ordinary', false), authorization('ignored-one', true), authorization('ignored-two', true)];
const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1', frozenIgnoreRulesRef: ref,
  frozenIgnoreRulesDigest: ref, explicitIncludes: authorizations.map(value => ({ ...value.selector, authorizationRef: canonicalSha256(value) })),
  explicitExcludes: [], maxChangedPaths: 10000, maxChangedBytes: 512 * 1024 ** 2, projectionDigest: '' };
projection.projectionDigest = digestOmitting(projection, 'projectionDigest');

test('fresh Delivery grant locators follow the original user selectors without changing builtin scopes', () => {
  const selected = deliverySourceIncludes(projection, authorizations, ['fresh-one', 'fresh-two']);
  assert.deepEqual(selected, [{ path: 'ordinary', scope: 'entry' },
    { path: 'ignored-one', scope: 'entry', readGrantId: 'fresh-one' },
    { path: 'ignored-two', scope: 'entry', readGrantId: 'fresh-two' }]);
  assert(Object.isFrozen(selected) && selected.every(Object.isFrozen));
  assert.deepEqual(deliverySourceIncludes({ ...projection, explicitIncludes: [projection.explicitIncludes[0]!] },
    [authorizations[0]!], []), [{ path: 'ordinary', scope: 'entry' }]);
});

test('missing, extra, reused, duplicate or retargeted Delivery source consent cannot change the original selection', () => {
  for (const ids of [[], ['only-one'], ['one', 'two', 'extra'], ['same', 'same'],
    ['old-ignored-one', 'fresh-two'], ['fresh-one', 'old-ignored-two']])
    assert.throws(() => deliverySourceIncludes(projection, authorizations, ids), { refusalCode: 'AUTHORIZATION_REQUIRED' });
  assert.throws(() => deliverySourceIncludes(projection, authorizations.slice(1), ['one', 'two']),
    { refusalCode: 'AUTHORIZATION_REQUIRED' });
  assert.throws(() => deliverySourceIncludes(projection, [...authorizations].reverse(), ['one', 'two']),
    { refusalCode: 'AUTHORIZATION_REQUIRED' });
  assert.throws(() => deliverySourceIncludes({ ...projection, explicitIncludes: [] }, [], ['needless']),
    { refusalCode: 'AUTHORIZATION_REQUIRED' });
});
