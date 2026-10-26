import assert from 'node:assert/strict';
import test from 'node:test';
import { assertSameAuthorizationListing } from './installed-client-applications.js';

// Powerless response data: no connection, StateOwner, Run, grant or native proof.
const listing = (grants: readonly unknown[], nextCursor?: string) => ({ protocolVersion: 1, ok: true,
  result: { method: 'authorization.list', grants, ...(nextCursor === undefined ? {} : { nextCursor }) } });
const original = { id: 'original', state: 'active', target: { kind: 'workspace' } };

test('an empty original authorization listing is compared exactly without creating a grant', () => {
  assertSameAuthorizationListing(listing([]), listing([]));
});

test('a fresh opaque cursor may differ while the complete original grant page stays identical', () => {
  assertSameAuthorizationListing(listing([original], 'old-cut'), listing([original], 'new-cut'));
});

for (const [name, expected, actual] of [
  ['omitted original grant', listing([original]), listing([])],
  ['invented grant', listing([]), listing([original])],
  ['altered original grant', listing([original]), listing([{ ...original, state: 'revoked' }])],
  ['changed page completeness', listing([original], 'old-cut'), listing([original])],
  ['invalid cursor kind', listing([original], 'old-cut'), { ...listing([original]), result: { ...listing([original]).result, nextCursor: 0 } }],
  ['unmatched response field', listing([original]), { ...listing([original]), result: { ...listing([original]).result, extra: true } }],
  ['refused observation', listing([]), { protocolVersion: 1, ok: false }],
  ['wrong original response method', { ...listing([original]), result: { ...listing([original]).result, method: 'run.list' } }, listing([original])],
] as const) test(`authorization comparison rejects ${name}`, () => {
  assert.throws(() => assertSameAuthorizationListing(expected, actual));
});
