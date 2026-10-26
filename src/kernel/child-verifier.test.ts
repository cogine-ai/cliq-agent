import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from './canonical.js';
import { digestOmitting } from './identity.js';
import { parseJsonStrict } from './json.js';
import { decodeDerivedChildUnverifiedConsent, type DerivedChildUnverifiedConsentV1 } from './child-verifier.js';
import { decodeUnverifiedConsent } from '../state/decoders.js';

// Pure decoding only: these objects are deliberately not an admitted child,
// StateOwner, ToolPermission grant, original receipt or native observation.
function consent(): DerivedChildUnverifiedConsentV1 {
  const value: DerivedChildUnverifiedConsentV1 = { schemaVersion: 1, kind: 'derived_child_unverified_consent',
    parentRunId: 'parent', childRunId: 'child', delegateBatchItemId: 'batch', delegateCallId: 'call', delegateCallIndex: 0,
    delegateOpId: 'delegate-op', delegateOperationGrantRef: 'a'.repeat(64), childCapabilityGrantCoreDigest: 'b'.repeat(64),
    childRunSpecCoreDigest: 'c'.repeat(64), allowUnverifiedHelper: true, createdAt: '2026-10-26T00:00:00.000Z', consentDigest: '' };
  value.consentDigest = digestOmitting(value, 'consentDigest'); return value;
}
test('derived child consent has one closed digest-bound shape and cannot enter the direct consent decoder', () => {
  const original = consent(), bytes = canonicalJsonBytes(original), decoded = decodeDerivedChildUnverifiedConsent(parseJsonStrict(bytes.toString()));
  assert.deepEqual(canonicalJsonBytes(decoded), bytes); assert(Object.isFrozen(decoded));
  const laterCall = { ...original, delegateCallIndex: 32 }; laterCall.consentDigest = digestOmitting(laterCall, 'consentDigest');
  assert.equal(decodeDerivedChildUnverifiedConsent(laterCall).delegateCallIndex, 32, 'the owning original batch supplies the actual index bound');
  assert.throws(() => decodeUnverifiedConsent(original), { code: 'ARTIFACT_MISMATCH' });
  for (const key of Object.keys(original)) {
    const changed: Record<string, unknown> = { ...original }; delete changed[key];
    assert.throws(() => decodeDerivedChildUnverifiedConsent(changed), 'missing ' + key);
  }
  for (const changed of [{ ...original, extra: true }, { ...original, principalId: 'caller' }, { ...original, childRunId: 'other' },
    { ...original, delegateCallIndex: -1 }, { ...original, delegateCallIndex: Number.MAX_SAFE_INTEGER + 1 }, { ...original, delegateCallIndex: 0.5 },
    { ...original, childCapabilityGrantCoreDigest: 'B'.repeat(64) }, { ...original, createdAt: '2026-10-26T00:00:00Z' },
    { ...original, allowUnverifiedHelper: false }]) assert.throws(() => decodeDerivedChildUnverifiedConsent(changed));
  const loop = { ...original, childRunId: original.parentRunId }; loop.consentDigest = digestOmitting(loop, 'consentDigest');
  assert.throws(() => decodeDerivedChildUnverifiedConsent(loop));
});
test('derived consent rejects proxy and accessor inputs without executing caller code', () => {
  let touched = 0;
  const proxy = new Proxy(consent(), { ownKeys() { touched++; throw new Error('must not run'); } });
  assert.throws(() => decodeDerivedChildUnverifiedConsent(proxy));
  const accessor = { ...consent() }; Object.defineProperty(accessor, 'parentRunId', { enumerable: true, get() { touched++; return 'parent'; } });
  assert.throws(() => decodeDerivedChildUnverifiedConsent(accessor)); assert.equal(touched, 0);
});
