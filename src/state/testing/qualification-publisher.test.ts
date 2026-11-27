import assert from 'node:assert/strict';
import { sign, verify } from 'node:crypto';
import { test } from 'node:test';
import { createInstalledQualificationPublisher, qualificationPublisherMaterial } from './qualification-publisher.js';

test('one controlled publisher session retains the actual signer without accepting equal key labels', () => {
  const publisher = createInstalledQualificationPublisher(), other = createInstalledQualificationPublisher();
  const a = qualificationPublisherMaterial(publisher), again = qualificationPublisherMaterial(publisher), b = qualificationPublisherMaterial(other);
  assert.equal(a.privateKey, again.privateKey); assert.equal(a.publicKey, again.publicKey);
  assert.equal(a.releaseKeys[0]!.keyId, b.releaseKeys[0]!.keyId);
  assert.notEqual(a.releaseKeys[0]!.publicKeyPem, b.releaseKeys[0]!.publicKeyPem);
  const old7 = Buffer.from('actual old product bytes'), target8 = Buffer.from('actual target product bytes');
  for (const bytes of [old7, target8]) {
    const signature = sign(null, bytes, a.privateKey);
    assert.equal(verify(null, bytes, again.publicKey, signature), true);
    assert.equal(verify(null, bytes, b.publicKey, signature), false);
  }
  assert.throws(() => qualificationPublisherMaterial({ purpose: publisher.purpose }), /original controlled session/);
});
