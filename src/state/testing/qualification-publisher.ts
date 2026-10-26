// Dedicated test publisher composition. Never an official release key or a
// credential accepted from a Run, repository, control request or environment.
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { immutableSnapshot } from '../../model/immutable.js';
import type { ReleaseTrustKey } from '../../policy/runtime-authority.js';
export type InstalledQualificationPublisher = Readonly<{ purpose: 'installed-upgrade-mechanism-qualification' }>;
const publishers = new WeakMap<InstalledQualificationPublisher, { privateKey: KeyObject; publicKey: KeyObject;
  releaseKeys: readonly ReleaseTrustKey[] }>();
export function createInstalledQualificationPublisher(): InstalledQualificationPublisher {
  const keys = generateKeyPairSync('ed25519');
  const publisher: InstalledQualificationPublisher = Object.freeze({ purpose: 'installed-upgrade-mechanism-qualification' });
  publishers.set(publisher, { ...keys, releaseKeys: immutableSnapshot([{ keyId: 'explicit-installed-startup-test-root',
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }]) });
  return publisher;
}
/** Test-build friend only. Structural objects or equal key labels cannot
 * borrow a publisher. The same object means the same actual Ed25519 key. */
export function qualificationPublisherMaterial(publisher: InstalledQualificationPublisher) {
  const material = publishers.get(publisher);
  if (!material) throw new TypeError('qualification publisher requires its original controlled session');
  return material;
}
