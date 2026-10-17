import { randomBytes, X509Certificate } from 'node:crypto';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { decodeEndpointCredentialGrantBinding, decodeEndpointRegistration,
  type CredentialExternalSubjectV1, type EndpointCredentialGrantBinding, type EndpointRegistrationV1 } from '../../kernel/credential-authority.js';
import { digestOmitting, sha256Bytes } from '../../kernel/identity.js';
import type { RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import type { ArtifactCatalog } from '../artifacts.js';

/** Closed retained DATA for existing offline reducer/campaign prefixes. There
 * is no registry, secret, live credential scope, provider or native authority. */
export async function publishOfflineModelEndpoint(input: {
  artifacts: ArtifactCatalog; principalId: string; bundle: RuntimeBundleManifest; trustStorePem: string; createdAt: string;
}) {
  const { artifacts, principalId, bundle, createdAt } = input;
  const bytes = Buffer.from(input.trustStorePem);
  const trust = bundle.entries.find(entry => entry.entryId === 'default_https_trust_store');
  if (!trust || trust.digest !== sha256Bytes(bytes) || trust.byteCount !== bytes.length || trust.role !== 'trust_store' || trust.executable) {
    throw new TypeError('offline model DATA does not match the exact signed trust-store entry');
  }
  await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-https-trust-store-v1');
  const spki = new X509Certificate(bytes).publicKey.export({ type: 'spki', format: 'der' });
  const tls: EndpointRegistrationV1['tls'] = { serverNameAscii: 'offline-model.test', minimumVersion: 'TLSv1.3',
    trustStoreRuntimeBundleRef: canonicalSha256(bundle), trustStoreRuntimeBundleManifestDigest: bundle.manifestDigest,
    trustStoreEntryId: 'default_https_trust_store', trustStoreRef: trust.digest, trustStoreDigest: trust.digest,
    spkiSha256Pins: [sha256Bytes(spki)] };
  const target: EndpointRegistrationV1['target'] = { scheme: 'https', hostAscii: 'offline-model.test', port: 443,
    basePath: '/api', redirectPolicy: 'reject_all' };
  const tlsPolicyDigest = canonicalSha256(tls), endpointIdentityDigest = canonicalSha256({ target, tlsPolicyDigest });
  const registration: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1',
    endpointRegistrationId: 'offline-model-data-v1', registrationKind: 'user', ownerPrincipalId: principalId,
    purposes: ['model_endpoint'], target, tls, endpointIdentityDigest, tlsPolicyDigest, createdAt, registrationDigest: '' };
  registration.registrationDigest = digestOmitting(registration, 'registrationDigest');
  decodeEndpointRegistration(registration);
  const endpointRef = (await artifacts.publishCanonical(registration, registration.format)).ref;
  const externalSubject: CredentialExternalSubjectV1 = { schemaVersion: 1, format: 'cliq-credential-external-subject-v1',
    endpointIdentityDigest, subject: { kind: 'opaque_generation', opaqueSubjectId: randomBytes(32).toString('base64url'),
      scopes: ['endpoint_exact_only'], audiences: [] }, observedAt: createdAt, subjectDigest: '' };
  externalSubject.subjectDigest = digestOmitting(externalSubject, 'subjectDigest');
  await artifacts.publishCanonical(externalSubject, externalSubject.format);
  const credentialGrantId = 'offline-model-credential-data-v1', purpose = 'model_endpoint' as const, credentialServiceRevision = 1;
  const binding: EndpointCredentialGrantBinding = { schemaVersion: 1, credentialGrantId, authorityRevision: 1,
    credentialServiceRevision, ownerPrincipalId: principalId,
    credentialHandleIdentityDigest: canonicalSha256({ ownerPrincipalId: principalId, credentialGrantId, credentialServiceRevision,
      purpose, endpointRegistrationRef: endpointRef, endpointIdentityDigest, tlsPolicyDigest }),
    secretGeneration: 1, externalSubject, externalSubjectDigest: externalSubject.subjectDigest, purpose,
    endpointRegistrationRef: endpointRef, endpointIdentityDigest, tlsPolicyDigest, createdAt, bindingDigest: '' };
  binding.bindingDigest = digestOmitting(binding, 'bindingDigest');
  decodeEndpointCredentialGrantBinding(binding);
  const credentialRef = (await artifacts.publishCanonical(binding, 'cliq-endpoint-credential-grant-binding-v1')).ref;
  return { endpoint: { kind: 'registered' as const, registrationKind: 'user' as const, endpointRegistrationRef: endpointRef,
    endpointIdentityDigest, tlsPolicyDigest }, credentialRefs: [credentialRef] };
}
