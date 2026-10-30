import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { controlWireRecord, controlWireText } from '../kernel/control-wire-data.js';
import { decodeEndpointAuthorityCommandCore, type EndpointAuthorityCommandCoreV1 } from '../kernel/credential-authority.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { withCredentialAuthorityLock, withHeldInstalledRuntime, type HeldInstalledRuntime } from '../state/installed-runtime.js';
import { commitEndpointAuthority, decodeCredentialWriteRequest, readCredentialAuthority, writeCredentialAuthority,
  type CredentialWriteRequest } from '../state/store.js';
import { mutationIdentity } from './commands.js';
import type { InstalledClientData } from './installed-data.js';
import { modelSetupEndpointCandidate, type ModelSetupProfileV1 } from './model-setup-profile.js';
import { CLIENT_MODEL_SELECTION_LIMIT, readClientPreferences, writeClientPreferences, type ClientModelSelectionV1 } from './preferences.js';

type SetupRequest = Readonly<{
  schemaVersion: 1; format: 'cliq-client-model-setup-v1'; alias: string; profileId: string;
  provider: 'openai-compatible'; model: string; endpointIdentityDigest: string;
  endpointRequestId: string; endpoint: EndpointAuthorityCommandCoreV1;
  credential: CredentialWriteRequest & Readonly<{ kind: 'enroll' }>;
}>;
const equal = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
function decodeSetupRequest(value: unknown): SetupRequest {
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'alias', 'profileId', 'provider', 'model',
    'endpointIdentityDigest', 'endpointRequestId', 'endpoint', 'credential']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-client-model-setup-v1' || data.provider !== 'openai-compatible')
    throw new TypeError('model setup request has an unsupported format');
  const endpoint = decodeEndpointAuthorityCommandCore(data.endpoint), credential = decodeCredentialWriteRequest(data.credential);
  if (endpoint.kind !== 'register' || credential.kind !== 'enroll' || credential.purpose !== 'model_endpoint' ||
      credential.endpointRegistrationId !== endpoint.registration.endpointRegistrationId ||
      endpoint.registration.endpointIdentityDigest !== data.endpointIdentityDigest)
    throw new TypeError('model setup request does not bind the same endpoint and credential');
  return { schemaVersion: 1, format: 'cliq-client-model-setup-v1', alias: controlWireText(data.alias, 128),
    profileId: controlWireText(data.profileId, 128), provider: 'openai-compatible', model: controlWireText(data.model, 512),
    endpointIdentityDigest: controlWireText(data.endpointIdentityDigest, 64),
    endpointRequestId: controlWireText(data.endpointRequestId, 256), endpoint, credential };
}

/** Public choices are matched inside the genuine installed borrow. The returned
 * metadata never replaces the native producer, registration or finalizer checks. */
async function currentModel(selected: HeldInstalledRuntime, data: InstalledClientData, profile: ModelSetupProfileV1) {
  return withHeldInstalledRuntime(selected, async installed => {
    if (!equal(installed.stateRoot, data.stateRoot) || installed.bundleDigest !== data.sourceBundleDigest)
      throw new TypeError('model setup changed its selected installation');
    const endpoint = modelSetupEndpointCandidate(profile, installed.bundle);
    const matches = installed.modelAuthority?.models.filter(pair => pair.catalog.value.provider === profile.provider &&
      pair.catalog.value.model === profile.model && pair.catalog.value.endpointIdentityDigest === endpoint.endpointIdentityDigest &&
      pair.priceTable.value.provider === profile.provider && pair.priceTable.value.model === profile.model &&
      pair.priceTable.value.endpointIdentityDigest === endpoint.endpointIdentityDigest) ?? [];
    if (matches.length !== 1) throw new TypeError('model setup has no unique signed model and price pair');
    const pair = matches[0]!, now = new Date().toISOString();
    for (const value of [pair.catalog.value, pair.priceTable.value])
      if (now < value.validFrom || now >= value.validThrough) throw new TypeError('model setup catalog or price interval is not current');
    const root = { schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
      canonicalAbsolutePath: installed.stateRoot.canonicalPath, ownerUid: installed.stateRoot.ownerUid,
      deviceId: installed.stateRoot.deviceId, directoryFileId: installed.stateRoot.fileId,
      mode: 448, openedNoFollow: true, layoutVersion: 1 };
    const principalId = identityHash('cliq-local-principal-v1', canonicalSha256(root), 'linux', installed.stateRoot.ownerUid);
    return { endpoint, principalId, expiresAt: [pair.catalog.value.validThrough, pair.priceTable.value.validThrough].sort()[0]! };
  });
}

/** One local setup action. Persist only the original secret-free command IDs
 * before their first writes, so retrying setup can read committed history before
 * prompting again. No key enters these files or the client wire request cache. */
export async function configureInstalledModel(selected: HeldInstalledRuntime, data: InstalledClientData,
  profile: ModelSetupProfileV1, alias: string, input: 'stdin' | 'terminal') {
  controlWireText(alias, 128);
  const current = await currentModel(selected, data, profile);
  const initialPreferences = await readClientPreferences(data.directory);
  if (!initialPreferences.modelSelections.some(value => value.alias === alias) &&
      initialPreferences.modelSelections.length >= CLIENT_MODEL_SELECTION_LIMIT)
    throw new TypeError('model aliases are full; no credential setup was started');
  const filename = `model-setup-${canonicalSha256({ alias, provider: profile.provider, model: profile.model,
    endpointIdentityDigest: current.endpoint.endpointIdentityDigest })}.json`;
  let bytes = await data.directory.read(filename, 65_536);
  if (bytes === undefined) {
    const endpointRegistrationId = `cliq-model-${mutationIdentity().admissionKey}`;
    const registration = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId,
      registrationKind: 'user', ownerPrincipalId: current.principalId, purposes: ['model_endpoint'],
      ...current.endpoint, createdAt: new Date().toISOString(), registrationDigest: '' };
    registration.registrationDigest = digestOmitting(registration, 'registrationDigest');
    const core = { schemaVersion: 1, kind: 'register', ownerPrincipalId: current.principalId, registration,
      expectedRegistrationArtifactRef: canonicalSha256(registration), commandDigest: '' };
    core.commandDigest = digestOmitting(core, 'commandDigest');
    const draft = decodeSetupRequest({ schemaVersion: 1, format: 'cliq-client-model-setup-v1', alias, profileId: profile.id,
      provider: profile.provider, model: profile.model, endpointIdentityDigest: current.endpoint.endpointIdentityDigest,
      endpointRequestId: mutationIdentity().requestId, endpoint: core,
      credential: { schemaVersion: 1, kind: 'enroll', requestId: mutationIdentity().requestId,
        credentialGrantId: `cliq-model-${mutationIdentity().admissionKey}`, secretSubmissionId: mutationIdentity().requestId,
        purpose: 'model_endpoint', endpointRegistrationId, expiresAt: current.expiresAt } });
    await data.directory.publish(filename, canonicalJsonBytes(draft));
    bytes = await data.directory.read(filename, 65_536);
  }
  if (bytes === undefined) throw new TypeError('model setup lost its durable original request');
  const request = decodeSetupRequest(parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)));
  if (!canonicalJsonBytes(request).equals(bytes) || request.alias !== alias || request.profileId !== profile.id ||
      request.provider !== profile.provider || request.model !== profile.model || request.endpointIdentityDigest !== current.endpoint.endpointIdentityDigest ||
      request.endpoint.kind !== 'register' || request.endpoint.ownerPrincipalId !== current.principalId ||
      !equal({ target: request.endpoint.registration.target, tls: request.endpoint.registration.tls,
        tlsPolicyDigest: request.endpoint.registration.tlsPolicyDigest, endpointIdentityDigest: request.endpoint.registration.endpointIdentityDigest }, current.endpoint))
    throw new TypeError('model setup original request differs from its current signed model selection');
  await withCredentialAuthorityLock(selected, async token => commitEndpointAuthority(token, request.endpointRequestId, request.endpoint));
  // The existing writer authenticates and reads its history before selecting
  // the original bounded input source; committed replay consumes no secret.
  const operation = await writeCredentialAuthority(selected, request.credential, input);
  if (operation.phase !== 'committed' || operation.credentialGrantId !== request.credential.credentialGrantId)
    throw new TypeError('model credential setup did not commit its original operation');
  const record = await withCredentialAuthorityLock(selected, async token => readCredentialAuthority(token, request.credential.credentialGrantId));
  if (!record || record.state !== 'active' || record.purpose !== 'model_endpoint' || record.endpointIdentityDigest !== current.endpoint.endpointIdentityDigest ||
      record.expiresAt !== undefined && new Date().toISOString() >= record.expiresAt)
    throw new TypeError('model credential is revoked, expired or differs from its original endpoint');
  await currentModel(selected, data, profile);
  const preferences = await readClientPreferences(data.directory);
  const selection: ClientModelSelectionV1 = { alias, provider: profile.provider, model: profile.model,
    endpointRegistrationId: request.credential.endpointRegistrationId, credentialGrantId: request.credential.credentialGrantId };
  await writeClientPreferences(data.directory, { ...preferences,
    modelSelections: [...preferences.modelSelections.filter(value => value.alias !== alias), selection],
    defaultModelAlias: preferences.defaultModelAlias ?? alias });
  return selection;
}
