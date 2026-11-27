import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { AuthorizationConsumptionReceiptV1, AuthorizationGrantV1 } from '../kernel/authorization.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { digestOmitting } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { authorizationGrantCore, VerifierAuthorizationError } from './authorization-artifacts.js';
import type { AuthorizationRuntime } from './authorization.js';
import { readSourceGitAuthorizationHistory, readSourceReadAuthorizationHistory } from './authorization.js';
import { type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { consumeOrRevokeAuthorization, readAuthorizationCreationControl, readAuthorizationGrant } from './repositories/authorization-grants.js';
import { readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

type Expected = Readonly<{ principalId: string; sessionId: string; workspaceIdentityRef: string; workspaceIdentityDigest: string;
  repositoryIdentityRef: string; repositoryIdentityDigest: string; inspectionId: string; admissionIntentDigest: string;
  resources: SandboxResourceSpec }>;
declare const consentBrand: unique symbol;
export type PreparedSourceGitConsent = Readonly<{ [consentBrand]: true }>;
type Consumption = { prior: AuthorizationGrantV1; next: Extract<AuthorizationGrantV1, { state: 'consumed' }>;
  receipt: AuthorizationConsumptionReceiptV1; metadata: PublishedArtifact };
type Binding = Consumption & { owner: StateOwnerContext; expected: Expected; ignore: Consumption[] };
const bindings = new WeakMap<PreparedSourceGitConsent, Binding>();
function held(owner: StateOwnerContext, consent: PreparedSourceGitConsent): Binding {
  const value = bindings.get(consent);
  if (!value || value.owner !== owner) throw new TypeError('source Git consent has no original owning preparation');
  return value;
}
function refusal(): never { throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED'); }

/** Publishes inert receipt data only. No raw repository byte is read and no
 * grant is consumed until the original capturing transaction commits. */
export async function prepareSourceGitConsent(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, grantId: string, expected: Expected, signal?: AbortSignal,
  ignoreReadGrantIds: readonly string[] = []): Promise<PreparedSourceGitConsent> {
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const prior = readAuthorizationGrant(driver, grantId);
  if (!prior || prior.state !== 'active' || prior.ownerPrincipalId !== expected.principalId || prior.target.kind !== 'source_git_inspection') refusal();
  const target = prior.target;
  if (target.sessionId !== expected.sessionId || target.workspaceIdentityRef !== expected.workspaceIdentityRef ||
      target.workspaceIdentityDigest !== expected.workspaceIdentityDigest || target.repositoryIdentityRef !== expected.repositoryIdentityRef ||
      target.repositoryIdentityDigest !== expected.repositoryIdentityDigest || target.inspector.runtimeBundleRef !== canonicalSha256(runtime.bundle) ||
      target.inspector.runtimeBundleManifestDigest !== runtime.bundle.manifestDigest ||
      (Object.keys(expected.resources) as (keyof SandboxResourceSpec)[]).some(key => expected.resources[key] > target.resourceCeiling[key])) refusal();
  const history = await readSourceGitAuthorizationHistory(driver, artifacts, owner, prior, runtime.releaseKeys, signal);
  signal?.throwIfAborted();
  const prepare = async (selected: AuthorizationGrantV1, committedAt: string): Promise<Consumption> => {
    const consumedAt = sampleCanonicalNow();
    if (consumedAt < committedAt || consumedAt >= selected.expiresAt) refusal();
    const receipt: AuthorizationConsumptionReceiptV1 = { schemaVersion: 1, grantId: selected.grantId, ownerPrincipalId: expected.principalId,
      targetDigest: selected.targetDigest, consumer: { kind: 'source_inspection', inspectionId: expected.inspectionId,
        admissionIntentDigest: expected.admissionIntentDigest }, consumedAt, receiptDigest: '' };
    receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest');
    const metadata = await artifacts.publishCanonical(receipt, 'cliq-authorization-consumption-receipt-v1');
    signal?.throwIfAborted();
    const next: Extract<AuthorizationGrantV1, { state: 'consumed' }> = { ...authorizationGrantCore(selected), rowVersion: 2,
      grantCoreDigest: selected.grantCoreDigest, state: 'consumed', useCount: 1, consumptionReceiptRef: metadata.ref, consumedAt, rowDigest: '' };
    next.rowDigest = digestOmitting(next, 'rowDigest');
    return { prior: immutableSnapshot(selected), next: immutableSnapshot(next), receipt: immutableSnapshot(receipt), metadata };
  };
  if (ignoreReadGrantIds.length > 128 || new Set(ignoreReadGrantIds).size !== ignoreReadGrantIds.length) refusal();
  const ignore: Consumption[] = [], paths = new Set<string>();
  for (const id of [...ignoreReadGrantIds].sort()) {
    signal?.throwIfAborted();
    const selected = readAuthorizationGrant(driver, id);
    if (!selected || selected.state !== 'active' || selected.ownerPrincipalId !== expected.principalId ||
        selected.target.kind !== 'read_scope' || selected.target.workspaceIdentityDigest !== expected.workspaceIdentityDigest ||
        selected.target.scope !== 'entry' || (selected.target.canonicalRootRelativePath !== '.git/info/exclude' &&
          selected.target.canonicalRootRelativePath.split('/').at(-1) !== '.gitignore') ||
        paths.has(selected.target.canonicalRootRelativePath)) refusal();
    paths.add(selected.target.canonicalRootRelativePath);
    const selectedHistory = await readSourceReadAuthorizationHistory(driver, artifacts, owner, selected, runtime.releaseKeys, signal);
    if (selectedHistory.request.decision.kind !== 'read_scope' || selectedHistory.request.decision.target.sessionId !== expected.sessionId) refusal();
    ignore.push(await prepare(selected, selectedHistory.committedAt));
  }
  const selected = await prepare(prior, history.committedAt);
  const token = Object.freeze({}) as PreparedSourceGitConsent;
  bindings.set(token, { owner, expected: immutableSnapshot(expected), ...selected, ignore });
  return token;
}
export function sourceGitConsentData(owner: StateOwnerContext, consent: PreparedSourceGitConsent) {
  const value = held(owner, consent);
  return { grantId: value.prior.grantId, receiptRef: value.metadata.ref, receiptDigest: value.receipt.receiptDigest,
    expiresAt: [value.prior.expiresAt, ...value.ignore.map(item => item.prior.expiresAt)].sort()[0]!,
    metadata: [value.metadata, ...value.ignore.map(item => item.metadata)],
    ignoreReadConsents: value.ignore.map(item => ({ grantId: item.prior.grantId, receiptRef: item.metadata.ref, receiptDigest: item.receipt.receiptDigest })),
    // Inert selector data, never a descriptor or native input capability.
    ignoreReadScopes: value.ignore.map(item => {
      if (item.prior.target.kind !== 'read_scope') throw new TypeError('prepared ignore consent changed purpose');
      return immutableSnapshot(item.prior.target);
    }) };
}
/** Synchronous friend called only by reserveSourceInspectionAttempt's actual
 * SQL connection. It cannot create a row or return read/native authority. */
export function consumeSourceGitConsent(connection: SqliteConnection, owner: StateOwnerContext, consent: PreparedSourceGitConsent,
  actual: Pick<Expected, 'inspectionId' | 'admissionIntentDigest' | 'workspaceIdentityDigest'>, createdAt: string): void {
  const value = held(owner, consent), expected = value.expected;
  assertActiveStateOwner(connection, owner);
  if (readSessionPrincipalId(connection, expected.sessionId) !== expected.principalId ||
      readSession(connection, expected.sessionId).workspaceIdentityRef !== expected.workspaceIdentityRef ||
      actual.inspectionId !== expected.inspectionId || actual.admissionIntentDigest !== expected.admissionIntentDigest ||
      actual.workspaceIdentityDigest !== expected.workspaceIdentityDigest)
    refusal();
  for (const selected of [value, ...value.ignore]) {
    const prior = readAuthorizationGrant(connection, selected.prior.grantId);
    if (!prior || !canonicalJsonBytes(prior).equals(canonicalJsonBytes(selected.prior)) ||
        createdAt < selected.next.consumedAt || createdAt >= prior.expiresAt) refusal();
    if (selected.next.consumedAt < readAuthorizationCreationControl(connection, prior).committedAt)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'source consumption precedes its actual grant creation');
    consumeOrRevokeAuthorization(connection, prior, selected.next);
  }
}
