import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { AuthorizationConsumptionReceiptV1, AuthorizationGrantV1 } from '../kernel/authorization.js';
import type { SourceSelectorRequest } from '../kernel/control-submit.js';
import { digestOmitting } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { authorizationGrantCore, decodeAuthorizationConsumptionReceipt, decodeAuthorizationGrant,
  VerifierAuthorizationError } from './authorization-artifacts.js';
import { readSourceReadAuthorizationHistory, type AuthorizationRuntime } from './authorization.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { consumeOrRevokeAuthorization, readAuthorizationCreationControl,
  readAuthorizationGrant } from './repositories/authorization-grants.js';
import { readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { assertSourceIncludeConstraintScope } from './source-include-constraints.js';

type Expected = Readonly<{ principalId: string; sessionId: string; workspaceIdentityRef: string;
  workspaceIdentityDigest: string; inspectionId: string; admissionIntentDigest: string }>;
type Consumption = Readonly<{ prior: AuthorizationGrantV1;
  next: Extract<AuthorizationGrantV1, { state: 'consumed' }>;
  receipt: AuthorizationConsumptionReceiptV1; snapshotRef: string }>;
declare const consentBrand: unique symbol;
export type PreparedSourceIncludeConsent = Readonly<{ [consentBrand]: true }>;
type Binding = { owner: StateOwnerContext; expected: Expected; consumptions: readonly Consumption[];
  metadata: readonly PublishedArtifact[] };
const bindings = new WeakMap<PreparedSourceIncludeConsent, Binding>();
const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
function refuse(): never { throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED'); }
function held(owner: StateOwnerContext, token: PreparedSourceIncludeConsent): Binding {
  const binding = bindings.get(token);
  if (!binding || binding.owner !== owner) throw new TypeError('source include consent has no original owning preparation');
  return binding;
}
function assertSession(connection: SqliteConnection | SqliteDriver, owner: StateOwnerContext, expected: Expected): void {
  assertActiveStateOwner(connection, owner);
  if (readSessionPrincipalId(connection, expected.sessionId) !== expected.principalId ||
      readSession(connection, expected.sessionId).workspaceIdentityRef !== expected.workspaceIdentityRef) refuse();
}

/** Receipt/snapshot publication is inert preparation. The genuine target and
 * original SourceInspection transaction must recheck and consume it before
 * opening source content. Neither the returned token nor its refs are a read
 * permission, native proof or registration of a capturing attempt. */
export async function prepareSourceIncludeConsent(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, expectedInput: Expected, selectors: readonly SourceSelectorRequest[],
  signal?: AbortSignal): Promise<PreparedSourceIncludeConsent> {
  const expected = immutableSnapshot(expectedInput);
  signal?.throwIfAborted(); assertSession(driver, owner, expected);
  if (!Array.isArray(selectors) || selectors.length > 128) refuse();
  const grants = new Set<string>(), paths = new Set<string>(), consumptions: Consumption[] = [];
  for (const selector of selectors) {
    const key = `${selector.path}\0${selector.scope}`;
    if (paths.has(key)) refuse(); paths.add(key);
    if (selector.readGrantId === undefined) continue;
    if (grants.has(selector.readGrantId)) refuse(); grants.add(selector.readGrantId);
    const prior = readAuthorizationGrant(driver, selector.readGrantId);
    if (!prior || prior.state !== 'active' || prior.ownerPrincipalId !== expected.principalId ||
        prior.target.kind !== 'read_scope' || prior.target.purpose !== 'source' ||
        prior.target.workspaceIdentityDigest !== expected.workspaceIdentityDigest ||
        prior.target.canonicalRootRelativePath !== selector.path || prior.target.scope !== selector.scope) refuse();
    assertSourceIncludeConstraintScope(prior.target);
    const history = await readSourceReadAuthorizationHistory(driver, artifacts, owner, prior, runtime.releaseKeys, signal);
    if (history.request.decision.kind !== 'read_scope' || history.request.decision.target.sessionId !== expected.sessionId) refuse();
    signal?.throwIfAborted();
    const consumedAt = sampleCanonicalNow();
    if (consumedAt < history.committedAt || consumedAt >= prior.expiresAt) refuse();
    const receipt: AuthorizationConsumptionReceiptV1 = { schemaVersion: 1, grantId: prior.grantId, ownerPrincipalId: expected.principalId,
      targetDigest: prior.targetDigest, consumer: { kind: 'source_inspection', inspectionId: expected.inspectionId,
        admissionIntentDigest: expected.admissionIntentDigest }, consumedAt, receiptDigest: '' };
    receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest'); decodeAuthorizationConsumptionReceipt(receipt);
    const next: Extract<AuthorizationGrantV1, { state: 'consumed' }> = { ...authorizationGrantCore(prior),
      grantCoreDigest: prior.grantCoreDigest, rowVersion: 2, state: 'consumed', useCount: 1,
      consumptionReceiptRef: canonicalSha256(receipt), consumedAt, rowDigest: '' };
    next.rowDigest = digestOmitting(next, 'rowDigest'); decodeAuthorizationGrant(next);
    consumptions.push(immutableSnapshot({ prior, next, receipt, snapshotRef: canonicalSha256(next) }));
  }
  const publications = consumptions.flatMap(item => [
    { value: item.receipt, schemaKind: 'cliq-authorization-consumption-receipt-v1' },
    { value: item.next, schemaKind: 'cliq-authorization-grant-v1' }
  ]);
  const metadata: PublishedArtifact[] = [];
  // Two grants form one natural four-object group. Every file sync, complete
  // readback and issued cleanup still joins; no arbitrary-sized CAS batch.
  for (let index = 0; index < publications.length; index += 4) {
    signal?.throwIfAborted(); assertSession(driver, owner, expected);
    const group = publications.slice(index, index + 4);
    const result = group.length === 4
      ? await artifacts.publishCanonicalFour([group[0]!, group[1]!, group[2]!, group[3]!])
      : await artifacts.publishCanonicalPair([group[0]!, group[1]!]);
    if (result.length !== group.length || result.some((artifact, offset) => {
      const original = group[offset]!;
      return artifact.ref !== canonicalSha256(original.value) || artifact.byteLength !== canonicalJsonBytes(original.value).length ||
        artifact.mediaType !== 'application/json' || artifact.schemaKind !== original.schemaKind;
    })) throw new TypeError('source include preparation differs from its complete receipt and snapshot bytes');
    signal?.throwIfAborted(); assertSession(driver, owner, expected); metadata.push(...result);
  }
  const token = Object.freeze({}) as PreparedSourceIncludeConsent;
  bindings.set(token, { owner, expected, consumptions: Object.freeze(consumptions), metadata: immutableSnapshot(metadata) });
  return token;
}

/** Inert fields for the existing verified target. The owning producer retains
 * the opaque token; a caller-selected snapshot ref cannot reconstruct it. */
export function sourceIncludeConsentData(owner: StateOwnerContext, token: PreparedSourceIncludeConsent) {
  const { consumptions, metadata } = held(owner, token);
  const expiresAt = consumptions.map(item => item.prior.expiresAt).sort()[0];
  return immutableSnapshot({ sourceReadGrantRefs: consumptions.map(item => item.snapshotRef), metadata,
    ...(expiresAt === undefined ? {} : { expiresAt }),
    scopes: consumptions.map(item => {
      if (item.prior.target.kind !== 'read_scope') throw new TypeError('source include preparation changed its purpose');
      return { grantId: item.prior.grantId, target: item.prior.target, receipt: item.receipt, snapshotRef: item.snapshotRef };
    }) });
}

/** Synchronous friend of the original reserveSourceInspectionAttempt SQL
 * callback. Its caller supplies the genuine target/current frame checks and
 * registers all metadata and the actual attempt in this same transaction. */
export function consumeSourceIncludeConsent(connection: SqliteConnection, owner: StateOwnerContext,
  token: PreparedSourceIncludeConsent, actual: Pick<Expected, 'inspectionId' | 'admissionIntentDigest' | 'workspaceIdentityDigest'>,
  createdAt: string): void {
  const binding = held(owner, token), { expected } = binding;
  assertSession(connection, owner, expected);
  if (actual.inspectionId !== expected.inspectionId || actual.admissionIntentDigest !== expected.admissionIntentDigest ||
      actual.workspaceIdentityDigest !== expected.workspaceIdentityDigest) refuse();
  for (const item of binding.consumptions) {
    const current = readAuthorizationGrant(connection, item.prior.grantId);
    if (!current || !same(current, item.prior) || createdAt < item.receipt.consumedAt || createdAt >= item.prior.expiresAt ||
        item.receipt.consumedAt < readAuthorizationCreationControl(connection, item.prior).committedAt) refuse();
    consumeOrRevokeAuthorization(connection, item.prior, item.next);
  }
}

/** A real post-transaction read, never a cached success bit. Rollback after
 * an attempted consumption must not leave permission in the JS preparation. */
export function assertSourceIncludeConsentConsumed(driver: SqliteDriver, owner: StateOwnerContext,
  token: PreparedSourceIncludeConsent): void {
  const binding = held(owner, token);
  assertSession(driver, owner, binding.expected);
  for (const item of binding.consumptions) {
    const current = readAuthorizationGrant(driver, item.next.grantId);
    if (!current || !same(current, item.next)) refuse();
  }
}
