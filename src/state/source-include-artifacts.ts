import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireRecord, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { SourceIncludeAuthorizationV1 } from '../kernel/source-include.js';
import { normalizeSourceReadScopePath } from '../kernel/source-read-scope.js';
import { immutableSnapshot } from '../model/immutable.js';
import { assertBoundedJsonValue, parseJsonStrict } from '../kernel/json.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeAuthorizationConsumptionReceipt } from './authorization-artifacts.js';

const common = ['schemaVersion', 'format', 'principalId', 'inspectionId', 'runId', 'sessionId', 'workspaceIdentityRef',
  'workspaceIdentityDigest', 'selector', 'selectorDigest', 'admissionIntentDigest', 'capturedEntriesRef', 'capturedTreeDigest',
  'createdAt', 'authorizationDigest', 'kind'];
const builtin = ['frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest', 'classification',
  'classificationEvidenceRef', 'classificationEvidenceDigest'];
const user = ['authorizationGrantId', 'authorizationGrantTargetDigest', 'consumedGrantSnapshotRef', 'consumptionReceiptRef', 'consumptionReceiptDigest'];

/** Closed data validation. The owning reader separately verifies the original
 * authenticated capture, actual consumed SQL grant and derived Run identity. */
export function decodeSourceIncludeAuthorization(value: unknown): Readonly<SourceIncludeAuthorizationV1> {
  assertControlWireJson(value);
  assertBoundedJsonValue(value,'source include authorization');
  if (canonicalJsonBytes(value).length > 1024*1024) throw new TypeError('source include authorization exceeds the original JSON byte bound');
  const shape = controlWireRecord(value, common, [...builtin, ...user]);
  const branch = shape.kind === 'builtin_nonignored' ? builtin : shape.kind === 'consumed_user_read_grant' ? user : undefined;
  if (!branch) throw new TypeError('source include authorization has an unknown kind');
  const data = controlWireRecord(value, [...common, ...branch]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-source-include-authorization-v1')
    throw new TypeError('source include authorization has another format');
  for (const key of ['principalId', 'inspectionId', 'runId', 'sessionId']) controlWireText(data[key]);
  for (const key of ['workspaceIdentityRef', 'workspaceIdentityDigest', 'selectorDigest', 'admissionIntentDigest',
    'capturedEntriesRef', 'capturedTreeDigest', 'authorizationDigest'])
    controlWireRef(data[key]);
  const selector = controlWireRecord(data.selector, ['path', 'scope']);
  const path = normalizeSourceReadScopePath(selector.path, selector.scope);
  if (path.split('/').some(part => part.toLowerCase() === '.git') || canonicalSha256(selector) !== data.selectorDigest)
    throw new TypeError('source include selector or its complete digest differs');
  parseCanonicalTime(controlWireText(data.createdAt, 24, 24));
  if (data.kind === 'builtin_nonignored') {
    if (data.classification !== 'tracked_or_nonignored_in_root')
      throw new TypeError('source include builtin has another classification');
    for (const key of ['frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest', 'classificationEvidenceRef', 'classificationEvidenceDigest'])
      controlWireRef(data[key]);
  } else {
    controlWireText(data.authorizationGrantId);
    for (const key of ['authorizationGrantTargetDigest', 'consumedGrantSnapshotRef', 'consumptionReceiptRef', 'consumptionReceiptDigest']) controlWireRef(data[key]);
  }
  if (digestOmitting(data, 'authorizationDigest') !== data.authorizationDigest)
    throw new TypeError('source include authorization digest differs');
  return immutableSnapshot(data as SourceIncludeAuthorizationV1);
}

/** Audit the exact immutable receipt pair, without claiming that either value
 * was registered or that its original admission transaction actually ran. */
export function readSourceIncludeGrantReceipt(authorizationValue: unknown, receiptValue: unknown) {
  const authorization = decodeSourceIncludeAuthorization(authorizationValue);
  const receipt = decodeAuthorizationConsumptionReceipt(receiptValue);
  if (authorization.kind !== 'consumed_user_read_grant' ||
      canonicalSha256(receipt) !== authorization.consumptionReceiptRef || receipt.receiptDigest !== authorization.consumptionReceiptDigest ||
      receipt.grantId !== authorization.authorizationGrantId || receipt.ownerPrincipalId !== authorization.principalId ||
      receipt.targetDigest !== authorization.authorizationGrantTargetDigest || receipt.consumer.kind !== 'source_inspection' ||
      receipt.consumer.inspectionId !== authorization.inspectionId || receipt.consumer.admissionIntentDigest !== authorization.admissionIntentDigest ||
      receipt.consumedAt > authorization.createdAt)
    throw new TypeError('source include receipt is not its exact original capture');
  return receipt;
}

/** Full CAS bytes, strict original JSON bounds and exact canonical encoding.
 * A consumer ceiling never replaces the CAS identity/hash/currentness checks. */
export async function readSourceIncludeArtifact(artifacts: Pick<ArtifactCatalog,'readBoundedBytes'>,
  ref: string, maxByteCount = 1024*1024): Promise<unknown> {
  if (!Number.isSafeInteger(maxByteCount) || maxByteCount < 1 || maxByteCount > 1024*1024)
    throw new TypeError('source include artifact ceiling exceeds the original JSON byte bound');
  const bytes = await artifacts.readBoundedBytes(ref,maxByteCount);
  const value = parseJsonStrict(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('source include artifact is not its complete canonical JSON bytes');
  return value;
}
