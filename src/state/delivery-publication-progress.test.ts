// Retained-data locator checks only. These values create no claim, native birth,
// physical progress or SQL cleanup permission.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { decodePublicationArenaBirth, decodePublicationPathProgressItem, decodePublicationPathResultItem,
  publicationArenaId, type PublicationAbortOperation } from '../kernel/publication.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { publicationEnvelopeLocations } from './delivery-publication-progress.js';

test('an actual claimed abort has exactly one fixed private preimage slot, never a workspace locator', () => {
  const ref = 'a'.repeat(64), operation: PublicationAbortOperation = { index: 0,
    operationId: identityHash('data-only-abort-directory'), kind: 'abort_rmdir', path: 'directory',
    createdByOperationId: identityHash('data-only-directory-creator'), quarantineName: 'preimage', quarantineExpected: { kind: 'absent' } };
  const arenaId = publicationArenaId('data-only-run', operation.operationId, 'data-only-op', 0, 'data-only-dispatch');
  const source = { schemaVersion: 1, format: 'cliq-publication-arena-birth-v1', deliveryRunId: 'data-only-run', deliveryPlanRef: ref,
    workspaceIdentityRef: ref, workspaceIdentityDigest: ref, stateRootIdentityRef: ref, stateRootIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, sequence: 'abort', operationIndex: 0, operationId: operation.operationId,
    opId: 'data-only-op', attempt: 0, dispatchId: 'data-only-dispatch', arenaId,
    arenaIdentity: { deviceId: '1', fileId: '2', ownerUid: 501, mode: 448 }, parentIdentity: { deviceId: '1', fileId: '3', ownerUid: 501, mode: 448 },
    observedAt: '2026-10-18T00:00:00.000Z', birthDigest: '' };
  source.birthDigest = digestOmitting(source, 'birthDigest');
  const birth = decodePublicationArenaBirth(source);
  assert.deepEqual(publicationEnvelopeLocations({ birth, operation }), [{ kind: 'publication_arena', arenaId, component: 'preimage' }]);
  assert.deepEqual(publicationEnvelopeLocations({ operation }), []);
});

/** Execute the actual retained-reader association predicate, not a copy of
 * its comparison. Decoders remain real; these are data only, never a Run,
 * StateOwner, receipt, resource retirement or native publication proof. */
async function receivedPairPredicate() {
  const source = await readFile(new URL('./delivery-publication-progress.ts', import.meta.url), 'utf8');
  const file = ts.createSourceFile('delivery-publication-progress.ts', source, ts.ScriptTarget.Latest, true);
  const scope = file.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'readPublicationPrefixData');
  assert(scope?.body);
  const declarations: ts.VariableDeclaration[] = [], associations: ts.IfStatement[] = [];
  function visit(node: ts.Node): void {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'paired') declarations.push(node);
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'requireEqual' &&
        ts.isStringLiteral(node.arguments[2]!) && node.arguments[2]!.text === 'publication result exact original received probe association') {
      assert(ts.isExpressionStatement(node.parent) && ts.isIfStatement(node.parent.parent));
      associations.push(node.parent.parent);
    }
    ts.forEachChild(node, visit);
  }
  visit(scope.body);
  assert.equal(declarations.length, 1); assert.equal(associations.length, 1);
  // Only trusted repository source is compiled; neither artifact nor caller
  // data is source code. Use this realm so the real canonical plain-object
  // checks run unchanged rather than rejecting a foreign VM prototype first.
  return Function('requireEqual', `return (item, entry) => { const ${declarations[0]!.getText(file)}; ${associations[0]!.getText(file)} };`)
    (requireEqual) as (item: unknown, entry: { receivedHandoff: { item: unknown } }) => void;
}
function pairData(reconciled = false) {
  const common = { schemaVersion: 1, runId: 'data-only-run', deliveryPlanRef: 'a'.repeat(64), operationIndex: 0,
    operationId: identityHash('data-only-received-association'), opId: 'data-only-op', attempt: 0, sequence: 'forward', createdAt: '2026-10-25T00:00:00.000Z' };
  const retirement = { slotObservationRefs: ['c'.repeat(64)], arenaRetirementRef: 'd'.repeat(64) };
  const pair = reconciled ? { reconciliationEvidenceRef: '8'.repeat(64), reconciliationEvidenceDigest: '9'.repeat(64) } : {};
  const handoff = { ...common, kind: 'publication_path_progress', itemId: 'data-only-handoff', state: 'received_handoff',
    dispatchId: 'data-only-dispatch', claimJournalSeq: 1, receiptRef: 'e'.repeat(64), receiptDigest: 'f'.repeat(64), retirement,
    generationResources: { kind: 'sealed', workerLaunchId: 'data-only-worker', generationRef: '1'.repeat(64), snapshotEvidenceRef: '2'.repeat(64) }, ...pair };
  const result = { ...common, kind: 'publication_path_result', itemId: 'data-only-result', outcome: 'completed',
    evidenceRef: 'e'.repeat(64), receiptRef: 'e'.repeat(64), retirement, ...pair };
  return { result, handoff };
}

test('the original normal handoff and completion compare their absent probe association as canonical empty data', async () => {
  const compare = await receivedPairPredicate(), { result, handoff } = pairData();
  const decodedResult = decodePublicationPathResultItem(result), decodedHandoff = decodePublicationPathProgressItem(handoff);
  assert.doesNotThrow(() => compare(decodedResult, { receivedHandoff: { item: decodedHandoff } }),
    'normal received-result association must not construct undefined canonical members');
});

test('a reconciled received-result association keeps both exact reference and digest comparisons', async () => {
  const compare = await receivedPairPredicate(), { result, handoff } = pairData(true);
  const decodedHandoff = decodePublicationPathProgressItem(handoff);
  assert.doesNotThrow(() => compare(decodePublicationPathResultItem(result), { receivedHandoff: { item: decodedHandoff } }));
  for (const changed of [
    { ...result, reconciliationEvidenceRef: '7'.repeat(64) },
    { ...result, reconciliationEvidenceDigest: '6'.repeat(64) },
  ]) assert.throws(() => compare(decodePublicationPathResultItem(changed), { receivedHandoff: { item: decodedHandoff } }),
    /publication result exact original received probe association/u);
});

test('normal and reconciled associations cannot be substituted for one another', async () => {
  const compare = await receivedPairPredicate(), normal = pairData(), reconciled = pairData(true);
  assert.throws(() => compare(decodePublicationPathResultItem(normal.result),
    { receivedHandoff: { item: decodePublicationPathProgressItem(reconciled.handoff) } }),
  /publication result exact original received probe association/u);
  assert.throws(() => compare(decodePublicationPathResultItem(reconciled.result),
    { receivedHandoff: { item: decodePublicationPathProgressItem(normal.handoff) } }),
  /publication result exact original received probe association/u);
});

test('the real retained item decoders still reject partial, undefined and extra probe association fields', () => {
  const data = pairData(true);
  for (const [source, decode] of [
    [data.result, decodePublicationPathResultItem],
    [data.handoff, decodePublicationPathProgressItem],
  ] as const) {
    for (const field of ['reconciliationEvidenceRef', 'reconciliationEvidenceDigest']) {
      const partial: Record<string, unknown> = { ...source }; delete partial[field];
      assert.throws(() => decode(partial), TypeError);
      assert.throws(() => decode({ ...source, [field]: undefined }), TypeError);
    }
    assert.throws(() => decode({ ...source, probeAssociation: {} }), TypeError);
  }
  // Canonical JSON remains strict; this fix does not teach it to drop values.
  assert.throws(() => requireEqual({}, { ref: undefined, digest: undefined }, 'data-only strict canonical comparison'),
    /canonical JSON does not permit undefined/u);
});
