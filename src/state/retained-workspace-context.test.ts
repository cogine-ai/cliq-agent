// Plain descriptor data and source wiring only. No filesystem workspace,
// StateOwner, Session, Run, permission, installation or native proof is made.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { digestOmitting } from '../kernel/identity.js';
import { decodeRetainedWorkspaceIdentity, decodeWorkspaceIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';

const WHEN = '2026-11-03T00:00:00.000Z';
function seal(value: Record<string, unknown>): Record<string, unknown> {
  return { ...value, identityDigest: digestOmitting(value, 'identityDigest') };
}
function unavailable(changes: Record<string, unknown> = {}): Record<string, unknown> {
  return seal({ schemaVersion: 1, format: 'cliq-workspace-identity-v1', ownerPrincipalId: 'inert-principal', platform: 'linux',
    kind: 'legacy_unavailable', legacyCanonicalRootPath: '/original/missing-workspace', unavailableReason: 'missing', observedAt: WHEN,
    ...changes });
}
function mismatch(action: () => unknown): void {
  assert.throws(action, error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
}

test('all unavailable reasons remain readable historical context on both supported Kernel platforms', () => {
  for (const platform of ['linux', 'macos']) for (const unavailableReason of ['missing', 'moved', 'unsupported_platform', 'identity_unverifiable']) {
    const data = unavailable({ platform, unavailableReason }), decoded = decodeRetainedWorkspaceIdentity(data);
    assert.deepEqual(decoded, data);
    assert.equal(decoded.kind, 'legacy_unavailable');
    assert.throws(() => decodeWorkspaceIdentity(data), error => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST',
      'context readability never changes the original execution/admission refusal');
  }
});

test('live retained data delegates to the original workspace decoder without inventing a different execution descriptor', () => {
  const data = seal({ schemaVersion: 1, format: 'cliq-workspace-identity-v1', ownerPrincipalId: 'inert-principal', platform: 'linux',
    kind: 'live', canonicalRootPath: '/ordinary/workspace', rootIdentity: { deviceId: '1', fileId: '2', ownerUid: 501 } });
  assert.strictEqual(decodeRetainedWorkspaceIdentity(data), decodeWorkspaceIdentity(data));
  const corrupted = { ...data, identityDigest: '0'.repeat(64) };
  mismatch(() => decodeRetainedWorkspaceIdentity(corrupted));
  mismatch(() => decodeWorkspaceIdentity(corrupted));
});

test('a retained legacy identity has exactly its historical fields and cannot borrow live coordinates or permission fields', () => {
  const data = unavailable();
  for (const key of Object.keys(data)) {
    const missing = { ...data }; delete missing[key];
    mismatch(() => decodeRetainedWorkspaceIdentity(missing));
  }
  for (const [key, value] of Object.entries({ canonicalRootPath: '/new/workspace', rootIdentity: {}, repositoryIdentityRef: 'a'.repeat(64),
    repositoryIdentityDigest: 'b'.repeat(64), permission: 'write', grantRef: 'c'.repeat(64), nativeHandle: {}, extra: true }))
    mismatch(() => decodeRetainedWorkspaceIdentity(seal({ ...data, [key]: value })));
});

test('retained legacy identity checks its complete digest and canonical principal, platform, path and observation data', () => {
  const data = unavailable();
  for (const change of [{ ownerPrincipalId: 'other-principal' }, { platform: 'macos' }, { legacyCanonicalRootPath: '/other/workspace' },
    { unavailableReason: 'moved' }, { observedAt: '2026-11-04T00:00:00.000Z' }, { identityDigest: '0'.repeat(64) }])
    mismatch(() => decodeRetainedWorkspaceIdentity({ ...data, ...change }));
  for (const change of [{ schemaVersion: 2 }, { format: 'cliq-workspace-identity-v2' }, { kind: 'unknown' },
    { ownerPrincipalId: '' }, { ownerPrincipalId: 'p'.repeat(129) }, { ownerPrincipalId: 'e\u0301' }, { platform: 'windows' },
    { legacyCanonicalRootPath: 'relative/workspace' }, { legacyCanonicalRootPath: '/workspace/../elsewhere' },
    { legacyCanonicalRootPath: '/workspace//nested' }, { legacyCanonicalRootPath: '/workspace\\nested' },
    { legacyCanonicalRootPath: '/workspace/é\0' }, { legacyCanonicalRootPath: '/workspace/e\u0301' },
    { legacyCanonicalRootPath: '/' + 'p'.repeat(4096) }, { unavailableReason: 'available' },
    { observedAt: '2026-11-03' }, { observedAt: '2026-11-03T00:00:00Z' }, { observedAt: '2026-02-30T00:00:00.000Z' }])
    mismatch(() => decodeRetainedWorkspaceIdentity(unavailable(change)));
});

test('retained decoding never observes proxy traps or accessor code in historical descriptor data', () => {
  let observed = 0;
  const getter = () => { observed++; throw new Error('historical data is not executable input'); };
  const accessor = unavailable();
  Object.defineProperty(accessor, 'kind', { enumerable: true, get: getter });
  const proxy = new Proxy(unavailable(), { get: getter, ownKeys: getter, getOwnPropertyDescriptor: getter, getPrototypeOf: getter });
  for (const value of [accessor, proxy]) {
    mismatch(() => decodeRetainedWorkspaceIdentity(value));
    assert.equal(observed, 0);
  }
});

async function source(name: string): Promise<ts.SourceFile> {
  return ts.createSourceFile(name, await readFile(new URL(name, import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
}
function namedFunction(file: ts.SourceFile, name: string): ts.FunctionDeclaration {
  const functions = file.statements.filter((node): node is ts.FunctionDeclaration => ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert.equal(functions.length, 1, name); assert(functions[0]!.body); return functions[0]!;
}
function calls(root: ts.Node, name: string): ts.CallExpression[] {
  const values: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText() === name) values.push(node);
    ts.forEachChild(node, visit);
  };
  visit(root); return values;
}
const compact = (value: string) => value.replace(/\s+/gu, '');

test('only the actual Session handoff and workspace-list filter use the retained descriptor reader and preserve original full-read/principal checks', async () => {
  const wrapper = namedFunction(await source('./session-continuity.ts'), 'createSessionHandoff');
  assert.equal(calls(wrapper, 'createStreamedSessionHandoff').length, 1);
  const handoff = namedFunction(await source('./session-handoff-stream.ts'), 'createStreamedSessionHandoff');
  const handoffReads = calls(handoff, 'decodeRetainedWorkspaceIdentity');
  assert.equal(handoffReads.length, 1); assert.equal(calls(handoff, 'decodeWorkspaceIdentity').length, 0);
  assert.equal(compact(handoffReads[0]!.arguments[0]!.getText()), 'awaitreadBoundedSessionContextJson(reads,context.cut.session.workspaceIdentityRef)');
  assert.match(handoff.getText(), /workspace\.ownerPrincipalId !== identity\.principalId/u);
  assert.equal(calls(handoff, 'validateControlChannelClosure').length, 1);
  assert.equal(calls(handoff, 'assertActiveStateOwner').length, 3);
  assert.equal(calls(handoff, 'readCurrentSessionContextGraph').length, 1);
  assert.equal(calls(handoff, 'assertCurrentSessionContextGraph').length, 2);
  assert.equal(calls(handoff, 'readSessionContextEntryStream').length, 1);
  assert.equal(calls(handoff, 'walkSessionContextSegments').length, 2);
  assert.match(handoff.getText(), /const source = \{ driver, cut: context\.cut \}/u);
  assert.match(handoff.getText(), /readSessionContextEntryStream\(reads, context\.projection, \{ source, signal \}\)/u);

  const filter = namedFunction(await source('./list-read-cut.ts'), 'sessionListSource');
  const filterReads = calls(filter, 'decodeRetainedWorkspaceIdentity');
  assert.equal(filterReads.length, 1); assert.equal(filterReads[0]!.arguments[0]!.getText(), 'value');
  assert.equal(calls(filter, 'decodeWorkspaceIdentity').length, 0);
  assert.match(filter.getText(), /await artifacts\.readCanonical\(row\.ref\); if \(canonicalSha256\(value\) !== row\.ref\) return corrupt\(\)/u);
  assert.match(filter.getText(), /workspace\.ownerPrincipalId !== principalId/u);
  assert.match(filter.getText(), /workspace\.kind === 'live' \? workspace\.canonicalRootPath : workspace\.legacyCanonicalRootPath/u);
  assert.match(filter.getText(), /workspaceRefDigest\(connection, principalId\) !== prepared\.refsDigest/u);
});

test('execution, source, verifier and authorization consumers keep their original decoder and cannot adopt historical unavailable data', async () => {
  for (const [name, count] of [['authorization.ts', 3], ['source-target.ts', 3], ['installed-run.ts', 2], ['run-authority.ts', 1],
    ['agent-recovery.ts', 1], ['run-execution.ts', 2], ['verifier-execution.ts', 1], ['delivery-approval.ts', 1], ['publication-plan.ts', 1]] as const) {
    const file = await source('./' + name);
    assert.equal(calls(file, 'decodeWorkspaceIdentity').length, count, name);
    assert.equal(calls(file, 'decodeRetainedWorkspaceIdentity').length, 0, name);
  }
  const original = namedFunction(await source('./decoders.ts'), 'decodeWorkspaceIdentity');
  assert.match(original.getText(), /identity\.kind === 'legacy_unavailable'/u);
  assert.match(original.getText(), /new KernelStorageError\('INVALID_REQUEST', 'legacy_unavailable Sessions cannot admit a Run'\)/u);
  const retained = namedFunction(await source('./decoders.ts'), 'decodeRetainedWorkspaceIdentity');
  assert.equal(calls(retained, 'decodeWorkspaceIdentity').length, 1);
  assert.match(retained.getText(), /value\.kind === 'live'\) return decodeWorkspaceIdentity\(value\)/u);
});
