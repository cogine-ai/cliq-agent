// Execute only the existing fixture's public-request composition. These inert
// responses do not create consent, StateOwner, Run, or native proof.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { normalizeRunApplyRequest } from '../../../src/kernel/control-apply.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../../../src/kernel/control-submit.js';
import { decodeAuthorizationCreateRequest } from '../../../src/kernel/control-wire.js';

test('actual installed Git apply composes a fresh closed grant using the current public Session identity for each new admission', async () => {
  const text = readFileSync(new URL('./installed-delivery-journey.ts', import.meta.url), 'utf8');
  const file = ts.createSourceFile('journey.ts', text, ts.ScriptTarget.Latest, true);
  const initializers: ts.Expression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'apply') {
      assert(node.initializer); initializers.push(node.initializer);
    }
    ts.forEachChild(node, visit);
  };
  visit(file); assert.equal(initializers.length, 1); const initializer = initializers[0]!; assert(ts.isArrowFunction(initializer));
  const compiled = ts.transpileModule(`const apply = ${initializer.getText(file)};`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
  const requests: Record<string, any>[] = [], grants: string[] = [], workspaceRef = 'a'.repeat(64), workspaceDigest = 'b'.repeat(64);
  const source = { expectedGit: true, cut: { snapshot: { run: { id: 'inert-source', sessionId: 'inert-session', resultRef: 'c'.repeat(64) } } },
    submit: { sourceInspectionGrantId: 'old-consumed-consent' } };
  const request = (core: object) => ({ ...core, requestDigest: canonicalSha256(core) });
  const accepted = (response: any, method: string) => {
    assert.equal(response.protocolVersion, 1); assert.equal(response.ok, true); assert.equal(response.result.method, method); return response.result;
  };
  const send = async (body: Record<string, any>, timeout?: number) => {
    requests.push(body);
    if (body.method === 'session.get') {
      assert.equal(body.sessionId, source.cut.snapshot.run.sessionId);
      return { snapshot: { session: { workspaceIdentityRef: workspaceRef } } };
    }
    const decoded = decodeAuthorizationCreateRequest(body); assert.equal(timeout, 30000);
    assert.equal(decoded.decision.kind, 'source_git_inspection');
    if (decoded.decision.kind !== 'source_git_inspection') assert.fail();
    assert.equal(decoded.decision.target.sessionId, source.cut.snapshot.run.sessionId);
    assert.equal(decoded.decision.target.expectedWorkspaceIdentityDigest, workspaceDigest);
    assert.deepEqual(decoded.decision.target.resourceCeiling, DEFAULT_SANDBOX_RESOURCES);
    const grantId = randomUUID(); grants.push(grantId);
    return { grant: { grantId, state: 'active', useCount: 0, targetKind: 'source_git_inspection' } };
  };
  let requestSequence = 0;
  const context = { nextId: () => `019a0000-0000-7000-8000-${(++requestSequence).toString(16).padStart(12, '0')}`,
    send: async (body: Record<string, any>, timeout: number) => {
    const normalized = normalizeRunApplyRequest(body).request; assert.equal(timeout, 30000);
    assert.equal(normalized.sourceInspectionGrantId, grants.at(-1));
    assert.equal(normalized.sourceRunId, source.cut.snapshot.run.id);
    assert.equal(normalized.expectedRunResultRef, source.cut.snapshot.run.resultRef);
    requests.push(body);
    return { protocolVersion: 1, ok: true, result: { method: 'run.apply', snapshot: { operation: 'delivery', run: { id: randomUUID(), revision: 1 } } } };
  } };
  const object = async (ref: string) => { assert.equal(ref, workspaceRef); return { identityDigest: workspaceDigest,
    repositoryIdentityRef: 'd'.repeat(64), repositoryIdentityDigest: 'e'.repeat(64) }; };
  const apply = Function('context', 'send', 'object', 'request', 'accepted', 'randomBytes', 'DEFAULT_SANDBOX_RESOURCES', 'assert',
    `${compiled}\nreturn apply;`)(context, send, object, request, accepted, randomBytes, DEFAULT_SANDBOX_RESOURCES, assert);
  await apply(source); await apply(source);
  assert.deepEqual(requests.map(body => body.method), ['session.get', 'authorization.create', 'run.apply', 'session.get', 'authorization.create', 'run.apply']);
  assert.equal(new Set(grants).size, 2); assert(!grants.includes(source.submit.sourceInspectionGrantId));
  requests.length = 0;
  const nonGitContext = { ...context, send: async (body: Record<string, any>) => {
    assert.equal(normalizeRunApplyRequest(body).request.sourceInspectionGrantId, undefined); requests.push(body);
    return { protocolVersion: 1, ok: true, result: { method: 'run.apply', snapshot: { operation: 'delivery', run: { id: randomUUID(), revision: 1 } } } };
  } };
  const plain = Function('context', 'send', 'object', 'request', 'accepted', 'randomBytes', 'DEFAULT_SANDBOX_RESOURCES', 'assert',
    `${compiled}\nreturn apply;`)(nonGitContext, send, object, request, accepted, randomBytes, DEFAULT_SANDBOX_RESOURCES, assert);
  const { expectedGit: _git, ...nonGitSource } = source;
  await plain(nonGitSource); assert.deepEqual(requests.map(body => body.method), ['run.apply']);
});
