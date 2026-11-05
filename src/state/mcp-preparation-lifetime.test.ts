// Read-only wiring checks. No installed image, credential, SQL, Run or native
// authority is created; physical cancellation remains a Linux qualification.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

async function source(name: string): Promise<ts.SourceFile> {
  return ts.createSourceFile(name, await readFile(new URL(name, import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
}
function calls(root: ts.Node, name: string): ts.CallExpression[] {
  const found: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name) found.push(node);
    ts.forEachChild(node, visit);
  };
  visit(root);
  return found;
}
function declaration(parsed: ts.SourceFile, name: string): ts.FunctionDeclaration {
  const selected = parsed.statements.filter((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert.equal(selected.length, 1, `inspect the original ${name} declaration`);
  return selected[0]!;
}

test('all four direct asynchronous control producers await inside the original refusal boundary', async () => {
  const parsed = await source('./installed-control.ts');
  for (const name of ['mutateMcpRegistration', 'listMcpRegistrations', 'sessionContinuity', 'listControl']) {
    const selected: ts.CallExpression[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
          node.expression.expression.getText(parsed) === 'store' && node.expression.name.text === name) selected.push(node);
      ts.forEachChild(node, visit);
    };
    visit(parsed); assert.equal(selected.length, 1, name);
    const call = selected[0]!;
    assert(ts.isAwaitExpression(call.parent) && ts.isReturnStatement(call.parent.parent),
      'an asynchronous backend refusal must reach the application catch before returning');
    let boundary: ts.Node | undefined = call.parent.parent;
    while (boundary && !ts.isTryStatement(boundary)) boundary = boundary.parent;
    assert(boundary && ts.isTryStatement(boundary) && boundary.catchClause);
    assert(boundary.tryBlock.pos < call.pos && call.end < boundary.tryBlock.end);
    assert.match(boundary.catchClause.getText(parsed), /error: (?:sessionContextRequestLimitRefusal\(knownMethod,\s*error\) \?\? )?errorResult\(error, method === 'credential\.finalize'\)/u,
      'preserve the closed original error mapper instead of retiring the connection on an ordinary refusal');
    if (name === 'mutateMcpRegistration' || name === 'listMcpRegistrations')
      assert.match(call.arguments[0]!.getText(parsed), /^decodeInstalledControlRequest\(request\) as /u);
    else assert.equal(call.arguments[0]!.getText(parsed), 'request');
    assert.equal(call.arguments[1]!.getText(parsed), 'identity');
  }
});

test('both MCP credential preparations forward their actual signal into the original installed credential scope', async () => {
  const parsed = await source('./store.ts');
  for (const name of ['withInstalledMcpHttpAuthority', 'resolveInstalledMcpTransport']) {
    const original = declaration(parsed, name), signal = original.parameters.at(-1)!;
    assert.equal(signal.name.getText(parsed), 'preparationSignal');
    assert(signal.questionToken, 'the internal signal is optional, not a new source of authority');
    assert.equal(signal.type?.getText(parsed), 'AbortSignal');
    const scopes = calls(original, 'withCredentialAuthorityLock');
    assert.equal(scopes.length, 1);
    assert.equal(scopes[0]!.arguments.length, 3);
    assert.equal(scopes[0]!.arguments[0]!.getText(parsed), 'selected');
    assert.equal(scopes[0]!.arguments[2]!.getText(parsed), 'preparationSignal');
    assert(ts.isArrowFunction(scopes[0]!.arguments[1]!), 'the original owned callback remains deferred');
  }
  const authority = declaration(parsed, 'withInstalledMcpHttpAuthority').getText(parsed);
  assert.match(authority, /token\.assertHeld\(\); assertStateOwnerLock\(owner\.filesystem\)/u);
  assert.match(authority, /assertCurrent\(\) \{ requireEqual\(current\(\), initial,/u,
    'preparation cancellation cannot replace the fresh endpoint and credential release gates');
});

test('Run and both Admin authority callers pass their retained task signal without replacing their result catalog', async () => {
  const execution = await source('./run-execution.ts');
  const run = calls(execution, 'withInstalledMcpHttpAuthority');
  assert.equal(run.length, 1);
  assert.deepEqual(run[0]!.arguments.slice(0, 5).map(value => value.getText(execution)),
    ['selectedRuntime', 'owner', 'reads', 'grant.principalId', 'transport']);
  assert.equal(run[0]!.arguments.length, 7);
  assert.equal(run[0]!.arguments[6]!.getText(execution), 'signal');
  const operation = run[0]!.arguments[5]!;
  assert(ts.isArrowFunction(operation));
  assert.match(operation.getText(execution), /signal\.throwIfAborted\(\); authority\.assertCurrent\(\)/u);
  assert.match(operation.getText(execution), /publishMcpRunCapture\(artifacts, native\)/u,
    'received result persistence retains the original catalog');
  assert.doesNotMatch(operation.getText(execution), /publishMcpRunCapture\(reads,/u);

  const admin = await source('./mcp-registration.ts');
  const authorities = calls(admin, 'withInstalledMcpHttpAuthority');
  assert.equal(authorities.length, 2, 'initial eligibility and the original probe share the owned admission lifetime');
  for (const call of authorities) {
    assert.equal(call.arguments.length, 7);
    assert.equal(call.arguments[6]!.getText(admin), 'signal');
    assert(ts.isArrowFunction(call.arguments[5]!));
  }
  const transports = calls(admin, 'resolveInstalledMcpTransport');
  assert.equal(transports.length, 1);
  assert.equal(transports[0]!.arguments.length, 6);
  assert.equal(transports[0]!.arguments[5]!.getText(admin), 'signal',
    'endpoint resolution before prepared intent must not lose the same cancellation signal');

  const store = await source('./store.ts');
  const producers = calls(store, 'mutateInstalledMcpRegistration');
  assert.equal(producers.length, 1);
  assert.equal(producers[0]!.arguments.at(-1)!.getText(store), 'signal');
  let owner: ts.Node | undefined = producers[0];
  while (owner && !ts.isMethodDeclaration(owner)) owner = owner.parent;
  assert(owner && ts.isMethodDeclaration(owner) && owner.name.getText(store) === 'mutateMcpRegistration');
  assert.match(owner.getText(store), /this\.ownInstalledAdmission\(async signal =>/u,
    'Admin uses its real Store-owned shutdown signal rather than an observer timeout');
});

test('the original native credential scope cancels only preparation and fully validates after the owned callback', async () => {
  const parsed = await source('./installed-runtime.ts'), methods: ts.MethodDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isMethodDeclaration(node) && node.body && node.name.getText(parsed) === 'credentialScope') methods.push(node);
    ts.forEachChild(node, visit);
  };
  visit(parsed);
  assert.equal(methods.length, 1);
  const body = methods[0]!.getText(parsed);
  assert.match(body, /preparationSignal\?\.throwIfAborted\(\)/u);
  assert.match(body, /await loadSelectedNative\(preparationSignal\)/u);
  const before = body.indexOf('await checkedRevalidate(preparationSignal); credential.assertHeld();');
  const callback = body.indexOf('await runInstalledCredentialAuthority(physical, operation);');
  const after = body.indexOf('await checkedRevalidate(); credential.assertHeld();');
  assert(before >= 0 && callback > before && after > callback,
    'claim/result custody must retain full postvalidation independently of a preparation abort');
  assert.match(body, /finally \{ binding\.active = false; \}/u,
    'the original native credential scope remains active until its callback and postvalidation finish');
});
