// Source/publisher identity and fixture wiring only. No installation,
// StateOwner, Run, native authority or qualification result is constructed.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import ts from 'typescript';
import { effectiveSourceExcludes } from '../../../src/kernel/dependency-source.js';
import { overlayCallbackDependencyInputs } from './qualify-native-callback-lifecycle.js';

test('the callback qualifier candidate pin names the complete current native image while preserving its original baseline and evidence reader', async () => {
  const source = await readFile(new URL('./qualify-native-callback-lifecycle.ts', import.meta.url), 'utf8');
  const native = await readFile(new URL('../../../native/linux/credential-platform.c', import.meta.url));
  const match = /const candidateNative = '([0-9a-f]{64})';/u.exec(source); assert(match);
  assert.equal(match[1], createHash('sha256').update(native).digest('hex'));
  assert.match(source, /commit: 'ba804a59dcadee80cb41c822e2d0e32198462f20'/u);
  assert.match(source, /native: '73cd16a6f23e9054c7a0b50ec6c1dcdeb47a1561f180f661686e1a63f74140a9'/u);
  assert.match(source, /readNativeCallbackEvidence\(\{ mode: view\.record\.name, stdout: run\.stdout, stderr: run\.stderr,/u);
  assert.match(source, /report\.qualified = report\.views\.every\(\(view: Record<string, any>\) => view\.evidence && !view\.evidenceRefused\)/u);
  assert.match(source, /assert\.equal\(baseline\.dependencies\.contentDigest, candidate\.dependencies\.contentDigest\)/u);
  assert.match(source, /dependencyMode = 'independent_shared_current_lock_integrity_no_scripts'/u);
});

test('the original native source view records its exact dependency overlay without changing the archive or current input', async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'cliq-callback-inputs-'));
  const root = path.join(temporary, 'baseline'), current = path.join(temporary, 'current');
  const names = ['package.json', 'package-lock.json'];
  const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
  try {
    await mkdir(root); await mkdir(current);
    const archive = path.join(temporary, 'original.source.tar'), originalArchive = Buffer.from('inert archive sentinel, not executable source');
    await writeFile(archive, originalArchive);
    const inventory = [];
    for (const name of names) {
      const old = Buffer.from(`original ${name}\n`), next = Buffer.from(`current ${name}\n`);
      await writeFile(path.join(root, name), old); await writeFile(path.join(current, name), next);
      inventory.push({ path: name, size: old.length, sha256: sha(old) });
    }
    const overlay = await overlayCallbackDependencyInputs(root, current, inventory);
    for (const [index, name] of names.entries()) {
      const old = Buffer.from(`original ${name}\n`), next = Buffer.from(`current ${name}\n`);
      assert.deepEqual(overlay[index], { path: name, originalSha256: sha(old), originalBytes: old.length,
        executionSha256: sha(next), executionBytes: next.length });
      assert((await readFile(path.join(root, name))).equals(next));
      assert((await readFile(path.join(current, name))).equals(next));
      assert.deepEqual(inventory[index], { path: name, size: next.length, sha256: sha(next) });
    }
    assert((await readFile(archive)).equals(originalArchive));
  } finally { await rm(temporary, { recursive: true, force: true }); }
});

test('an altered original or aliased replacement refuses before either dependency input is overlaid', async () => {
  for (const aliased of [false, true]) {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'cliq-callback-refusal-'));
    const root = path.join(temporary, 'baseline'), current = path.join(temporary, 'current');
    try {
      await mkdir(root); await mkdir(current);
      const inventory = [];
      for (const name of ['package.json', 'package-lock.json']) {
        const bytes = Buffer.from(`original ${name}\n`);
        await writeFile(path.join(root, name), bytes); await writeFile(path.join(current, name), `current ${name}\n`);
        inventory.push({ path: name, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
      }
      if (aliased) {
        await rm(path.join(current, 'package-lock.json')); await symlink(path.join(root, 'package-lock.json'), path.join(current, 'package-lock.json'));
      } else await writeFile(path.join(root, 'package-lock.json'), 'changed original lock');
      const before = await Promise.all(['package.json', 'package-lock.json'].map(name => readFile(path.join(root, name))));
      await assert.rejects(overlayCallbackDependencyInputs(root, current, inventory));
      for (const [index, name] of ['package.json', 'package-lock.json'].entries()) assert((await readFile(path.join(root, name))).equals(before[index]!));
    } finally { await rm(temporary, { recursive: true, force: true }); }
  }
});

test('the durable source-refusal campaign keeps the original selector preflight and real owned projection refusal', async () => {
  const source = await readFile(new URL('../qualify-installed-run-journey.ts', import.meta.url), 'utf8');
  const file = ts.createSourceFile('installed-source-refusal.ts', source, ts.ScriptTarget.Latest, true);
  const declarations = new Map<string, ts.VariableDeclaration>();
  const calls: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) declarations.set(node.name.text, node);
    if (ts.isCallExpression(node)) calls.push(node);
    ts.forEachChild(node, visit);
  }; visit(file);
  const refusal = declarations.get('refusalCore')?.initializer; assert(refusal && ts.isObjectLiteralExpression(refusal));
  const exclude = refusal.properties.find((property): property is ts.PropertyAssignment => ts.isPropertyAssignment(property) &&
    property.name.getText(file) === 'sourceExcludes')?.initializer;
  assert(exclude && ts.isPropertyAccessExpression(exclude));
  assert.equal(exclude.getText(file), 'resourceCore.sourceExcludes');
  // The actual failure-mode submit keeps its original vendor-only exclusion;
  // its pre-existing nested .git must not choose an unrelated native refusal.
  const submit = declarations.get('submit')?.initializer;
  assert(submit && ts.isCallExpression(submit));
  const core = submit.arguments[0]; assert(core && ts.isObjectLiteralExpression(core));
  const originalExcludes = core.properties.find((property): property is ts.PropertyAssignment => ts.isPropertyAssignment(property) &&
    property.name.getText(file) === 'sourceExcludes')?.initializer;
  assert(originalExcludes && ts.isConditionalExpression(originalExcludes));
  assert.equal(originalExcludes.condition.getText(file), 'failureOnly');
  assert(ts.isArrayLiteralExpression(originalExcludes.whenTrue));
  const selectors = originalExcludes.whenTrue.elements.map(item => {
    assert(ts.isObjectLiteralExpression(item));
    const fields = Object.fromEntries(item.properties.map(property => {
      assert(ts.isPropertyAssignment(property) && ts.isStringLiteral(property.initializer));
      return [property.name.getText(file), property.initializer.text];
    }));
    assert.deepEqual(Object.keys(fields).sort(), ['path', 'scope']);
    assert(fields.scope === 'entry' || fields.scope === 'subtree');
    return { path: fields.path!, scope: fields.scope as 'entry' | 'subtree' };
  });
  assert.doesNotThrow(() => effectiveSourceExcludes({ dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: selectors }));
  assert.deepEqual(selectors, [{ path: 'vendor', scope: 'subtree' }]);
  const fixture = calls.filter(call => call.expression.getText(file) === 'withInstalledSourceRefusalFixture');
  assert.equal(fixture.length, 1);
  assert.equal(fixture[0]!.arguments[0]?.getText(file), '{ workspace: recipe.workspace, uid: ledger.uid, gid: ledger.gid }');
  assert(fixture[0]!.pos < refusal.pos && fixture[0]!.end > refusal.end);
  assert.match(source, /sourceRule: 'non_nfc_source_name'/u);
  for (const original of [
    "original nonce must replay its durable source refusal despite current credential revocation",
    "fresh nonce must bind the same original source refusal without reauthorizing capture",
    "source_changed_or_unsupported",
  ]) assert(source.includes(original));
});
