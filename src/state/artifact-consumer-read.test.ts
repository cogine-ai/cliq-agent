// Wiring of ordinary retained reads only; no Run, StateOwner or native proof.
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import ts from 'typescript';
import { planArtifactBytes, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { sha256Bytes } from '../kernel/identity.js';
import { ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { joinResourceOperations, ResourceRetirementError } from './errors.js';
import { readCanonicalArtifact } from './agent-context.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';

test('submission, invocation, approval and continuation consumers dispatch retained CAS reads through the same bounded joined catalog', async () => {
  const expected = new Map([
    ['store.ts', ['this.artifacts:initial.assembly.provider.credentialGrantRefs']],
    ['reducers/stop.ts', ['artifacts:cause.plans', 'artifacts:selected.items', 'artifacts:selected.items']],
    ['reducers/agent.ts', ['artifacts:rows']],
    ['reducers/input.ts', ['reads:closure.items']],
    ['reducers/tool.ts', ['openingReads:contracts.filter((entry) => entry.outputSchemaRef !== undefined)']],
    ['broker-ambiguity.ts', ['artifacts:abandoned', 'artifacts:closures']],
    ['publication-preflight.ts', ['artifacts:cut.items']],
    ['delivery-approval.ts', ['artifacts:cut.items', 'artifacts:cut.items', 'artifacts:cut.items']],
    ['final-candidate.ts', ['artifacts:selected.items']],
    ['verifier-execution.ts', ['reads:selected.items']],
    ['reducers/invocation.ts', [
      'artifacts:artifactRefs.filter((ref): ref is string => ref !== undefined)',
      'artifacts:artifactRefs.filter((ref): ref is string => ref !== undefined)'
    ]]
  ]);
  const compact = (value: string) => value.replace(/\s+/gu, '');
  for (const [file, groups] of expected) {
    const body = await readFile(new URL(`./${file}`, import.meta.url), 'utf8');
    const parsed = ts.createSourceFile(file, body, ts.ScriptTarget.Latest, true), calls: ts.CallExpression[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'mapReads') calls.push(node);
      ts.forEachChild(node, visit);
    };
    visit(parsed);
    assert.deepEqual(calls.map(call => compact(`${(call.expression as ts.PropertyAccessExpression).expression.getText(parsed)}:${call.arguments[0]!.getText(parsed)}`)),
      groups.map(compact), file);
    for (const call of calls) {
      assert.equal(call.arguments.length, 2, file);
      assert(ts.isArrowFunction(call.arguments[1]!), `${file}: defer the original read body, not an already started operation`);
    }
    if (file === 'reducers/invocation.ts') {
      const declaration = body.slice(body.indexOf('const invocationMetadata ='), body.indexOf('const initialRun ='));
      assert.match(declaration, /await joinResourceOperations\(\[/u, 'the fixed two-read metadata group must also join every issued operation');
      assert.match(declaration, /artifacts\.describe\(input\.requestRef/u);
      assert.match(declaration, /artifacts\.describe\(input\.grantRef/u);
    }
  }
});

test('the original Agent planned publications join every real CAS return and preserve a later original retirement refusal', async t => {
  const source = await readFile(new URL('./reducers/agent.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('agent-planned-data.ts', source, ts.ScriptTarget.Latest, true);
  const declaration = parsed.statements.find((node): node is ts.FunctionDeclaration => ts.isFunctionDeclaration(node) && node.name?.text === 'publishPlans');
  assert(declaration);
  const output = ts.transpileModule(`${declaration.getText(parsed)}; return publishPlans;`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const publish = new Function('sha256Bytes', 'joinResourceOperations', output)(sha256Bytes, joinResourceOperations) as
    (artifacts: ArtifactCatalog, plans: readonly PlannedArtifact[]) => Promise<PublishedArtifact[]>;
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-agent-publication-join-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const cas = new ContentAddressedStore(root), artifacts = new ArtifactCatalog(cas);
  const plans = [0, 1].map(index => planArtifactBytes(Buffer.from(`plain joined publication ${index}`), 'application/octet-stream', 'inert-test-data'));
  const original = cas.publish.bind(cas), ordinary = new Error('original completed publication return failed');
  // Error-selection data, not native retirement evidence. Both publications
  // below really persist and close; only their original return gates are held.
  const retirement = new ResourceRetirementError('original later publication return was uncertain', ordinary);
  let enterFirst!: () => void, enterSecond!: () => void, release!: () => void, settled = false, active = 0;
  const first = new Promise<void>(resolve => { enterFirst = resolve; });
  const second = new Promise<void>(resolve => { enterSecond = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  t.mock.method(cas, 'publish', async (bytes: Uint8Array) => {
    active++;
    try {
      const ref = await original(bytes);
      if (ref === plans[0]!.ref) { enterFirst(); throw ordinary; }
      assert.equal(ref, plans[1]!.ref); enterSecond(); await gate; throw retirement;
    } finally { active--; }
  });
  const pending = publish(artifacts, plans);
  void pending.then(() => { settled = true; }, () => { settled = true; });
  try {
    await Promise.all([first, second]); await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(settled, false, 'failure cannot detach an already-issued real publication return');
    assert.equal(active, 1);
    release(); await assert.rejects(pending, error => error === retirement);
    assert.equal(active, 0);
    for (const plan of plans) assert.deepEqual(await artifacts.readBytes(plan.ref), Buffer.from(plan.bytes));
  } finally { release(); await Promise.allSettled([pending]); assert.equal(active, 0); }
});

test('admission metadata lazily describes every original fixed and credential ref in original order', async t => {
  const source = await readFile(new URL('./reducers/admission.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('admission-metadata-data.ts', source, ts.ScriptTarget.Latest, true);
  const expressions: ts.Expression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(parsed) === 'referencedMetadata' && node.initializer) expressions.push(node.initializer);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(expressions.length, 1);
  assert(ts.isAwaitExpression(expressions[0]!));
  const call = expressions[0]!.expression;
  assert(ts.isCallExpression(call)); assert.equal(call.expression.getText(parsed), 'reads.mapReads');
  const output = ts.transpileModule(`return (async () => ${expressions[0]!.getText(parsed)})();`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const execute = new Function('readCanonicalArtifact', 'canonicalJsonBytes', 'input', 'sourceManifest', 'reads', output);
  const read = (input: Record<string, unknown>, source: { entriesRef: string }, reads: ArtifactCatalog) =>
    execute(readCanonicalArtifact, canonicalJsonBytes, input, source, reads) as Promise<PublishedArtifact[]>;
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-admission-metadata-pool-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  const kinds = ['cliq-run-assembly-v1', 'cliq-run-policy-v1', 'cliq-sandbox-profile-v1', 'cliq-verifier-spec-v1',
    'cliq-source-projection-v1', 'cliq-frozen-ignore-rules-v1', 'cliq-source-manifest-v1', 'cliq-workspace-entries-v1',
    'cliq-endpoint-credential-grant-binding-v1'];
  const refs: string[] = [];
  for (const index of kinds.keys()) refs.push((await artifacts.publishCanonical({ inert: index }, 'plain-test-data')).ref);
  const names = ['assemblyRef', 'policyRef', 'sandboxProfileRef', 'verifierSpecRef', 'sourceProjectionRef', 'frozenIgnoreRulesRef', 'baseWorkspaceManifestRef'];
  const input = { ...Object.fromEntries(names.map((name, index) => [name, refs[index]!])), credentialGrantRefs: [refs[8]!] };
  const metadata = await read(input, { entriesRef: refs[7]! }, artifacts);
  assert.deepEqual(metadata.map(value => value.ref), refs);
  assert.deepEqual(metadata.map(value => value.schemaKind), kinds);
  assert(metadata.every(value => value.mediaType === 'application/json' && value.byteLength > 0));
});
