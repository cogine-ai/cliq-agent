// Execute the original private publication boundary with real CAS operations.
// These inert bytes create no StateOwner, Run, grant or execution authority.
import assert from 'node:assert/strict';
import { promises as fs, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import ts from 'typescript';
import { ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { ResourceRetirementError } from './errors.js';

function publisher(artifacts: ArtifactCatalog, signal: AbortSignal): (value: unknown, kind: string) => Promise<PublishedArtifact> {
  const source = readFileSync(new URL('./reducers/admission.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('admission.ts', source, ts.ScriptTarget.Latest, true);
  const admission = parsed.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'admitRunInternal');
  assert(admission?.body);
  const publications: ts.VariableDeclaration[] = [], raw: ts.CallExpression[] = [], guarded: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(parsed) === 'publish') publications.push(node);
    if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'artifacts.publishCanonical') raw.push(node);
    if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'publish') guarded.push(node);
    ts.forEachChild(node, visit);
  };
  visit(admission.body);
  assert.equal(publications.length, 1); assert(publications[0]!.initializer);
  assert.equal(raw.length, 1, 'only the guarded boundary may start a raw admission publication');
  assert.equal(guarded.length, 10, 'every original independent admission artifact retains its publication');
  const body = ts.transpileModule('return ' + publications[0]!.initializer!.getText(parsed), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText;
  return new Function('artifacts', 'signal', body)(artifacts, signal);
}

test('revoked admission starts no new CAS publication', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-admission-revoked-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const owner = new AbortController(), reason = new Error('original preparation revoked'); owner.abort(reason);
  const publish = publisher(new ArtifactCatalog(new ContentAddressedStore(directory)), owner.signal);
  let opened = 0;
  t.mock.method(fs, 'open', async () => { opened++; throw new Error('revoked work opened CAS'); });
  await assert.rejects(publish({ inert: true }, 'inert-publication-v1'), error => error === reason);
  assert.equal(opened, 0); assert.deepEqual(await fs.readdir(directory), []);
});

for (const fault of ['cancel', 'retirement'] as const)
  test(`admission joins its original complete publication before reporting ${fault} and starts no successor`, async t => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-admission-publication-'));
    t.after(() => fs.rm(directory, { recursive: true, force: true }));
    const catalog = new ArtifactCatalog(new ContentAddressedStore(directory));
    const owner = new AbortController(), reason = new Error('original preparation revoked');
    const failure = new Error('original root close reported uncertainty');
    const publish = publisher(catalog, owner.signal), open = fs.open.bind(fs), active = new Set<object>();
    let enter!: () => void, release!: () => void, settled = false, roots = 0;
    const entered = new Promise<void>(resolve => { enter = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const fd = await open(...args); active.add(fd);
      const close = fd.close.bind(fd);
      t.mock.method(fd, 'close', async () => {
        await close(); assert(active.delete(fd));
        if (args[0] === directory && ++roots === 1) {
          enter(); await gate;
          if (fault === 'retirement') throw failure;
        }
      });
      return fd;
    });
    const bytes = { inert: true, text: 'complete original publication' };
    const work = (async () => { await publish(bytes, 'inert-publication-v1'); await publish({ successor: true }, 'inert-publication-v1'); })();
    void work.then(() => { settled = true; }, () => { settled = true; });
    try {
      await entered; assert.equal(active.size, 0);
      owner.abort(reason); await setImmediate();
      assert.equal(settled, false, 'revocation cannot detach the original publisher');
      release();
      await assert.rejects(work, error => fault === 'cancel' ? error === reason
        : error instanceof ResourceRetirementError && error.cause === failure);
      assert.equal(active.size, 0); assert.equal(roots, 1, 'a revoked admission never starts the successor');
      const names = await fs.readdir(directory); assert.equal(names.length, 1);
      assert.match(names[0]!, /^[a-f0-9]{64}$/u);
      assert.deepEqual(await catalog.readCanonical(names[0]!), bytes, 'all original bytes remain independently verifiable');
    } finally { release(); await Promise.allSettled([work]); t.mock.restoreAll(); }
  });
