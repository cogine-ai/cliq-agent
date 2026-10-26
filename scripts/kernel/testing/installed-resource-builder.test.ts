import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { Script } from 'node:vm';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { build, transformSync } from 'esbuild';
import ts from 'typescript';
import { INSTALLED_RESOURCE_SUBSCRIBER } from './supervisor-sea-builder.js';
import { decodeInstalledResourceLine } from './installed-resource-wire.js';

test('actual qualification injection is opt-in, fixed and contained; default image adds no probe I/O', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-resource-image-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = fileURLToPath(new URL('../../../src/state/installed-resource-diagnostics.ts', import.meta.url));
  const input = path.join(root, 'entry.ts');
  await writeFile(input, `import { noteInstalledResourceBoundary } from ${JSON.stringify(source)};
    let borrowed = 0;
    noteInstalledResourceBoundary('preparation_ready', () => { borrowed++; throw Error('no original installed root in this inert fixture'); });
    process.stdout.write(String(borrowed));`);
  for (const enabled of [false, true]) {
    const output = path.join(root, enabled ? 'observed.cjs' : 'default.cjs');
    await build({ entryPoints: [input], outfile: output, bundle: true, platform: 'node', format: 'cjs', target: 'node22',
      ...(enabled ? { inject: [INSTALLED_RESOURCE_SUBSCRIBER] } : {}) });
    const result = await promisify(execFile)(process.execPath, [output], { timeout: 5000, maxBuffer: 16384 });
    assert.equal(result.stdout, enabled ? '1' : '0');
    if (enabled) {
      const actual = decodeInstalledResourceLine(Buffer.from(result.stderr));
      assert.equal(actual.role, 'supervisor'); assert.equal(actual.boundary, 'preparation_ready');
      assert.equal(actual.numbers.mask, 0); assert.equal(actual.numbers.unavailable, 2);
    } else assert.equal(result.stderr, '');
  }
  // This executes the same injected module in a real plain Node child. It is
  // deliberately not an installation, signed image or native authority test.
});

test('the actual controller measurement callback performs no I/O during original close or abort joins', async () => {
  const source = await readFile(new URL('../../../src/sandbox/linux-worker.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('linux-worker.ts', source, ts.ScriptTarget.Latest, true);
  let actual: ts.ArrowFunction | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(parsed) === 'noteResources' && node.initializer && ts.isArrowFunction(node.initializer)) actual = node.initializer;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(actual);
  for (const closed of ['controllerClosed', 'controllerAbort', 'installationAbort', 'signal', 'none']) {
    let reads = 0;
    const context = { controllerClosed: closed === 'controllerClosed', controllerAbort: { signal: { aborted: closed === 'controllerAbort' } },
      installationAbort: { signal: { aborted: closed === 'installationAbort' } }, signal: { aborted: closed === 'signal' },
      birthIdentity: { pid: 1, processStartToken: 'inert-data', leaf: { deviceId: '1', fileId: '2' }, leafName: 'inert-data' },
      source: { noteResources() { reads++; } }, probe: undefined as unknown as (boundary: string) => void };
    new Script(transformSync('globalThis.probe=' + actual.getText(parsed), { loader: 'ts' }).code).runInNewContext(context);
    context.probe('capture_durable'); assert.equal(reads, closed === 'none' ? 1 : 0);
  }
  assert(!/await\b|setTimeout|setInterval/u.test(actual.getText(parsed)));
  // Only the real passive callback is executed with inert data. No fake
  // controller, authority, worker, death receipt or qualification is created.
});
