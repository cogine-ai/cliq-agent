import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, mkdtemp, writeFile, rm, cp, mkdir } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { buildInstalledClientDriver, fixedInstalledInkSource, installedClientBuildOptions } from './installed-client-build.js';

test('fixed locked Ink source rejects changed hashes, condition counts and unknown module identities', async () => {
  const directory = path.dirname(path.dirname(fileURLToPath(import.meta.resolve('ink'))));
  for (const name of ['ink.js', 'reconciler.js']) {
    const bytes = await readFile(path.join(directory, 'build', name));
    assert.equal(fixedInstalledInkSource(name, bytes).includes("process.env['DEV'] === 'true'"), false);
    assert.throws(() => fixedInstalledInkSource(name, Buffer.from(bytes.toString().replace("process.env['DEV'] === 'true'", 'false'))), /condition count/u);
    const changed = Buffer.from(bytes); changed[0] = changed[0] === 47 ? 32 : 47;
    assert.throws(() => fixedInstalledInkSource(name, changed), /hash/u);
  }
  assert.throws(() => fixedInstalledInkSource('other.js', Buffer.from('')));
});

test('actual standalone client bundle keeps its Node-only dependencies, original size bound and live Ink rendering', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-client-bundle-'));
  try {
    const driver = await buildInstalledClientDriver(path.join(home, 'driver.mjs'));
    assert(driver.length > 0 && driver.length <= 16 * 1024 * 1024);
    const input = `import {render} from 'ink-testing-library';import React from 'react';
      import {ClientTui} from ${JSON.stringify(fileURLToPath(new URL('../../../src/client/tui.tsx', import.meta.url)))};
      import {createClientApplication} from ${JSON.stringify(fileURLToPath(new URL('../../../src/client/application.ts', import.meta.url)))};
      import {protocolClient,outputStream} from ${JSON.stringify(fileURLToPath(new URL('../../../src/client/testing/protocol.ts', import.meta.url)))};
      import{PassThrough}from'node:stream'; const f=protocolClient(),app=createClientApplication(f.session,()=>{}),input=new PassThrough();
      const ui=render(React.createElement(ClientTui,{app,io:{input,output:outputStream().stream,diagnostic:outputStream().stream,workspacePath:'/workspace'}}));
      await new Promise(resolve=>setImmediate(resolve));if(!ui.lastFrame().includes('Cliq'))throw Error('actual Ink did not render');
      ui.unmount();await app.close();process.stdout.write('owned compiled Ink component joined\\n');`;
    const fixture = await build({ stdin: { contents: input, resolveDir: process.cwd(), loader: 'js' }, outfile: path.join(home, 'fixture.mjs'),
      bundle: true, platform: 'node', format: 'esm', target: 'node22.13', write: false, ...installedClientBuildOptions() });
    await writeFile(path.join(home, 'fixture.mjs'), fixture.outputFiles![0]!.contents, { flag: 'wx', mode: 0o600 });
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(home, 'fixture.mjs')],
      { env: { ...process.env, DEV: 'true' }, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout: Buffer[] = [], stderr: Buffer[] = []; let bytes = 0, failure: unknown;
    const collect = (target: Buffer[]) => (value: Buffer) => {
      bytes += value.length;
      if (bytes > 65536) { failure ??= new Error('owned compiled component exceeded its fixed output bound'); child.kill('SIGKILL'); return; }
      target.push(Buffer.from(value));
    };
    child.stdout.on('data', collect(stdout)); child.stderr.on('data', collect(stderr));
    const timer = setTimeout(() => { failure ??= new Error('owned compiled component did not exit'); child.kill('SIGKILL'); }, 10000);
    let result: { code: number | null; signal: string | null };
    try { result = await new Promise((resolve) => {
      child.once('error', error => { failure ??= error; }); child.once('close', (code, signal) => resolve({ code, signal }));
    }); } finally { clearTimeout(timer); }
    assert.equal(failure, undefined);
    assert.equal(result.code, 0); assert.equal(result.signal, null); assert.equal(Buffer.concat(stderr).length, 0);
    assert.equal(Buffer.concat(stdout).toString(), 'owned compiled Ink component joined\n');
  } finally { await rm(home, { recursive: true, force: true }); }
});

test('independent source builds bind their own exact locked Ink tree and reject another source or ambient fallback', async () => {
  const home = await mkdtemp(path.join(process.cwd(), '.cliq-client-source-roots-'));
  const installed = path.dirname(path.dirname(fileURLToPath(import.meta.resolve('ink'))));
  try {
    const roots = [path.join(home, 'old-source'), path.join(home, 'new-source')];
    for (const root of roots) {
      await mkdir(path.join(root, 'node_modules'), { recursive: true });
      await cp(installed, path.join(root, 'node_modules', 'ink'), { recursive: true, errorOnExist: true, force: false });
      await writeFile(path.join(root, 'package.json'), '{"private":true,"type":"module"}', { flag: 'wx', mode: 0o644 });
      await writeFile(path.join(root, 'entry.mjs'), "export {render} from 'ink';", { flag: 'wx', mode: 0o644 });
    }
    const bundle = async (root: string, entryRoot = root) => {
      const result = await build({ entryPoints: [path.join(entryRoot, 'entry.mjs')], outfile: path.join(home, 'bundle.mjs'),
        bundle: true, platform: 'node', format: 'esm', target: 'node22.13', write: false, metafile: true,
        logLevel: 'silent', ...installedClientBuildOptions(root) });
      assert.equal(result.outputFiles!.length, 1);
      assert(result.outputFiles![0]!.contents.length > 0 && result.outputFiles![0]!.contents.length <= 16 * 1024 * 1024);
      assert(Object.values(result.metafile!.outputs).flatMap(output => output.imports).every(item => item.external && item.path.startsWith('node:')));
    };
    await bundle(roots[0]!); await bundle(roots[1]!);
    await assert.rejects(bundle(roots[0]!, roots[1]!), /fixed-installed-client-dependencies/u);
    const absent = path.join(home, 'missing-owned-dependency'); await mkdir(absent);
    await writeFile(path.join(absent, 'package.json'), '{"private":true,"type":"module"}', { flag: 'wx', mode: 0o644 });
    assert.throws(() => installedClientBuildOptions(absent), 'a parent node_modules tree cannot replace the selected source dependency');
    const filename = path.join(roots[0]!, 'node_modules', 'ink', 'build', 'ink.js'), changed = Buffer.from(await readFile(filename));
    changed[0] = changed[0] === 47 ? 32 : 47; await writeFile(filename, changed);
    await assert.rejects(bundle(roots[0]!), /fixed Ink source hash changed/u);
  } finally { await rm(home, { recursive: true, force: true }); }
});
