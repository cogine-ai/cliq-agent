// Component verification of the actual packed package in an external Node
// consumer. No installation, release trust, Store, provider or network call.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const root = fileURLToPath(new URL('../', import.meta.url));
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'cliq-sdk-packed-'));
const env = { ...process.env, PATH: path.dirname(process.execPath) + path.delimiter + process.env.PATH,
  npm_config_audit: 'false', npm_config_fund: 'false', npm_config_update_notifier: 'false' };
function run(command, args, cwd = root) {
  const result = spawnSync(command, args, { cwd, env, encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 * 1024 });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, `${path.basename(command)} failed: ${result.stderr.slice(-4096)}`);
  return result.stdout;
}
// --ignore-scripts means this consumes a completed ordinary build; it cannot
// secretly rebuild the package or acquire any missing dependency from npm.
const packed = JSON.parse(run('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', fixture]));
assert(Array.isArray(packed) && packed.length === 1);
const inventory = packed[0];
assert(inventory.files.length > 0 && inventory.files.length <= 2048);
const declarations = inventory.files.filter(file => file.path.endsWith('.d.ts'));
assert(declarations.length > 0);
for (const file of inventory.files) {
  assert(!file.path.split('/').includes('..') && !path.isAbsolute(file.path));
  assert(!file.path.endsWith('.test.js') && !file.path.endsWith('.test.d.ts'));
  if (file.path.endsWith('.d.ts')) assert(!/^dist\/(state|sandbox|runtime)\//u.test(file.path), 'private authority declarations escaped');
}
const modules = path.join(fixture, 'node_modules'), packageDir = path.join(modules, '@cogineai/cliq');
fs.mkdirSync(packageDir, { recursive: true });
run('/usr/bin/tar', ['-xzf', path.join(fixture, inventory.filename), '--strip-components=1', '-C', packageDir]);
// Reuse only already installed, locked production dependencies, as real files
// in the external consumer. Offline npm cannot populate an uncached package;
// no repository symlink, tsx or other development runtime may fill that gap.
const dependencies = run('npm', ['ls', '--omit=dev', '--all', '--parseable']).trim().split('\n');
assert(path.resolve(dependencies.shift()) === path.resolve(root));
const copied = new Set();
for (const directory of dependencies) {
  const marker = path.sep + 'node_modules' + path.sep, at = directory.lastIndexOf(marker);
  assert(at >= 0);
  const name = directory.slice(at + marker.length);
  assert(!name.split(path.sep).includes('..') && !path.isAbsolute(name));
  assert(!['tsx', 'typescript', 'esbuild', 'ink-testing-library'].includes(name));
  const destination = path.join(modules, name);
  if (!copied.has(name)) { fs.cpSync(directory, destination, { recursive: true, dereference: true }); copied.add(name); }
}
fs.writeFileSync(path.join(fixture, 'package.json'), '{"private":true,"type":"module"}\n');
fs.writeFileSync(path.join(fixture, 'smoke.mjs'), `
import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
const before = await readdir('.');
const sdk = await import('@cogineai/cliq');
const protocol = await import('@cogineai/cliq/control/v1');
assert.equal(typeof sdk.openCliqClient, 'function');
assert.equal(protocol.HEADLESS_SCHEMA_VERSION, 3);
for (const name of ['openStateStore','createInstalledRuntime','mintOperationGrant']) assert(!Object.hasOwn(sdk,name));
await assert.rejects(import('@cogineai/cliq/state/store'), {code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});
let traps = 0;
await assert.rejects(sdk.openCliqClient(new Proxy({}, {get(){traps++;throw new Error('must not inspect caller');}})));
assert.equal(traps, 0);
assert.deepEqual(await readdir('.'), before);
process.stdout.write('PACKED_SDK_IMPORT_OK\\n');
`);
const smoke = run(process.execPath, ['smoke.mjs'], fixture);
assert.equal(smoke, 'PACKED_SDK_IMPORT_OK\n');
// TypeScript is a verification tool outside the packed runtime. Only its
// compiler and Node typing inputs come from devDependencies; all SDK imports
// below resolve through the actual external package's exports and .d.ts graph.
const typeRoot = path.join(fixture, 'compiler/node_modules/@types');
fs.mkdirSync(typeRoot, { recursive: true });
fs.cpSync(path.join(root, 'node_modules/@types/node'), path.join(typeRoot, 'node'), { recursive: true, dereference: true });
fs.cpSync(path.join(root, 'node_modules/undici-types'), path.join(fixture, 'compiler/node_modules/undici-types'), { recursive: true, dereference: true });
fs.writeFileSync(path.join(fixture, 'consumer.ts'), `
import {openCliqClient,clientMutation,type CliqClient,type ClientUpdate} from '@cogineai/cliq';
import {decodeInstalledControlRequest,type InstalledControlRequestV1} from '@cogineai/cliq/control/v1';
declare const genuineInstallationFromTrustedHost: object;
async function example(){
 const output=(update:ClientUpdate)=>{if(update.kind==='response')void update.response.ok;};
 const client:CliqClient=await openCliqClient(genuineInstallationFromTrustedHost,output);
 const request:InstalledControlRequestV1=decodeInstalledControlRequest({protocolVersion:1,method:'run.get',runId:'original'});
 await client.execute({kind:'request',request});
 await client.execute({kind:'request',request:clientMutation({protocolVersion:1,method:'run.cancel',runId:'original',expectedRevision:1})});
 if(client.pendingRequest){await client.execute({kind:'reconnect'});await client.replay();}
 await client.close();
}
void example;
// @ts-expect-error private authority is not a public SDK subpath
import {openStateStore} from '@cogineai/cliq/state/store';
void openStateStore;
`);
run(process.execPath, [path.join(root, 'node_modules/typescript/bin/tsc'), '--strict', '--noEmit', '--skipLibCheck', 'false',
  '--target', 'es2022', '--module', 'nodenext', '--moduleResolution', 'nodenext', '--typeRoots', typeRoot, 'consumer.ts'], fixture);
process.stdout.write(JSON.stringify({ componentOnly: true, node: process.versions.node, fixture,
  package: inventory.filename, packageSha512: inventory.integrity, declarations: declarations.length,
  copiedProductionDependencies: copied.size, importAndStrictTypes: true, linuxQualification: false }) + '\n');
