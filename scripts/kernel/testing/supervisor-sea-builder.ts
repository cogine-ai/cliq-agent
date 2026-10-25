// Qualification-only carrier/image construction. Never a production loader.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, open, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { build } from 'esbuild';
import { inject } from 'postject';
import { INSTALLED_CREDENTIAL_PHASE_CHANNEL, INSTALLED_CREDENTIAL_PHASES,
  INSTALLED_SERVER_AUTHENTICATION_CHANNEL, INSTALLED_SERVER_AUTHENTICATION_PHASES } from '../../../src/state/installed-diagnostics.js';
import { INSTALLED_WORK_CHANNEL } from '../../../src/state/installed-work-diagnostics.js';
import { PUBLICATION_RETIREMENT_CHANNEL } from '../../../src/state/publication-retirement-diagnostics.js';
import { INSTALLED_STORE_DIAGNOSTIC_BANNER } from './installed-store-diagnostic-banner.js';
import { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER } from './installed-assembly-work-banner.js';
import { compareSupervisorCarrierLayout } from './supervisor-carrier-layout.js';
export { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER } from './installed-assembly-work-banner.js';

export const SUPERVISOR_SEA_NODE_VERSION = '24.21.0';
export const SUPERVISOR_SEA_CARRIER_CHECKSUMS: Readonly<Record<string, string>> = {
  'linux-x64': 'fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6',
  'darwin-arm64': '6239d4cf92d864487ec8cd3615038f7b67e7f58b77b21cd2f09ea9fbd68065fe',
};

// Fixed trusted composition, not caller-supplied banner code or a runtime
// option. The subscriber itself must catch every error: diagnostics_channel
// reports subscriber throws as uncaught exceptions outside publish().
export const CREDENTIAL_PHASE_DIAGNOSTIC_BANNER = `;(() => { try {
  const diagnostic = require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_CREDENTIAL_PHASE_CHANNEL)});
  const phases = new Set(${JSON.stringify(INSTALLED_CREDENTIAL_PHASES)}), write = require('node:fs').writeSync;
  diagnostic.subscribe(phase => { try {
    if (typeof phase === 'string' && phases.has(phase)) write(2, 'CLIQ_CREDENTIAL_PHASE_V1:' + phase + '\\n');
  } catch {} });
} catch {} })();`;

// Fixed test-image subscription only. Each span is the complete original JS
// await, not an individual native syscall or a deadline/authority assertion.
export const SERVER_AUTHENTICATION_DIAGNOSTIC_BANNER = `;(() => { try {
  const diagnostic = require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_SERVER_AUTHENTICATION_CHANNEL)});
  const phases = new Set(['publish_started', ...${JSON.stringify(INSTALLED_SERVER_AUTHENTICATION_PHASES)}
    .flatMap(phase => [phase + '_completed', phase + '_failed'])]);
  const write = require('node:fs').writeSync, isProxy = require('node:util').types.isProxy, prefix = 'CLIQ_SERVER_AUTH_V1:';
  let emitted = 0, stopped = false;
  diagnostic.subscribe(value => { try {
    if (stopped || !value || typeof value !== 'object' || isProxy(value) || Array.isArray(value)) return;
    const fields = Object.getOwnPropertyDescriptors(value), keys = ['ordinal', 'phase', 'elapsedNs'];
    if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !fields[key] ||
        !Object.hasOwn(fields[key], 'value') || !fields[key].enumerable)) return;
    const ordinal = fields.ordinal.value, phase = fields.phase.value, elapsed = fields.elapsedNs.value;
    if (!Number.isSafeInteger(ordinal) || ordinal < 1 || typeof phase !== 'string' || !phases.has(phase) ||
        !Number.isSafeInteger(elapsed) || elapsed < 0 || phase === 'publish_started' && elapsed !== 0) return;
    if (emitted >= 64) { stopped = true; try { write(2, prefix + 'truncated\\n'); } catch {} return; }
    const frame = prefix + ordinal + ':' + phase + ':' + elapsed + '\\n';
    if (frame.length > 128) return;
    emitted++; try { if (write(2, frame) !== frame.length) stopped = true; } catch { stopped = true; }
  } catch {} });
} catch {} })();`;

// No timer or arbitrary serialization. This subscriber belongs only to the
// trusted disposable image. Every getter/output error is contained here, not
// delegated to diagnostics_channel's publish() exception behavior.
export const INSTALLED_WORK_DIAGNOSTIC_BANNER = `;(() => { try {
  const role = process.argv[2] === '--bootstrap-credential' ? 'bootstrap'
    : process.argv[2] === '--installed-credential' ? 'credential' : undefined;
  if (!role) return;
  const diagnostic = require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_WORK_CHANNEL)});
  const write = require('node:fs').writeSync;
  let emitted = 0, stopped = false;
  const truncate = () => { if (!stopped) { stopped = true; write(2, 'CLIQ_INSTALLED_WORK_V1:' + role + ':truncated\\n'); } };
  const values = (object, keys) => {
    if (!object || typeof object !== 'object' || Array.isArray(object)) throw 0;
    const fields = Object.getOwnPropertyDescriptors(object);
    if (Reflect.ownKeys(fields).length !== keys.length) throw 0;
    return keys.map(key => { const field = fields[key];
      if (!field || !Object.hasOwn(field, 'value')) throw 0; return field.value; });
  };
  diagnostic.subscribe(snapshot => { try {
    if (stopped) return;
    if (snapshot === 'truncated') { truncate(); return; }
    const rows = values(snapshot, ['package', 'revalidate', 'createCompare']);
    const numbers = rows.flatMap(row => {
      const result = values(row, ['started', 'completed', 'bytesRead', 'spanElapsedMs']);
      if (!result.every(value => Number.isSafeInteger(value) && value >= 0) || result[1] > result[0]) throw 0;
      return result;
    });
    if (numbers[10] !== 0) return;
    const frame = 'CLIQ_INSTALLED_WORK_V1:' + role + ':' + numbers.join(':') + '\\n';
    if (frame.length > 256) { truncate(); return; }
    if (emitted >= 256) { truncate(); return; }
    emitted++; write(2, frame);
  } catch {} });
} catch {} })();`;

// Fixed qualification composition only. Never serialize an arbitrary packet,
// invoke its getters, or let a broken diagnostic sink affect the producer.
export const PUBLICATION_RETIREMENT_DIAGNOSTIC_BANNER = `;(() => { try {
  const diagnostic = require('node:diagnostics_channel').channel(${JSON.stringify(PUBLICATION_RETIREMENT_CHANNEL)});
  const write = require('node:fs').writeSync, prefix = 'CLIQ_PUBLICATION_RETIRE_V1:';
  let emitted = 0, stopped = false;
  const values = (object, keys) => {
    if (!object || typeof object !== 'object') throw 0;
    const fields = Object.getOwnPropertyDescriptors(object);
    if (Reflect.ownKeys(fields).length !== keys.length) throw 0;
    return keys.map(key => { const field = fields[key];
      if (!field || !Object.hasOwn(field, 'value') || key !== 'length' && !field.enumerable) throw 0; return field.value; });
  };
  const array = (value, length) => {
    if (!Array.isArray(value)) throw 0;
    const keys = Array.from({length}, (_, index) => String(index));
    const fields = values(value, [...keys, 'length']);
    if (fields.pop() !== length) throw 0; return fields;
  };
  const time = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= 18446744073709551615n;
  const output = text => { try { if (write(2, text) !== text.length) stopped = true; } catch { stopped = true; } };
  diagnostic.subscribe(packet => { try {
    if (stopped || Array.isArray(packet)) return;
    const [version, key, kind, joined, input] = values(packet, ['version', 'key', 'kind', 'joined', 'slots']);
    if (version !== 1 || typeof key !== 'string' || !/^[a-f0-9]{64}$/.test(key) ||
        kind !== 'original' && kind !== 'namespace' || joined !== true) return;
    const slots = array(input, 3), head = prefix + key + ':' + kind + ':';
    const frames = slots.map((slot, index) => {
      if (slot === null) { if (index !== 0) throw 0; return head + index + ':none\\n'; }
      if (!Array.isArray(slot)) throw 0;
      const length = Object.getOwnPropertyDescriptor(slot, 'length');
      const row = array(slot, length && Object.hasOwn(length, 'value') && length.value === 3 ? 3 : 7), [calls, attempts, outcome] = row;
      if (!Number.isSafeInteger(calls) || calls < 1 || calls > 0xffffffff ||
          !Number.isSafeInteger(attempts) || attempts < calls || attempts > 0xffffffff) throw 0;
      if (row.length === 3) { if (outcome !== 'unavailable') throw 0; }
      else if (!['ok', 'interrupted', 'error'].includes(outcome) || !row.slice(3).every(time) ||
          BigInt(row[5]) < BigInt(row[3]) || BigInt(row[6]) < BigInt(row[4])) throw 0;
      return head + index + ':' + row.join(':') + '\\n';
    });
    frames.push(head + 'joined\\n');
    if (frames.some(frame => frame.length > 256) || frames.join('').length > 1024) return;
    if (emitted >= 32) { stopped = true; try { write(2, prefix + 'truncated\\n'); } catch {} return; }
    emitted++; output(frames.join(''));
  } catch {} });
} catch {} })();`;

function run(fixture: string, executable: string, args: string[]) {
  const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 60_000, cwd: fixture,
    maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.error, undefined, `${executable}: ${result.error}`);
  assert.equal(result.status, 0, `${executable}: ${result.stderr}`);
  return result;
}

export async function prepareSupervisorSeaCarrier(fixture: string, cachedArchive?: string) {
  const platform = `${process.platform}-${process.arch}`;
  const checksum = SUPERVISOR_SEA_CARRIER_CHECKSUMS[platform];
  assert(checksum, `no qualified SEA carrier for ${platform}`);
  const archiveName = `node-v${SUPERVISOR_SEA_NODE_VERSION}-${platform}.tar.xz`;
  const nodeRoot = path.join(fixture, `node-v${SUPERVISOR_SEA_NODE_VERSION}-${platform}`);
  await assert.rejects(lstat(nodeRoot), { code: 'ENOENT' }, 'carrier extraction directory must not already exist');
  // A read-only cache is still checked in full before fresh extraction; never
  // reuse/adopt an already extracted executable or native-header directory.
  const archive = cachedArchive ? await readFile(cachedArchive) : await (async () => {
    const response = await fetch(`https://nodejs.org/download/release/v${SUPERVISOR_SEA_NODE_VERSION}/${archiveName}`,
      { signal: AbortSignal.timeout(60_000) });
    assert(response.ok, `carrier download failed: ${response.status}`);
    return Buffer.from(await response.arrayBuffer());
  })();
  assert.equal(createHash('sha256').update(archive).digest('hex'), checksum, 'official carrier checksum mismatch');
  const archivePath = path.join(fixture, archiveName);
  await writeFile(archivePath, archive, { flag: 'wx', mode: 0o600 });
  // Create fresh files owned by this builder, including when invoked as root;
  // archived publisher uid/gid are not local protected-source authority.
  run(fixture, 'tar', ['--no-same-owner', '-xJf', archivePath, '-C', fixture]);
  const carrier = path.join(nodeRoot, 'bin/node');
  assert.equal(run(fixture, carrier, ['--version']).stdout.trim(), `v${SUPERVISOR_SEA_NODE_VERSION}`);
  return { nodeRoot, carrier };
}

/** Fixed publisher derivation, never a runtime option or loader shortcut.
 * The original carrier remains the input to guest/component recipes. Only
 * the Supervisor's new signed SEA image uses the smaller derived carrier;
 * complete installed, guest and READY qualification remains independent. */
export async function prepareInstalledSupervisorSeaCarrier(fixture: string, cachedArchive?: string) {
  const original = await prepareSupervisorSeaCarrier(fixture, cachedArchive);
  if (process.platform !== 'linux') return { ...original, supervisorCarrier: original.carrier };
  assert.equal(process.arch, 'x64', 'only the fixed Linux x64 carrier has a metadata derivation');
  const directory = await lstat(fixture, { bigint: true });
  assert(directory.isDirectory() && directory.uid === BigInt(process.geteuid!()) && (directory.mode & 0o077n) === 0n,
    'carrier derivation requires the publisher private fixture');
  const fields = ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const;
  const held = async (filename: string, maxBytes = 268_435_456) => {
    const fd = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const before = await fd.stat({ bigint: true });
      assert(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= BigInt(maxBytes),
        'carrier derivation requires a bounded single-link regular input');
      const bytes = await fd.readFile(); assert.equal(BigInt(bytes.length), before.size);
      for (const after of [await fd.stat({ bigint: true }), await lstat(filename, { bigint: true })])
        for (const key of fields) assert.equal(after[key], before[key], 'carrier derivation input changed');
      return { bytes, identity: before, sha256: createHash('sha256').update(bytes).digest('hex') };
    } finally { await fd.close(); }
  };
  const unchanged = async (filename: string, before: Awaited<ReturnType<typeof held>>) => {
    const after = await held(filename, before.bytes.length); assert.equal(after.sha256, before.sha256);
    for (const key of fields) assert.equal(after.identity[key], before.identity[key], 'publisher input identity changed');
  };
  const execute = (executable: string, args: string[], expected?: string) => {
    const child = spawnSync(executable, args, { cwd: fixture, encoding: 'utf8', timeout: 60_000, maxBuffer: 65_536,
      env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' } });
    assert.equal(child.error, undefined, 'publisher derivation process did not join');
    assert.equal(child.signal, null); assert.equal(child.status, 0, 'publisher derivation failed');
    assert.equal(child.stderr, ''); if (expected !== undefined) assert.equal(child.stdout, expected);
    return child.stdout;
  };
  const input = await held(original.carrier);
  assert.equal(input.identity.uid, BigInt(process.geteuid!()));
  assert.equal(input.sha256, '7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c',
    'derivation accepts only the complete fixed official Node image');
  const strip = await realpath('/usr/bin/strip'), tool = await held(strip, 16_777_216);
  assert.equal(tool.identity.uid, 0n); assert.equal(tool.identity.mode & 0o022n, 0n);
  assert(/^GNU strip \([\x20-\x7e]{1,96}\) [0-9][\x20-\x7e]{0,48}$/u.test(execute(strip, ['--version']).split('\n')[0]!));
  const supervisorCarrier = path.join(fixture, 'supervisor-carrier-static');
  await copyFile(original.carrier, supervisorCarrier, constants.COPYFILE_EXCL);
  execute(strip, ['--strip-all', '--no-merge-notes', '--', supervisorCarrier]);
  await chmod(supervisorCarrier, 0o500);
  const selected = await held(supervisorCarrier);
  assert.equal(selected.identity.uid, BigInt(process.geteuid!()));
  compareSupervisorCarrierLayout(input.bytes, selected.bytes, 'static');
  execute(supervisorCarrier, ['--version'], `v${SUPERVISOR_SEA_NODE_VERSION}\n`);
  await unchanged(original.carrier, input); await unchanged(strip, tool); await unchanged(supervisorCarrier, selected);
  const file = await open(supervisorCarrier, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const current = await file.stat({ bigint: true });
    for (const key of fields) assert.equal(current[key], selected.identity[key]);
    await file.sync();
  } finally { await file.close(); }
  const parent = await open(fixture, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const current = await parent.stat({ bigint: true });
    for (const key of ['dev', 'ino', 'uid', 'gid', 'mode'] as const) assert.equal(current[key], directory[key]);
    await parent.sync();
  } finally { await parent.close(); }
  await unchanged(supervisorCarrier, selected);
  return { ...original, supervisorCarrier };
}

export async function buildSupervisorSeaImage(input: {
  fixture: string; carrier: string; entryPoint: string; executable: string;
  variant: string; assets: Record<string, string>; defines?: Record<string, string>;
  credentialPhaseDiagnostics?: true;
  publicationRetirementDiagnostics?: true;
  serverAuthenticationDiagnostics?: true;
  storeFailureDiagnostics?: true;
}): Promise<string> {
  assert(input.credentialPhaseDiagnostics === undefined || input.credentialPhaseDiagnostics === true);
  assert(input.publicationRetirementDiagnostics === undefined || input.publicationRetirementDiagnostics === true);
  assert(input.serverAuthenticationDiagnostics === undefined || input.serverAuthenticationDiagnostics === true);
  assert(input.storeFailureDiagnostics === undefined || input.storeFailureDiagnostics === true);
  const banner = (input.credentialPhaseDiagnostics ? CREDENTIAL_PHASE_DIAGNOSTIC_BANNER + INSTALLED_WORK_DIAGNOSTIC_BANNER : '') +
    (input.publicationRetirementDiagnostics ? PUBLICATION_RETIREMENT_DIAGNOSTIC_BANNER : '') +
    (input.serverAuthenticationDiagnostics ? SERVER_AUTHENTICATION_DIAGNOSTIC_BANNER : '') +
    (input.storeFailureDiagnostics ? INSTALLED_STORE_DIAGNOSTIC_BANNER + INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER : '');
  const main = path.join(input.fixture, `${input.variant}.cjs`);
  const result = await build({ entryPoints: [input.entryPoint], outfile: main,
    bundle: true, platform: 'node', format: 'cjs', target: 'node24.21', metafile: true,
    ...(banner ? { banner: { js: banner } } : {}),
    // These entries run only as SEA. The ordinary ESM helper branch cannot run.
    define: { 'import.meta.url': 'undefined', ...input.defines } });
  for (const emitted of Object.values(result.metafile!.outputs)) {
    assert(emitted.imports.every(item => item.external && item.path.startsWith('node:')),
      'SEA application closure must have no runtime filesystem dependency');
  }
  const blob = path.join(input.fixture, `${input.variant}.blob`);
  const configuration = path.join(input.fixture, `${input.variant}-sea.json`);
  await writeFile(configuration, JSON.stringify({ main, output: blob, useSnapshot: false, useCodeCache: false,
    // Signed image policy: closing NODE_OPTIONS does not close Node's native
    // SIGUSR1 debugger route. No caller-provided CLI/environment extension.
    execArgv: ['--disable-sigusr1'], execArgvExtension: 'none', disableExperimentalSEAWarning: true, assets: input.assets }),
  { flag: 'wx', mode: 0o600 });
  run(input.fixture, input.carrier, ['--experimental-sea-config', configuration]);
  await copyFile(input.carrier, input.executable, constants.COPYFILE_EXCL);
  // Keep explicit ownership on this newly created copy independently of the
  // carrier extraction policy and platform copyFile metadata behavior;
  // never relax the fresh-package transfer oracle or chown the carrier tree.
  const image = await open(input.executable, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = await image.stat();
    assert(metadata.isFile() && metadata.nlink === 1, 'SEA output must be a new single-link regular image');
    await image.chown(process.geteuid!(), process.getegid!());
  } finally { await image.close(); }
  if (process.platform === 'darwin') run(input.fixture, 'codesign', ['--remove-signature', input.executable]);
  await inject(input.executable, 'NODE_SEA_BLOB', await readFile(blob),
    { sentinelFuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2', machoSegmentName: 'NODE_SEA' });
  if (process.platform === 'darwin') run(input.fixture, 'codesign', ['--sign', '-', input.executable]);
  await chmod(input.executable, 0o500);
  return input.executable;
}
