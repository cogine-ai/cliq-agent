// Real compiled Linux data checks and a plain owned fixture process. No
// prepare factory, native scope, StateOwner, SQL, dispatch or retirement
// authority is used. The fixture never attests an earlier effect execution.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { sign } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { rootCertificates } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { policyProfile, SINGLE_CAS_STREAMS_LAYOUT, type RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { createInstalledRuntime } from '../../../src/state/installed-runtime.js';
import { createInstalledQualificationPublisher, qualificationPublisherMaterial } from '../../../src/state/testing/qualification-publisher.js';
import { compileInputSchema } from '../../../src/tools/input-schema.js';
import { MCP_RECOVERY_FIXTURE_ARGV, MCP_RECOVERY_HOLD_ARGV, MCP_RECOVERY_REFUSED_ARGV, MCP_RECOVERY_REFUSED_STATUS_LINE, MCP_RECOVERY_UNRESOLVED_ARGV,
  MCP_RECOVERY_MISSING_ARGV, buildInstalledMcpRecoveryPackage } from './installed-mcp-recovery-package.js';

const linux = process.platform === 'linux' && process.arch === 'x64';
const repository = fileURLToPath(new URL('../../..', import.meta.url));
const environment = { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' };

test('actual C stdio fixed recipe, JSON lines and cancelled received-data NoEcho remain bounded', { skip: !linux }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-mcp-stdio-data-'));
  try {
    const dependencies = spawnSync('/usr/bin/pkg-config', ['--cflags', '--libs', 'gio-2.0', 'openssl'],
      { env: environment, encoding: 'utf8', timeout: 10_000, maxBuffer: 8192 });
    assert.equal(dependencies.error, undefined); assert.equal(dependencies.signal, null);
    assert.equal(dependencies.status, 0, dependencies.stderr);
    const binary = path.join(directory, 'mcp-stdio-data.node');
    const headers = path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node');
    const compiled = spawnSync('/usr/bin/cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
      '-shared', '-fPIC', '-pthread', '-I', headers, 'native/linux/mcp-stdio-native-fixture.c',
      '-o', binary, ...dependencies.stdout.trim().split(/\s+/u)], { cwd: repository, env: environment,
      encoding: 'utf8', timeout: 60_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
    assert.equal(compiled.error, undefined); assert.equal(compiled.signal, null); assert.equal(compiled.status, 0, compiled.stderr);
    await chmod(binary, 0o500);
    const binding = createRequire(import.meta.url)(binary) as {
      interfaceVersion: number;
      runMcpStdioDataFixture(): { checks: number; factoryExecuted: false; authorityExecuted: false };
      runMcpStdioRecoveryDataFixture(): { checks: number; factoryExecuted: false; authorityExecuted: false };
    };
    assert.equal(binding.interfaceVersion, 1);
    assert.deepEqual(binding.runMcpStdioDataFixture(), { checks: 41, factoryExecuted: false, authorityExecuted: false });
    assert.deepEqual(binding.runMcpStdioRecoveryDataFixture(), { checks: 33, factoryExecuted: false, authorityExecuted: false });
    async function compileRole(name: string, statusOnly: boolean) {
      const binary = path.join(directory, name);
      const built = spawnSync('/usr/bin/musl-gcc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
        '-fno-ident', '-ffile-prefix-map=' + repository + '=.', '-Wl,--build-id=none', '-s',
        ...(statusOnly ? ['-DCLIQ_MCP_RECOVERY_STATUS_ONLY=1'] : []),
        'native/linux/mcp-stdio-server-fixture.c', '-o', binary], { cwd: repository, env: environment,
        encoding: 'utf8', timeout: 60_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
      assert.equal(built.error, undefined); assert.equal(built.signal, null); assert.equal(built.status, 0, built.stderr);
      await chmod(binary, 0o500); return binary;
    }
    const server = await compileRole('mcp-static-server', false), adapter = await compileRole('mcp-static-status-adapter', true);
    const [serverBytes, adapterBytes] = await Promise.all([readFile(server), readFile(adapter)]);
    assert.notEqual(sha256Bytes(serverBytes), sha256Bytes(adapterBytes));

    // Exercise physical package capture using the real publisher. The
    // Supervisor and worker entries are opaque bytes and are never executed.
    const publisher = createInstalledQualificationPublisher();
    const recovery = await buildInstalledMcpRecoveryPackage({ server, serverBytes, adapter, adapterBytes, publisher });
    const { releaseKeys, privateKey } = qualificationPublisherMaterial(publisher);
    const policy = policyProfile(), policyRef = canonicalSha256(policy);
    const emptyRoot = { schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
      filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'],
      persistent: false, networkConfiguration: 'none' };
    const contents = [
      { entryId: 'supervisor', role: 'supervisor', version: '1', relativePath: 'supervisor', executable: true,
        bytes: Buffer.from('opaque installer fixture Supervisor') },
      { entryId: 'worker', role: 'worker', version: '1', relativePath: 'workers/worker', executable: true,
        bytes: Buffer.from('opaque installer fixture worker') },
      { entryId: 'default_https_trust_store', role: 'trust_store', version: '1', relativePath: 'profiles/https-trust.pem',
        executable: false, bytes: Buffer.from(rootCertificates.join('\n')) },
      { entryId: 'root', role: 'sandbox_root_profile', version: '1', relativePath: 'profiles/empty-root.json', executable: false,
        bytes: canonicalJsonBytes({ ...emptyRoot, profileDigest: canonicalSha256(emptyRoot) }) },
      { entryId: 'policy', role: 'policy_engine', version: '1', relativePath: 'profiles/policy.json', executable: false,
        bytes: canonicalJsonBytes(policy) },
      { entryId: 'mcp-static-stdio-fixture-v1', role: 'mcp_server', version: '1', relativePath: 'mcp/static-stdio-fixture',
        executable: true, bytes: serverBytes },
      ...recovery.contents,
    ];
    const core = {
      schemaVersion: 2, installedLayout: SINGLE_CAS_STREAMS_LAYOUT, bundleVersion: 'mcp-recovery-member-qualification',
      controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
      stateSchemaRange: { min: 1, max: 8 }, workerProtocolRange: { min: 1, max: 1 },
      entries: contents.map(({ bytes, ...entry }) => ({ ...entry, digest: sha256Bytes(bytes), byteCount: bytes.length })),
      structuredArtifacts: [recovery.root, { kind: 'policy_engine_profile', artifactId: 'policy', rootEntryId: 'policy',
        artifactRef: policyRef, semanticDigest: policy.profileDigest, memberRefs: [] }],
      guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId
    } satisfies Omit<RuntimeBundleManifest, 'manifestDigest' | 'signature'>;
    const manifestDigest = canonicalSha256(core);
    const signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${manifestDigest}`), privateKey).toString('base64');
    const bundle = { ...core, manifestDigest, signature };
    const packageRoot = path.join(realpathSync(directory), 'package'), stateRoot = path.join(realpathSync(directory), 'state');
    await mkdir(packageRoot, { mode: 0o700 });
    for (const { relativePath, executable, bytes } of contents) {
      const filename = path.join(packageRoot, relativePath);
      await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
      await writeFile(filename, bytes, { flag: 'wx', mode: executable ? 0o500 : 0o400 });
    }
    await writeFile(path.join(packageRoot, 'manifest.json'), canonicalJsonBytes(bundle), { flag: 'wx', mode: 0o400 });
    const runtime = createInstalledRuntime({ releaseKeys });
    assert.deepEqual(await runtime.installInitial({ packageRoot, stateRoot }), { bundleDigest: canonicalSha256(bundle), manifestDigest });
    for (const object of recovery.contents.filter(entry => !entry.executable))
      assert.deepEqual(await readFile(path.join(stateRoot, KERNEL_CAS_DIRECTORY, sha256Bytes(object.bytes))), object.bytes);
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });

    const recoveryModes = new Set([MCP_RECOVERY_FIXTURE_ARGV, MCP_RECOVERY_HOLD_ARGV, MCP_RECOVERY_REFUSED_ARGV,
      MCP_RECOVERY_UNRESOLVED_ARGV, MCP_RECOVERY_MISSING_ARGV]);
    const key = identityHash('cliq-mcp-tool-idempotency-v1', 'run', 'operation', 'a'.repeat(64), 'effect');
    const invalidKeys = ['b'.repeat(64), key.slice(1), key + '=', 'A'.repeat(42) + 'B'];
    for (const mode of ['immutable_noop_profile', '--immutable-noop-effect-exit-no-reply', ...recoveryModes])
      for (const operation of ['stdio_noop_effect', 'stdio_noop_status']) for (const candidate of [key, ...invalidKeys]) {
      const omitReply = mode === '--immutable-noop-effect-and-status-no-reply' ||
        (mode !== 'immutable_noop_profile' && operation === 'stdio_noop_effect');
      const responsivePing = omitReply && mode !== '--immutable-noop-effect-exit-no-reply' && mode !== MCP_RECOVERY_MISSING_ARGV;
      let input = [
        { id: 1, jsonrpc: '2.0', method: 'initialize' },
        { jsonrpc: '2.0', method: 'notifications/initialized' },
        { id: 2, jsonrpc: '2.0', method: 'tools/list' },
        { id: 3, jsonrpc: '2.0', method: 'tools/call', params: { arguments: { idempotencyKey: candidate }, name: operation } }
      ].map(value => JSON.stringify(value)).join('\n') + '\n';
      if (candidate === key && responsivePing)
        input += JSON.stringify({ id: 'fixture-noop-ping', jsonrpc: '2.0', method: 'ping' }) + '\n';
      const child = spawnSync(server, [mode], { env: environment, input,
        encoding: 'utf8', timeout: 10_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
      assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.stderr, '');
      assert.equal(child.status, candidate === key ? 0 : 65);
      const lines = child.stdout.trimEnd().split('\n');
      if (recoveryModes.has(mode)) {
        const statusOnly = spawnSync(adapter, [mode], { env: environment, input,
          encoding: 'utf8', timeout: 10_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
        assert.equal(statusOnly.error, undefined); assert.equal(statusOnly.signal, null); assert.equal(statusOnly.stderr, '');
        if (operation === 'stdio_noop_effect') {
          assert.equal(statusOnly.status, 65);
          assert.equal(statusOnly.stdout, lines.slice(0, 2).join('\n') + '\n');
        } else {
          assert.equal(statusOnly.status, child.status); assert.equal(statusOnly.stdout, child.stdout);
        }
      }
      const malformed = mode === MCP_RECOVERY_REFUSED_ARGV && operation === 'stdio_noop_status' && candidate === key;
      assert.equal(lines.length, candidate === key && (!omitReply || responsivePing) ? 3 : 2);
      if (malformed) {
        assert(child.stdout.endsWith('\n')); assert.equal(lines[2], MCP_RECOVERY_REFUSED_STATUS_LINE);
        assert.throws(() => JSON.parse(lines[2]!), SyntaxError); lines.pop();
      }
      const replies = lines.map(line => JSON.parse(line));
      const selected = replies[1].result.tools.filter((tool: { name: string }) => tool.name === operation);
      assert.equal(selected.length, 1);
      const validate = compileInputSchema(selected[0].inputSchema);
      assert.equal(validate({ idempotencyKey: candidate }) !== undefined, candidate === key);
      assert.equal(replies.length, !malformed && candidate === key && (!omitReply || responsivePing) ? 3 : 2);
      if (candidate === key && responsivePing) {
        assert.deepEqual(replies.map(reply => reply.id), [1, 2, 'fixture-noop-ping']);
        assert.deepEqual(replies[2], { id: 'fixture-noop-ping', jsonrpc: '2.0', result: {} });
      } else if (candidate === key && !omitReply && !malformed) assert.deepEqual(replies[2].result.structuredContent, {
        originalExecutionObserved: false,
        profileClass: mode === MCP_RECOVERY_MISSING_ARGV ? 'immutable_missing_noop_target' : 'immutable_preexisting_noop_target',
        targetState: mode === MCP_RECOVERY_MISSING_ARGV ? 'missing_immutable_target' : 'preexisting_noop'
      });
    }
    const unknownMode = spawnSync(server, ['--unknown-noop-mode'], { env: environment, input: '',
      encoding: 'utf8', timeout: 10_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
    assert.equal(unknownMode.error, undefined); assert.equal(unknownMode.signal, null);
    assert.equal(unknownMode.status, 64); assert.equal(unknownMode.stdout, ''); assert.equal(unknownMode.stderr, '');
    for (const argv of [[], ['immutable_noop_profile'], ['--immutable-noop-effect-exit-no-reply'], ['--unknown-noop-mode']]) {
      const foreign = spawnSync(adapter, argv, { env: environment, input: '',
        encoding: 'utf8', timeout: 10_000, killSignal: 'SIGKILL', maxBuffer: 65_536 });
      assert.equal(foreign.error, undefined); assert.equal(foreign.signal, null); assert.equal(foreign.status, 64);
      assert.equal(foreign.stdout, ''); assert.equal(foreign.stderr, '');
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

