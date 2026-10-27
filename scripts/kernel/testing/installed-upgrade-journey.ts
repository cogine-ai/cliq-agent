// A separate explicit installation-upgrade qualification scope. It neither
// replaces the normal26 scenarios nor raises their scanner/deadline budgets.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import { constants } from 'node:fs';
import { chown, lstat, mkdir, open, readFile, readdir, readlink, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:https';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeCredentialAuthorityOperation, decodeCredentialAuthorityRevokeOperation, decodeEndpointAuthorityOperation, type EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { digestOmitting, identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { readLedger, transferPackage } from './installed-node-journey.js';
import { buildUpgradeQualificationPackages } from './installed-upgrade-build.js';
import { copyCredentialSecretScanFailureDiagnostic, createCredentialSecretScanner, CredentialSecretScanError,
  type CredentialSecretScanFailureStage, type CredentialSecretScanCode } from './credential-secret-scan.js';
import { readCredentialSecretCorpusScanProgress, scanCredentialSecretCorpus, type CredentialSecretCorpusScanProgress } from './credential-secret-corpus.js';
import { openInstalledClientConsumer } from './installed-client-consumer.js';
import { withUpgradeUnitHistory } from './installed-upgrade-unit-history.js';
import { decodeRunResult, decodeVerificationClosure, decodeWorkspaceDiff } from '../../../src/state/result-artifacts.js';
import { decodePlatformProcessIdentity, decodeSourceManifest, decodeWorkspaceEntries } from '../../../src/state/decoders.js';
import { decodeInstalledUpgradeReport, INSTALLED_UPGRADE_PROFILE } from './installed-upgrade-result.js';
import { createInstalledRunObserver } from './installed-run-observer.js';
import { createUpgradeTlsMaterial } from './installed-upgrade-tls.js';
import { decodeRuntimeUpgradeReceipt, decodeRuntimeUpgradeRetirement } from '../../../src/state/runtime-upgrade-history.js';
import { decodeUpgradeResourceIndex, decodeUpgradeResourcePage, UPGRADE_RESOURCE_FAMILIES,
  UPGRADE_RESOURCE_PAGE_ROWS, upgradeResourceSequenceDigest } from '../../../src/state/runtime-upgrade-resources.js';

const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
const model = 'installed-upgrade-transport-fixture', beforeText = 'before the owned upgrade edit\n';
const metadataFields = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;

export async function runInstalledRuntimeUpgradeJourney(filename: string, originalSourceRoot: string) {
  assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64'); assert.equal(process.geteuid!(), 0);
  const ledger = await readLedger(filename), recipe = ledger.runJourney;
  const secret = Buffer.from('owned-upgrade-old-' + randomBytes(32).toString('hex'));
  const secondSecret = Buffer.from('owned-upgrade-new-' + randomBytes(32).toString('hex'));
  const password = Buffer.from(randomBytes(32).toString('hex'));
  let scanStage: CredentialSecretScanFailureStage = 'runtime', firstFailureStage: CredentialSecretScanFailureStage | null = null;
  let beforeCorpus: { streamsOpened: number; bytesScanned: number } | null = null, corpusScanFailureCode: CredentialSecretScanCode | null = null;
  let secretCorpusScanProgress: CredentialSecretCorpusScanProgress | undefined;
  const scanner = createCredentialSecretScanner([secret, secondSecret, password], { maxStreams: 4096, maxBytes: 512 * 1024 * 1024 }, () => { firstFailureStage ??= scanStage; });
  const scan = (bytes: Uint8Array) => { const stream = scanner.openStream(); try { stream.scan(bytes); } finally { stream.close(); } };
  const report: Record<string, any> = { diagnosticOnly: true, qualified: false, schemaVersion: 1,
    format: 'cliq-installed-runtime-upgrade-qualification-v1', fixtureProfile: INSTALLED_UPGRADE_PROFILE,
    phase: 'source_and_packages', scope: 'signed_schema7_to8_two_unverified_edit_runs', cases: [],
    officialReleaseQualified: false, wholeI4Qualified: false, legacy43ErrorReceipt: { kind: 'not_exercised' } };
  const mark = (phase: string) => { report.phase = phase; console.log('Installed upgrade phase ' + phase); };
  const prefix = ['--user', ledger.username, '--', '/usr/bin/env', '-i', 'HOME=' + ledger.home, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C',
    'XDG_RUNTIME_DIR=/run/user/' + ledger.uid, 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + ledger.uid + '/bus'];
  const command = (executable: string, args: readonly string[], input?: Buffer, timeout = 30000) => {
    const result = spawnSync('/usr/sbin/runuser', [...prefix, executable, ...args],
      { cwd: ledger.home, env: environment, timeout, killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024, input });
    assert(Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr)); scan(result.stdout); scan(result.stderr);
    assert.equal(result.error, undefined, 'owned upgrade command must join'); assert.equal(result.signal, null);
    return result;
  };
  const acceptedCommand = (executable: string, args: readonly string[], input?: Buffer, timeout?: number) => {
    const result = command(executable, args, input, timeout); assert.equal(result.status, 0, 'same-user upgrade command refused'); return result.stdout;
  };
  const credential = (metadata: Record<string, unknown>, input?: Buffer) => acceptedCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
    ['--bootstrap-credential', canonicalJsonBytes(metadata).toString('base64url')], input, 60000);
  const show = (unit: string) => Object.fromEntries(acceptedCommand('/usr/bin/systemctl', ['--user', 'show', unit,
    '--property=ActiveState,SubState,MainPID,ExecMainPID,InvocationID,Type,Delegate,KillMode,Result,ExecMainCode,ExecMainStatus,TimeoutStopUSec', '--no-pager'])
    .toString('utf8').trim().split('\n').map(line => { const at = line.indexOf('='); assert(at > 0); return [line.slice(0, at), line.slice(at + 1)]; }));
  let requestOrdinal = 0;
  const nextId = () => '019a0018-0000-7000-8000-' + String(++requestOrdinal).padStart(12, '0');
  const request = <T extends Record<string, unknown>>(core: T) => ({ ...core, requestDigest: canonicalSha256(core) });
  const response = (bytes: Buffer) => parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim()) as Record<string, any>;
  const readCas = async (ref: string) => {
    assert.match(ref, /^[0-9a-f]{64}$/u); const filename = path.join(recipe.stateRoot, 'cas', ref);
    const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const before = await held.stat({ bigint: true });
      assert(before.isFile() && before.nlink === 1n && before.uid === BigInt(ledger.uid) && (before.mode & 0o7777n) === 0o400n && before.size <= 16n * 1024n * 1024n);
      const bytes = await held.readFile(); assert.equal(BigInt(bytes.length), before.size); assert.equal(sha256Bytes(bytes), ref);
      for (const after of [await held.stat({ bigint: true }), await lstat(filename, { bigint: true })])
        for (const field of metadataFields) assert.equal(after[field], before[field]);
      return bytes;
    } finally { await held.close(); }
  };
  const casInventory = async () => {
    const rows: Array<{ ref: string; size: number; identity: string }> = [];
    for (const ref of (await readdir(path.join(recipe.stateRoot, 'cas'))).sort()) {
      assert.match(ref, /^[0-9a-f]{64}$/u); const bytes = await readCas(ref), info = await lstat(path.join(recipe.stateRoot, 'cas', ref), { bigint: true });
      rows.push({ ref, size: bytes.length, identity: metadataFields.map(field => String(info[field])).join(':') });
    }
    return rows;
  };
  const processStart = async (pid: number) => {
    assert(Number.isSafeInteger(pid) && pid > 0); const text = await readFile('/proc/' + pid + '/stat', 'utf8'); assert(text.length <= 8192);
    const fields = text.slice(text.lastIndexOf(')') + 2).trim().split(/\s+/u); assert(!['Z', 'X', 'x'].includes(fields[0]!));
    assert.match(fields[19]!, /^[1-9][0-9]*$/u); return fields[19]!;
  };
  const absentLifetime = async (pid: number, start: string) => {
    try { assert.notEqual(await processStart(pid), start); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  };
  const schema = (expected: 7 | 8) => {
    const db = new DatabaseSync(path.join(recipe.stateRoot, 'kernel.sqlite3'), { readOnly: true, allowExtension: false });
    try { assert.equal(db.prepare('PRAGMA user_version').get()!.user_version, expected); }
    finally { db.close(); }
  };
  let server: Server | undefined, client: Awaited<ReturnType<typeof openInstalledClientConsumer>> | undefined;
  let daemon: ReturnType<typeof spawn> | undefined, daemonJoined: Promise<void> | undefined, daemonPid: number | undefined, daemonStart: string | undefined;
  let services: { supervisorUnit: string; keeperUnit: string } | undefined;
  const sockets: Promise<void>[] = []; let postCount = 0, tcpCount = 0, tlsCount = 0, providerFailure = false, primary: unknown;
  let activeStage: 0 | 1 = 0;
  try {
    // The TLS private key remains only in process memory and stdin to openssl.
    // Its public certificate alone is included in the signed model package.
    const { privatePem, certificatePem: cert } = createUpgradeTlsMaterial(scan);
    try {
      server = createServer({ key: privatePem, cert, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, async (incoming, outgoing) => {
        try {
          assert.equal(incoming.method, 'POST'); assert.equal(incoming.url, '/v1/chat/completions');
          const expected = activeStage === 0 ? secret : secondSecret;
          assert.equal(incoming.headers.authorization, 'Bearer ' + expected.toString('utf8'));
          let size = 0; const chunks: Buffer[] = [];
          for await (const value of incoming) { const chunk = Buffer.from(value); size += chunk.length; assert(size <= 1048576); chunks.push(chunk); }
          const bodyBytes = Buffer.concat(chunks); scan(bodyBytes); const body = parseJsonStrict(bodyBytes.toString('utf8')) as Record<string, any>;
          assert.equal(body.model, model); assert.deepEqual(body.tools.map((entry: any) => entry.function.name), ['edit']);
          const ordinal = ++postCount, local = ordinal - activeStage * 2; assert(local >= 1 && local <= 2);
          if (local === 2) assert(body.messages.some((entry: any) => entry.role === 'tool'));
          const payload = { id: `owned-upgrade-${ordinal}`, object: 'chat.completion', model,
            choices: [{ index: 0, finish_reason: local === 1 ? 'tool_calls' : 'stop', message: local === 1
              ? { role: 'assistant', content: '', tool_calls: [{ id: `upgrade-edit-${activeStage}`, type: 'function', function: { name: 'edit',
                arguments: JSON.stringify({ path: 'example.txt', old_text: beforeText, new_text: `after the owned schema${activeStage ? 8 : 7} private edit\n` }) } }] }
              : { role: 'assistant', content: 'The owned private edit is complete.' } }], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } };
          const bytes = Buffer.from(JSON.stringify(payload)); scan(bytes);
          outgoing.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(bytes.length), Connection: 'close' }); outgoing.end(bytes);
        } catch { providerFailure = true; incoming.destroy(); outgoing.destroy(); }
      });
    } finally { privatePem.fill(0); }
    server.on('connection', socket => { tcpCount++; sockets.push(new Promise<void>(resolve => socket.once('close', resolve))); });
    server.on('secureConnection', socket => { tlsCount++; if (socket.getProtocol() !== 'TLSv1.3') { providerFailure = true; socket.destroy(); } });
    server.on('tlsClientError', () => { providerFailure = true; });
    await new Promise<void>((resolve, reject) => { server!.once('error', reject); server!.listen(0, '127.0.0.1', resolve); });
    const address = server.address(); assert(address && typeof address === 'object');
    const packages = await buildUpgradeQualificationPackages({ fixture: ledger.fixture, originalSourceRoot, oldBuildFixture: recipe.buildFixture,
      model: { provider: 'openai-compatible', model, target: { hostAscii: '127.0.0.1', port: address.port, basePath: '/v1' },
        tls: { serverNameAscii: 'installed-upgrade-fixture.invalid', caPem: cert!, spkiSha256Pins: [sha256Bytes(new X509Certificate(cert!).publicKey.export({ type: 'spki', format: 'der' }))] },
        claims: { nativeToolCalling: true, streaming: false, trustedUsageEvidence: false, contextLimitTokens: 32768, maxOutputTokens: 4096 },
        requestTokenCeiling: { inputTokens: 32768, outputTokens: 4096, cacheReadTokens: 0, cacheWriteTokens: 0 },
        validFrom: new Date(Date.now() - 60000).toISOString(), validThrough: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString() } });
    report.originalSource = packages.sourceIdentity;
    report.packages = { sourceBundleRef: canonicalSha256(packages.old.bundle), targetBundleRef: canonicalSha256(packages.target.bundle),
      sourceManifestDigest: packages.old.bundle.manifestDigest, targetManifestDigest: packages.target.bundle.manifestDigest,
      sameActualPublisher: true, schemaConversionDigest: packages.target.bundle.entries.find(entry => entry.entryId === 'schema_conversion')!.digest };
    await writeFile(recipe.releaseKeysFile, canonicalJsonBytes(packages.old.releaseKeys), { flag: 'wx', mode: 0o444 });
    await transferPackage(packages.old.packageRoot, ledger.uid, ledger.gid); await transferPackage(packages.target.packageRoot, ledger.uid, ledger.gid);
    const cliqHome = path.join(ledger.home, '.cliq'); await mkdir(cliqHome, { mode: 0o700 }); await chown(cliqHome, ledger.uid, ledger.gid);
    mark('actual_schema7_installation');
    const installed = response(acceptedCommand(process.execPath, [packages.oldInstaller, packages.old.packageRoot, recipe.stateRoot, recipe.releaseKeysFile]));
    assert.equal(installed.bundleDigest, report.packages.sourceBundleRef);
    await mkdir(recipe.controlDirectory, { mode: 0o700 }); await chown(recipe.controlDirectory, ledger.uid, ledger.gid);
    daemon = spawn('/usr/sbin/runuser', [...prefix, '/usr/bin/gnome-keyring-daemon', '--foreground', '--components=secrets', '--unlock',
      '--control-directory=' + recipe.controlDirectory], { cwd: ledger.home, env: environment, stdio: ['pipe', 'ignore', 'ignore'] });
    daemonJoined = new Promise<void>((resolve, reject) => { daemon!.once('close', () => resolve()); daemon!.once('error', reject); }); void daemonJoined.catch(() => {});
    daemon.stdin!.on('error', () => {}); daemon.stdin!.end(password);
    const by = Date.now() + 10000;
    for (;;) {
      const result = acceptedCommand('/usr/bin/busctl', ['--address=unix:path=/run/user/' + ledger.uid + '/bus', 'call', 'org.freedesktop.DBus',
        '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'NameHasOwner', 's', 'org.freedesktop.secrets']).toString('utf8').trim();
      if (result === 'b true') break; assert(Date.now() < by && daemon.exitCode === null); await delay(20);
    }
    const platform = response(acceptedCommand(recipe.observer, ['list']));
    assert.equal(platform.serviceUid, ledger.uid); assert.equal(platform.connectionClosed, true); assert.deepEqual(platform.items, []);
    daemonPid = platform.servicePid; daemonStart = await processStart(daemonPid!);
    assert.equal(await readlink('/proc/' + daemonPid + '/exe'), '/usr/bin/gnome-keyring-daemon');
    const setup = response(credential({ schemaVersion: 1, kind: 'install_services' }));
    assert.deepEqual(Object.keys(setup).sort(), ['schemaVersion', 'supervisorUnit', 'keeperUnit'].sort());
    services = { supervisorUnit: setup.supervisorUnit, keeperUnit: setup.keeperUnit };
    for (const unit of Object.values(services)) { assert.match(unit, /^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,240}\.service$/u); assert.equal(show(unit).TimeoutStopUSec, '2s'); }
    const root = await lstat(recipe.stateRoot, { bigint: true });
    const principal = identityHash('cliq-local-principal-v1', canonicalSha256({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
      canonicalAbsolutePath: recipe.stateRoot, ownerUid: ledger.uid, deviceId: String(root.dev), directoryFileId: String(root.ino), mode: 448, openedNoFollow: true, layoutVersion: 1 }), 'linux', ledger.uid);
    const authorize = (stage: 0 | 1) => {
      const signed = stage ? packages.target : packages.old, endpointId = `installed-upgrade-endpoint-${stage}`, credentialId = `installed-upgrade-credential-${stage}`;
      const registration: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: endpointId,
        registrationKind: 'user', ownerPrincipalId: principal, purposes: ['model_endpoint'], ...signed.modelAuthority!.endpoint,
        createdAt: new Date().toISOString(), registrationDigest: '' };
      registration.registrationDigest = digestOmitting(registration, 'registrationDigest');
      const core = { schemaVersion: 1, kind: 'register', ownerPrincipalId: principal, registration,
        expectedRegistrationArtifactRef: canonicalSha256(registration), commandDigest: '' };
      const registered = response(acceptedCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], canonicalJsonBytes({ schemaVersion: 1,
        kind: 'commit', requestId: nextId(), commandCore: { ...core, commandDigest: digestOmitting(core, 'commandDigest') } })));
      assert.equal(decodeEndpointAuthorityOperation(registered.operation).disposition, 'registered');
      const enrolled = response(credential({ schemaVersion: 1, kind: 'enroll', requestId: nextId(), credentialGrantId: credentialId,
        purpose: 'model_endpoint', endpointRegistrationId: endpointId, secretSubmissionId: `installed-upgrade-secret-${stage}`, expiresAt: '2099-01-01T00:00:00.000Z' }, stage ? secondSecret : secret));
      assert.equal(decodeCredentialAuthorityOperation(enrolled.operation).phase, 'committed'); return { endpointId, credentialId };
    };
    const connect = async (stage: 0 | 1) => openInstalledClientConsumer({ executable: '/usr/sbin/runuser', args: [...prefix, process.execPath,
      '--disable-warning=ExperimentalWarning', packages.clients[stage]!, filename, '--schema3'], cwd: ledger.home, env: environment,
      headlessSchemaVersion: 3, openScan: () => scanner.openStream(), onJoined: () => {} });
    const send = async (value: Record<string, unknown>, method: string) => {
      assert(client); const reply = await client.send(value, 30000) as Record<string, any>;
      assert.equal(reply.ok, true, 'public upgrade fixture method refused: ' + method); assert.equal(reply.result.method, method); return reply;
    };
    const run = async (stage: 0 | 1, authority: ReturnType<typeof authorize>, originalAuthority?: ReturnType<typeof authorize>) => {
      activeStage = stage; schema(stage ? 8 : 7);
      const workspace = stage ? path.join(ledger.home, 'probe/upgrade-workspace') : recipe.workspace;
      await mkdir(workspace, { mode: 0o700 }); await chown(workspace, ledger.uid, ledger.gid);
      await writeFile(path.join(workspace, 'example.txt'), beforeText, { flag: 'wx', mode: 0o644 }); await chown(path.join(workspace, 'example.txt'), ledger.uid, ledger.gid);
      const workspaceId = sha256Bytes(Buffer.from(workspace)), trustDirectory = path.join(cliqHome, 'workspaces', workspaceId);
      await mkdir(trustDirectory, { recursive: true, mode: 0o700 }); for (const directory of [path.dirname(trustDirectory), trustDirectory]) await chown(directory, ledger.uid, ledger.gid);
      const trust = path.join(trustDirectory, 'trust.json'); await writeFile(trust, canonicalJsonBytes({ version: 1, workspaceId, workspaceRealPath: workspace,
        decision: 'trusted', decidedAt: new Date().toISOString() }), { flag: 'wx', mode: 0o600 }); await chown(trust, ledger.uid, ledger.gid);
      client = await connect(stage); const session = (await send(request({ protocolVersion: 1, method: 'session.create', requestId: nextId(),
        admissionKey: randomBytes(32).toString('base64url'), workspacePath: workspace, name: 'Actual schema' + (stage ? 8 : 7) + ' upgrade Run' }), 'session.create')).result.snapshot.session;
      const submission = request({ protocolVersion: 1, method: 'run.submit', requestId: nextId(), admissionKey: randomBytes(32).toString('base64url'),
        sessionId: session.id, expectedContextRevision: session.contextRevision, workspacePath: workspace, objective: 'Make the owned private edit and finish.',
        model: { provider: 'openai-compatible', model, endpoint: { kind: 'registered', endpointRegistrationId: authority.endpointId }, modelCredentialGrantIds: [authority.credentialId] },
        policyMode: 'accept-edits', budgets: { wallTimeMs: 300000, modelTokens: 2000000, costMicros: 10000000, toolCalls: 1000, repairAttempts: 0, childDepth: 0, childConcurrency: 1 },
        verifiers: [], dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: true });
      if (originalAuthority) {
        const countRuns = () => { const db = new DatabaseSync(path.join(recipe.stateRoot, 'kernel.sqlite3'), { readOnly: true, allowExtension: false });
          try { return db.prepare('SELECT count(*) AS total FROM runs').get()!.total; } finally { db.close(); } };
        const beforeRuns = countRuns(), { requestDigest: _digest, ...core } = submission;
        const refused = await client!.send(request({ ...core, requestId: nextId(), admissionKey: randomBytes(32).toString('base64url'),
          model: { ...core.model, endpoint: { kind: 'registered', endpointRegistrationId: originalAuthority.endpointId }, modelCredentialGrantIds: [originalAuthority.credentialId] } }), 30000);
        assert.equal(refused.ok, false); assert(refused.error && typeof refused.error.code === 'string' &&
          ['AUTHORIZATION_REQUIRED', 'ARTIFACT_MISMATCH', 'UNSUPPORTED_EXECUTION_IDENTITY', 'INVALID_REQUEST'].includes(refused.error.code));
        assert.equal(countRuns(), beforeRuns); assert.equal(postCount, 2); assert(!providerFailure);
        report.oldCredentialNewRuntimeRefusal = { code: refused.error.code, noNewRun: true, noModelDispatch: true };
      }
      const admitted = await send(submission, 'run.submit'), runId = admitted.result.snapshot.run.id;
      const finishBy = Date.now() + 90000; let cut: Record<string, any>;
      const observer = createInstalledRunObserver(() => connect(stage));
      try {
        for (;;) {
          const remaining = finishBy - Date.now(); assert(remaining > 0 && !providerFailure);
          const reply = (await observer.read(runId, Math.min(30000, remaining))).response;
          assert(reply.ok && reply.result?.method === 'run.get'); cut = reply.result;
          if (cut.snapshot.run.status === 'completed_unverified') break;
          assert(!['failed', 'cancelled', 'succeeded'].includes(cut.snapshot.run.status)); assert(Date.now() < finishBy && !providerFailure); await delay(50);
        }
      } finally { await observer.close(); }
      const completed = cut.snapshot.run; assert.equal(completed.activeWorkerLaunchId, undefined); assert.equal(completed.frontierRef, undefined);
      assert.equal(completed.budgetConsumed.toolCalls, 1); assert(Object.values(completed.budgetReserved).every(value => value === 0));
      assert.deepEqual(cut.journal.map((entry: any) => [entry.opKind, entry.phase]), [
        ['model', 'prepared'], ['model', 'dispatch_claimed'], ['model', 'completed'], ['tool', 'prepared'], ['tool', 'dispatch_claimed'], ['tool', 'completed'],
        ['model', 'prepared'], ['model', 'dispatch_claimed'], ['model', 'completed'] ]);
      const result = decodeRunResult(response(await readCas(completed.resultRef))); assert.equal(result.runId, runId);
      assert.deepEqual(result.verificationReceiptRefs, []);
      const closure = decodeVerificationClosure(response(await readCas(result.verificationClosureRef)));
      assert.equal(closure.verification.kind, 'local');
      if (closure.verification.kind !== 'local') throw new Error('expected genuine unverified local result');
      assert.equal(closure.verification.outcome, 'unverified');
      const diff = decodeWorkspaceDiff(response(await readCas(result.diffRef)));
      assert.equal(diff.baseSourceRef, result.baseSourceRef); assert.equal(diff.resultSourceRef, result.resultSourceRef);
      assert.equal(diff.operations.length, 1); assert.equal(diff.operations[0]!.path, 'example.txt');
      const source = decodeSourceManifest(response(await readCas(result.resultSourceRef)));
      assert.equal(source.role, 'result');
      const entries = decodeWorkspaceEntries(response(await readCas(source.entriesRef)));
      assert.equal(entries.entries.length, 1); assert.equal(entries.entries[0]!.kind, 'file');
      const entry = entries.entries[0]!; if (entry.kind !== 'file') throw new Error('expected genuine private result file');
      assert.equal(entry.path, 'example.txt');
      assert.equal((await readCas(entry.blobRef)).toString('utf8'), `after the owned schema${stage ? 8 : 7} private edit\n`);
      const retirements = response(acceptedCommand(process.execPath, [packages.observers[stage]!, recipe.stateRoot, String(ledger.uid), runId])) as any;
      assert(Array.isArray(retirements) && retirements.length > 0);
      for (const retired of retirements) {
        assert.equal(retired.phase, 'retired'); assert.equal(retired.generationWriteState, 'sealed');
        await absentLifetime(retired.pid, retired.processStartToken.replace('linux-proc-start-ticks:', ''));
      }
      assert.equal(postCount, (stage + 1) * 2); assert.equal(tcpCount, postCount); assert.equal(tlsCount, postCount); assert(!providerFailure);
      assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), beforeText);
      report.cases.push({ schemaVersion: stage ? 8 : 7, runId, status: completed.status, resultRef: completed.resultRef,
        firstResponseSha256: sha256Bytes(canonicalJsonBytes(admitted)), modelPosts: 2, toolCalls: 1,
        launchCount: retirements.length, retirementRefs: retirements.map((row: any) => row.retirementEvidenceRef),
        hostSourceUnchanged: true, publicRecoveryRead: true, actualWorkerLifetimesAbsent: true });
      return { submission, admitted, runId, cut, sessionId: session.id, resultBytes: await readCas(completed.resultRef) };
    };
    mark('schema7_public_authorization_and_run');
    const oldAuthority = authorize(0), oldRun = await run(0, oldAuthority), originalCas = await casInventory();
    await client!.close(); client = undefined;
    const originalUnits = [show(services.supervisorUnit), show(services.keeperUnit)];
    const originalProcesses = await Promise.all(originalUnits.map(async unit => ({ pid: Number(unit.MainPID), start: await processStart(Number(unit.MainPID)) })));
    mark('formal_signed_upgrade_and_real_ready');
    // The existing record-retention observer owns a10s input lifetime. It is
    // appropriate for final Stop2, not the entire legitimate upgrade30 budget.
    const upgrade = response(acceptedCommand(path.join(packages.target.packageRoot, 'supervisor'), ['--upgrade-runtime', recipe.stateRoot, packages.target.packageRoot]));
    assert.deepEqual(Object.keys(upgrade).sort(), ['schemaVersion', 'format', 'runtimeBundleRef', 'upgradeReceiptRef', 'providerBindingPolicy'].sort());
    assert.equal(upgrade.format, 'cliq-runtime-upgrade-complete-v1'); assert.equal(upgrade.runtimeBundleRef, report.packages.targetBundleRef);
    assert.equal(upgrade.providerBindingPolicy, 'explicit_new_runtime_authorization_required');
    const receipt = decodeRuntimeUpgradeReceipt(response(await readCas(upgrade.upgradeReceiptRef)));
    assert.equal(receipt.sourceRuntimeBundleRef, report.packages.sourceBundleRef); assert.equal(receipt.targetRuntimeBundleRef, report.packages.targetBundleRef);
    assert.equal(receipt.sourceRuntimeBundleManifestDigest, packages.old.bundle.manifestDigest);
    assert.equal(receipt.targetRuntimeBundleManifestDigest, packages.target.bundle.manifestDigest);
    assert.equal(receipt.installation.kind, 'held_installed_stage');
    if (receipt.installation.kind !== 'held_installed_stage') throw new Error('expected genuine installed upgrade receipt');
    assert.equal(receipt.installation.originalKeeper.pid, originalProcesses[1]!.pid);
    assert.equal(receipt.installation.originalKeeper.processStartToken, 'linux-proc-start-ticks:' + originalProcesses[1]!.start);
    const retired = decodeRuntimeUpgradeRetirement(response(await readCas(receipt.retirementRef)));
    assert.equal(retired.retirementDigest, receipt.retirementDigest); assert.equal(retired.sourceOwnerEpoch, receipt.sourceOwnerEpoch);
    assert.equal(retired.sourceOwnerRowDigest, receipt.sourceOwnerRowDigest);
    const processIdentity = decodePlatformProcessIdentity(response(await readCas(retired.sourceProcessIdentityRef)));
    assert.equal(processIdentity.identityDigest, retired.sourceProcessIdentityDigest); assert.equal(processIdentity.pid, originalProcesses[0]!.pid);
    assert.equal(processIdentity.processStartToken, 'linux-proc-start-ticks:' + originalProcesses[0]!.start);
    assert.equal(processIdentity.executableImageDigest, packages.old.bundle.entries.find(entry => entry.role === 'supervisor')!.digest);
    const sourceCut = { sourceOwnerEpoch: receipt.sourceOwnerEpoch, sourceOwnerRowDigest: receipt.sourceOwnerRowDigest }; let rowCount = 0;
    for (const family of UPGRADE_RESOURCE_FAMILIES) {
      const index = decodeUpgradeResourceIndex(response(await readCas(retired.resourceIndexRefs[family])), sourceCut, family), refs: string[] = [];
      for (const [ordinal, ref] of index.pageRefs.entries()) {
        const page = decodeUpgradeResourcePage(response(await readCas(ref)), sourceCut, family, ordinal,
          Math.min(UPGRADE_RESOURCE_PAGE_ROWS, index.rowCount - refs.length));
        for (const row of page.rowRefs) { response(await readCas(row)); refs.push(row); }
      }
      assert.equal(refs.length, index.rowCount); assert.equal(upgradeResourceSequenceDigest(sourceCut, family, refs), index.orderedRefsDigest); rowCount += refs.length;
    }
    assert.equal(rowCount, retired.totalRowCount); assert(rowCount >= 3);
    for (const original of originalProcesses) await absentLifetime(original.pid, original.start);
    schema(8); client = await connect(1);
    assert.deepEqual(canonicalJsonBytes(await send(oldRun.submission, 'run.submit')), canonicalJsonBytes(oldRun.admitted));
    assert.deepEqual(canonicalJsonBytes((await send({ protocolVersion: 1, method: 'run.get', runId: oldRun.runId }, 'run.get')).result), canonicalJsonBytes(oldRun.cut));
    assert.deepEqual(await readCas(oldRun.cut.snapshot.run.resultRef), oldRun.resultBytes);
    for (const row of originalCas) {
      assert.equal((await readCas(row.ref)).length, row.size);
      const info = await lstat(path.join(recipe.stateRoot, 'cas', row.ref), { bigint: true });
      assert.equal(metadataFields.map(field => String(info[field])).join(':'), row.identity);
    }
    const oldEndpoint = response(acceptedCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], canonicalJsonBytes({ schemaVersion: 1,
      kind: 'read', endpointRegistrationId: oldAuthority.endpointId })));
    const oldCredential = response(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: oldAuthority.credentialId }));
    assert.equal(oldEndpoint.record.registration.endpointRegistrationId, oldAuthority.endpointId);
    assert.equal(oldCredential.record.credentialGrantId, oldAuthority.credentialId);
    await client.close(); client = undefined;
    mark('explicit_schema8_new_authorization_and_run');
    const newAuthority = authorize(1); assert.notEqual(newAuthority.endpointId, oldAuthority.endpointId); assert.notEqual(newAuthority.credentialId, oldAuthority.credentialId);
    await run(1, newAuthority, oldAuthority); await client!.close(); client = undefined;
    const revoked = response(credential({ schemaVersion: 1, kind: 'revoke', requestId: nextId(), credentialGrantId: oldAuthority.credentialId,
      expectedAuthorityRevision: oldCredential.record.authorityRevision }));
    assert.equal(decodeCredentialAuthorityRevokeOperation(revoked.operation).credentialGrantId, oldAuthority.credentialId);
    assert.equal(response(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: oldAuthority.credentialId })).record.state, 'revoked');
    mark('same_receipt_recovery_and_old_first_response');
    const repeated = response(acceptedCommand(path.join(packages.target.packageRoot, 'supervisor'), ['--upgrade-runtime', recipe.stateRoot, packages.target.packageRoot]));
    assert.deepEqual(canonicalJsonBytes(repeated), canonicalJsonBytes(upgrade));
    client = await connect(1); assert.deepEqual(canonicalJsonBytes(await send(oldRun.submission, 'run.submit')), canonicalJsonBytes(oldRun.admitted));
    await client.close(); client = undefined;
    report.upgrade = { receiptRef: upgrade.upgradeReceiptRef, originalSupervisorAndKeeperLifetimesAbsent: true,
      realTargetHello: true, oldFirstResponseUnchanged: true, originalCasBytesAndInodesUnchanged: true,
      oldEndpointAndCredentialReadable: true, oldCredentialRevocable: true, explicitNewRuntimeEndpointAndCredential: true, sameReceiptRecovery: true,
      pagedRetirementGraphFullyRead: true, retirementResourceRowCount: rowCount };
    assert.equal(report.cases.length, 2); assert.equal(postCount, 4); mark('upgrade_assertions_complete');
  } catch (error) { primary = error; }
  finally {
    const failures: unknown[] = [];
    try { await client?.close(); } catch (error) { failures.push(error); }
    try {
      if (services) await withUpgradeUnitHistory({ executable: '/usr/sbin/runuser', args: [...prefix, recipe.observer, 'retain-systemd', services.supervisorUnit, services.keeperUnit],
        cwd: ledger.home, env: environment, scanner }, async () => {
        const started = performance.now(); acceptedCommand('/usr/bin/systemctl', ['--user', 'stop', services!.supervisorUnit, services!.keeperUnit]);
        assert(performance.now() - started <= 2000, 'final ordinary service Stop exceeded two seconds');
        for (const unit of Object.values(services!)) {
          const stopped = show(unit); assert.equal(stopped.ActiveState, 'inactive'); assert.equal(stopped.MainPID, '0');
          assert.equal(stopped.Result, 'success'); assert.equal(stopped.ExecMainCode, '1'); assert.equal(stopped.ExecMainStatus, '0');
        }
        report.servicesStoppedAndJoined = true;
      });
    } catch (error) { failures.push(error); }
    try {
      if (daemonPid && daemonStart) { assert.equal(await processStart(daemonPid), daemonStart); process.kill(daemonPid, 'SIGTERM'); }
      if (daemonJoined) { const timer = setTimeout(() => daemon!.kill('SIGKILL'), 2000); try { await daemonJoined; } finally { clearTimeout(timer); } }
      if (daemonPid && daemonStart) await absentLifetime(daemonPid, daemonStart);
      report.secretServiceJoined = daemon !== undefined;
    } catch (error) { failures.push(error); }
    try { if (server) { server.closeAllConnections(); await new Promise<void>(resolve => server!.close(() => resolve())); await Promise.all(sockets); report.httpsJoined = true; } }
    catch (error) { failures.push(error); }
    if (failures.length) primary = new AggregateError([...(primary === undefined ? [] : [primary]), ...failures]);
    report.transport = { postCount, acceptedTcp: tcpCount, acceptedTls: tlsCount, providerHealthy: !providerFailure };
    if (report.servicesStoppedAndJoined && report.secretServiceJoined && report.httpsJoined) {
      try {
        mark('secret_corpus'); scanStage = 'corpus'; const current = scanner.stats(); beforeCorpus = { streamsOpened: current.streamsOpened, bytesScanned: current.bytesScanned };
        report.secretCorpus = await scanCredentialSecretCorpus({ stateRoot: recipe.stateRoot, uid: ledger.uid, evidenceDirs: [], scanner });
      } catch (error) {
        if (error instanceof CredentialSecretScanError) {
          corpusScanFailureCode = error.code; secretCorpusScanProgress = readCredentialSecretCorpusScanProgress(error);
          if (secretCorpusScanProgress) report.secretCorpusScanProgress = secretCorpusScanProgress;
        }
        primary ??= error;
      }
    }
    report.qualified = primary === undefined && report.phase === 'secret_corpus';
    if (report.qualified) mark('complete');
    if (primary) report.error = { diagnosticOnly: true, kind: 'installed_runtime_upgrade_failed', sourceFrames: primary instanceof Error
      ? [...primary.stack?.matchAll(/\b(installed-upgrade-journey|installed-upgrade-build|legacy-upgrade-source|qualification-source|installed-supervisor-package|installed-client-consumer)\.ts:([1-9][0-9]{0,6}):([1-9][0-9]{0,6})/gu) ?? []]
        .slice(0, 8).map(match => ({ file: match[1] + '.ts', line: Number(match[2]), column: Number(match[3]) })) : [] };
    let bytes: Buffer;
    try { scanStage = 'report'; const value = canonicalJsonBytes(report); scan(value); scanner.close(); report.secretOutputScan = scanner.stats();
      decodeInstalledUpgradeReport(report); bytes = Buffer.concat([canonicalJsonBytes(report), Buffer.from('\n')]); }
    catch { primary ??= new Error('upgrade secret scan refused'); scanner.close();
      let secretScanFailure: ReturnType<typeof copyCredentialSecretScanFailureDiagnostic> | undefined;
      try { secretScanFailure = copyCredentialSecretScanFailureDiagnostic({ diagnosticOnly: true, firstFailureStage, beforeCorpus, corpusScanFailureCode }); }
      catch { /* Optional diagnosis cannot replace failure or secret retirement. */ }
      bytes = Buffer.from(JSON.stringify({ diagnosticOnly: true,
      qualified: false, schemaVersion: 1, format: report.format, fixtureProfile: INSTALLED_UPGRADE_PROFILE, phase: 'secret_scan_or_report_failure',
      secretOutputScan: scanner.stats(), ...(secretScanFailure ? { secretScanFailure } : {}), ...(secretCorpusScanProgress ? { secretCorpusScanProgress } : {}) }) + '\n'); }
    secret.fill(0); secondSecret.fill(0); password.fill(0);
    try { await writeFile(recipe.reportFile, bytes, { flag: 'wx', mode: 0o644 }); } finally { bytes.fill(0); }
  }
  if (primary) throw new Error('actual installed runtime upgrade failed; inspect the closed qualification report');
}
