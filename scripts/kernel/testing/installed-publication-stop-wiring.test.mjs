// Source wiring only; these checks never substitute for the actual native
// first-parent fsync interval, original process join, or installed result proof.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const source = name => readFileSync(new URL(name, import.meta.url), 'utf8');

test('the actual initial-client catch retains only the two original incomplete hello stages and rethrows the same error', () => {
  const owner = source('./installed-node-journey.ts');
  const parsed = ts.createSourceFile('installed-node-journey.ts', owner, ts.ScriptTarget.Latest, true);
  const catches = [];
  const visit = node => {
    if (ts.isTryStatement(node) && node.catchClause && node.tryBlock.statements.length === 2 &&
        node.tryBlock.statements.every(ts.isExpressionStatement) &&
        node.tryBlock.getText(parsed).includes('client = await persistentClient(); inspectionClient = await persistentClient();'))
      catches.push(node.catchClause.block);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(catches.length, 1, 'use the actual initial public-client catch, never enrollment or a reconstructed predicate');
  const caught = catches[0];
  assert.equal(caught.statements.length, 2, 'the catch only selects inert diagnosis and throws the original error');
  assert(ts.isIfStatement(caught.statements[0]) && ts.isThrowStatement(caught.statements[1]), 'preserve the original catch control flow');
  assert.equal(caught.statements[1].expression.getText(parsed), 'original', 'the deadline error identity must be preserved');
  assert(!/await |setTimeout|Date\.now|performance\.now/u.test(caught.getText(parsed)), 'diagnosis adds no await, timer or clock sample');
  const program = `
    import assert from 'node:assert/strict';
    import { InstalledClientConsumerDeadlineError, InstalledClientDriverError } from ${JSON.stringify(new URL('./installed-client-consumer.ts', import.meta.url).href)};
    const actualCatch = new Function('options', 'original', 'InstalledClientConsumerDeadlineError', 'serverAuthenticationBinding',
      'let serverAuthenticationFailure = false; const report = {}; try ' + ${JSON.stringify(caught.getText(parsed))} +
      ' catch (caught) { return { caught, matched: serverAuthenticationFailure, report }; } throw new Error("original catch must rethrow");');
    const stages = ['manager_observer_loaded', 'initial_current_observed', 'native_connected', 'pre_hello_current_verified',
      'hello_exchange_started', 'hello_received', 'final_current_verified'];
    const prefix = count => stages.slice(0, count).map((stage, index) => ({ stage, elapsedMs: index, observedElapsedMs: index }));
    const deadline = (count, stage = 'ready', driver = 'authentication') => new InstalledClientConsumerDeadlineError(
      stage, 5000, performance.now() - 5001, 0, driver, prefix(count));
    let accepted = 0, rejected = 0;
    const check = (original, expected, enabled = true, bound = false) => {
      const result = actualCatch({ publicationRetirementDiagnostics: enabled }, original,
        InstalledClientConsumerDeadlineError, bound ? Object.freeze({ diagnosticOnly: true }) : undefined);
      assert.equal(result.caught, original, 'the actual catch must rethrow the exact original error');
      assert.equal(result.matched, expected, 'only the two incomplete hello stages may select server diagnosis');
      assert.deepEqual(result.report, expected ? { serverAuthentication: { diagnosticOnly: true, kind: 'unavailable',
        reason: bound ? 'original_join_missing' : 'preexisting_binding_missing' } } : {}, 'the catch must not fabricate a bound journal or other fields');
      if (expected) accepted++; else rejected++;
    };
    // Complete literal prefixes are accepted; a detached received marker is not
    // used to manufacture the original consumer's observed history.
    for (let count = 0; count <= stages.length; count++) check(deadline(count), count === 5 || count === 6);
    for (const count of [5, 6]) { check(deadline(count), true, true, true); check(deadline(count), false, false); }
    for (const stage of ['request', 'close']) check(deadline(6, stage), false);
    for (const driver of [undefined, 'platform', 'composition', 'selection', 'request', 'output', 'retirement'])
      check(new InstalledClientConsumerDeadlineError('ready', 5000, performance.now() - 5001, 0, driver, prefix(6)), false);
    const received = deadline(6);
    check({ diagnostic: received.diagnostic }, false);
    check(Object.assign(new Error('inert foreign failure'), { diagnostic: received.diagnostic }), false);
    check(new InstalledClientDriverError('authentication'), false);
    console.log(JSON.stringify({ accepted, rejected }));
  `;
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', program], {
    cwd: fileURLToPath(new URL('../../../', import.meta.url)), env: process.env, timeout: 10000, maxBuffer: 64 * 1024
  });
  assert.equal(child.error, undefined, 'the actual-class catch regression child must join');
  assert.equal(child.signal, null, 'the actual-class catch regression child must not time out');
  assert.equal(child.status, 0, child.stderr.toString('utf8'));
  assert.deepEqual(JSON.parse(child.stdout.toString('utf8')), { accepted: 4, rejected: 20 });
});

test('fixed server timing is opt-in and cannot defer the original service stop or replace its deadline error', () => {
  const owner = source('./installed-node-journey.ts');
  assert(owner.includes('serverAuthenticationDiagnostics: options.publicationRetirementDiagnostics'));
  const bind = owner.indexOf('serverAuthenticationBinding = Object.freeze(');
  const firstClient = owner.indexOf('client = await persistentClient(); inspectionClient = await persistentClient();');
  assert(bind >= 0 && firstClient > bind);
  const stop = owner.indexOf("command('/usr/bin/systemctl', ['--user', 'stop', ...units])", owner.indexOf('  finally {\n    const cleanup'));
  const originalJoin = owner.indexOf("stopped.ExecMainStatus, '0'", stop);
  const read = owner.indexOf('readInstalledServerAuthenticationJournal(', originalJoin);
  const joined = owner.indexOf('report.installedWritersJoined = true;', read);
  assert(stop >= 0 && originalJoin > stop && read > originalJoin && joined > read);
  const body = owner.slice(stop, read);
  assert(body.includes("await assert.rejects(lstat('/proc/' + before[index]!.MainPID), { code: 'ENOENT' })"));
  assert(body.includes("'--no-tail'")); assert(body.includes('maxBuffer: 256 * 1024'));
  assert(body.includes('serverAuthenticationBinding.invocationId === before[0]!.InvocationID'));
  assert(owner.includes('throw original; // Preserve the original consumer deadline and its timing.'));
  const packageSource = source('./installed-supervisor-package.ts');
  assert(packageSource.includes('if (options.serverAuthenticationDiagnostics) assert(options.publicationRetirementDiagnostics === true'));
});

test('server authentication joins its fixed four complete publications before validating returns and registering authority', () => {
  const control = source('../../../src/state/control-channel.ts');
  const publish = control.slice(control.indexOf('    const publish = async () => {'), control.indexOf('    const connection: LocalControlConnection'));
  assert.equal(publish.match(/beginInstalledServerAuthentication\(\)/gu)?.length, 1);
  const hash = publish.indexOf("await observe('image_hash',"), firstGuard = publish.indexOf('assertCurrent();');
  const batch = publish.indexOf('const batch = artifacts.publishCanonicalFour([');
  const batchEnd = publish.indexOf('      ]);', batch);
  const group = publish.indexOf('const publishedArtifacts = await joinResourceOperations([');
  const joined = publish.indexOf('      ]);', group);
  assert(hash >= 0 && firstGuard > hash && batch > firstGuard && batchEnd > batch && group > batchEnd && joined > group);
  assert(publish.includes(': await hashNativeImage(peer, capture)'));
  assert.equal(publish.match(/artifacts\.publishCanonicalFour\(/gu)?.length, 1);
  assert(!/artifacts\.publishCanonical\(/u.test(publish), 'authentication must not fall back to four independent persistence lifecycles');
  const values = publish.slice(batch, batchEnd);
  const names = ['processPublication', 'principalPublication', 'peerPublication', 'channelPublication'];
  for (const name of names)
    assert.equal(values.split(`{ value: ${name}.data, schemaKind: ${name}.expected.schemaKind }`).length, 2);
  assert.equal(values.match(/\{ value:/gu)?.length, 4);
  assert(publish.includes(`const publications = Object.freeze([${names.join(', ')}]);`));
  const beforeBatch = publish.slice(0, batch);
  assert(beforeBatch.lastIndexOf('assertCurrent();') > beforeBatch.indexOf('const channelPublication = prepare('));
  const tasks = publish.slice(group, joined);
  for (const [index, phase] of ['process_cas', 'principal_cas', 'peer_cas', 'channel_cas'].entries())
    assert.equal(tasks.split(`published(${index}, '${phase}')`).length, 2);
  assert.equal(tasks.match(/published\(/gu)?.length, 4);
  assert(publish.includes('const data = immutableSnapshot(value), bytes = canonicalJsonBytes(data);'));
  assert(publish.includes('ref: sha256Bytes(bytes)'));
  for (const decoder of ['decodePlatformProcessIdentity(processIdentity)', 'decodeLocalPrincipalIdentity(principal)',
    'decodeLocalSocketPeerObservation(observation)', 'decodeControlChannel(channel)']) {
    const prepared = publish.indexOf(`prepare(${decoder})`);
    assert(prepared >= 0 && prepared < batch);
  }
  const derived = publish.indexOf('const published = (index: number, phase:');
  const derivedEnd = publish.indexOf('\n      };', derived);
  assert(derived > batchEnd && derivedEnd > derived && derivedEnd < group);
  const task = publish.slice(derived, derivedEnd);
  assert(task.includes('const result = () => batch.then(artifacts => artifacts[index]!);'));
  assert(task.includes('return observe ? observe(phase, result) : result();'));
  assert(!/await |publishCanonical|\.catch\(/u.test(task), 'diagnostic awaits only derive the same complete real group result');
  const validation = publish.indexOf('for (const [index, artifact] of publishedArtifacts.entries())');
  assert(validation > joined);
  for (const field of ['ref', 'byteLength', 'mediaType', 'schemaKind'])
    assert(publish.includes(`artifact.${field} !== expected.${field}`));
  const current = publish.lastIndexOf('assertCurrent();'), register = publish.indexOf('channels.set(');
  assert(current > validation && register > current);
  assert(!/Promise\.all|sync:\s*false|\.catch\(/u.test(publish));
});

test('the original-stop entry is fixed and always includes native retirement diagnostics', () => {
  const entry = source('../qualify-installed-delivery-journey.ts');
  assert(entry.includes("mode === '--delivery-stop-campaign'"));
  assert(entry.includes("await runInstalledNodeJourney(filename, 'delivery', { publicationRetirementDiagnostics: true, publicationRetirementStop: true })"));
  assert(entry.includes("mode === '--delivery-delay-campaign'"));
  assert(entry.includes("assert.equal(mode, '--delivery-campaign')"));
});

test('the original-stop shell mode cannot run without its same owned fixed delayed volume', () => {
  const shell = source('../qualify-systemd-user.sh');
  assert(shell.includes('--run-delivery-stop-journey) probe_campaign_kind=run-journey; probe_run_driver_mode=--delivery-stop-campaign; shift ;;'));
  const stopGuard = shell.indexOf('[[ "$probe_run_driver_mode" != --delivery-stop-campaign || "$probe_volume_mode" = delay-50ms ]]');
  const identityGuard = shell.indexOf('readonly probe_node=$1');
  assert(stopGuard >= 0 && stopGuard < identityGuard);
  assert(shell.includes('|| "$probe_run_driver_mode" = --delivery-stop-campaign ]]; then'));
});

test('the real shell refuses missing delayed storage before any identity or host provisioning command', () => {
  const child = spawnSync('/bin/bash', [fileURLToPath(new URL('../qualify-systemd-user.sh', import.meta.url)),
    '--run-delivery-stop-journey', process.execPath], { env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' },
    timeout: 5000, maxBuffer: 1024 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 2);
  assert.equal(child.stdout.toString('utf8'), '');
  assert.equal(child.stderr.toString('utf8'), 'the fixed publication-stop campaign requires its owned delayed volume\n');
});

test('the original-stop job is independent, free, bounded and retains only its own reports', () => {
  const workflow = source('../../../.github/workflows/kernel-foundation.yml');
  const marker = '\n  linux-installed-delivery-original-stop:\n';
  const index = workflow.indexOf(marker);
  assert(index >= 0);
  const next = /\n  [a-z][a-z0-9-]*:\n/u.exec(workflow.slice(index + marker.length));
  const job = workflow.slice(index, next ? index + marker.length + next.index : undefined);
  assert(job.includes('    runs-on: ubuntu-22.04\n'));
  assert(job.includes('    timeout-minutes: 20\n'));
  assert(!job.includes('    needs:'));
  const run = job;
  for (const fixed of ['test "$RUNNER_ENVIRONMENT" = github-hosted', 'test "$RUNNER_OS" = Linux', 'test "$RUNNER_ARCH" = X64',
    'sudo /usr/sbin/modprobe dm_delay', 'test -c /dev/mapper/control',
    'sudo "$probe_node" --test --test-concurrency=1 --import tsx scripts/kernel/testing/installed-publication-crash-observer.test.ts',
    '--delay-volume --run-delivery-stop-journey "$probe_node" "$RUNNER_TEMP/cliq-installed-delivery-original-stop"']) assert(run.includes(fixed), fixed);
  assert(!/self-hosted|drop_caches|modprobe -r|dmsetup (?:remove_all|suspend|reload)|--test-force-exit/u.test(run));
  assert.equal((job.match(/uses: actions\/upload-artifact@v4/gu) ?? []).length, 1);
  for (const fixed of ['if: always()', 'name: installed-delivery-original-stop-${{ github.run_id }}-${{ github.run_attempt }}',
    'path: ${{ runner.temp }}/cliq-installed-delivery-original-stop/*.json', 'retention-days: 7']) assert(job.includes(fixed));
  for (const previous of ['linux-installed-delivery', 'linux-installed-delivery-delayed-volume']) assert(workflow.includes(`\n  ${previous}:\n`));
});

test('deadline diagnosis rethrows the original unchanged assertion without querying or changing its clock sample', () => {
  const owner = source('./installed-node-journey.ts');
  const original = "assert(Date.now() < by, 'actual candidate/verifier/result did not reach terminal within its fixed 90-second qualification window');";
  assert.equal(owner.split(original).length, 2);
  const location = owner.indexOf(original), start = owner.lastIndexOf('try {', location);
  const end = owner.indexOf('throw original;', location);
  assert(start >= 0 && end > location);
  const guarded = owner.slice(start, end + 'throw original;'.length);
  assert(guarded.includes('catch (original)'));
  assert(guarded.includes('projectInstalledRunProgress({ caseKind: sourceKind, cut, postCount })'));
  assert.equal((guarded.match(/Date\.now\(\)/gu) ?? []).length, 1);
  assert(!/await |\.send\(|readCas\(|setTimeout\(|setInterval\(/u.test(guarded));
  assert(guarded.includes('catch { /* Optional fixed-data diagnosis cannot replace the original deadline failure. */ }'));
});

test('the actual native return must causally precede the same original actor death and join', () => {
  const owner = source('./installed-node-journey.ts');
  const nativeBracket = owner.indexOf('assert(isOriginalPublicationFirstParentSignalBracket(snapshot, key, stopped!.signal)');
  const deathBracket = owner.indexOf('assert(BigInt(snapshot.slots[1][5]!) <= BigInt(stopped!.joined.monotonicNs)');
  const retained = owner.indexOf('diagnostic.snapshot = snapshot;', nativeBracket);
  assert(nativeBracket >= 0 && deathBracket > nativeBracket && retained > deathBracket);
});
