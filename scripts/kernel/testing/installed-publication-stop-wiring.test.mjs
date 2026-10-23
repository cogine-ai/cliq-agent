// Source wiring only; these checks never substitute for the actual native
// first-parent fsync interval, original process join, or installed result proof.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const source = name => readFileSync(new URL(name, import.meta.url), 'utf8');

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

test('server observations leave all five original identity operations serial and register authority only afterward', () => {
  const control = source('../../../src/state/control-channel.ts');
  const publish = control.slice(control.indexOf('    const publish = async () => {'), control.indexOf('    const connection: LocalControlConnection'));
  assert.equal(publish.match(/beginInstalledServerAuthentication\(\)/gu)?.length, 1);
  let previous = -1;
  for (const phase of ['image_hash', 'process_cas', 'principal_cas', 'peer_cas', 'channel_cas']) {
    const needle = `await observe('${phase}',`;
    assert.equal(publish.split(needle).length, 2);
    const at = publish.indexOf(needle); assert(at > previous); previous = at;
  }
  for (const operation of ['hashNativeImage(peer, capture)',
    'artifacts.publishCanonical(processIdentity, processIdentity.format)', 'artifacts.publishCanonical(principal, principal.format)',
    'artifacts.publishCanonical(observation, observation.format)', 'artifacts.publishCanonical(channel, channel.format)'])
    assert(publish.includes(': await ' + operation));
  const current = publish.indexOf('assertCurrent();'), register = publish.indexOf('channels.set(');
  assert(current > previous && register > current);
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
