// Source wiring only; these checks never substitute for the actual native
// first-parent fsync interval, original process join, or installed result proof.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const source = name => readFileSync(new URL(name, import.meta.url), 'utf8');

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
