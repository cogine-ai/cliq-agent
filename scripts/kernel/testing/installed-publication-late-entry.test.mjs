// Fixed entry/wiring regressions only. These never qualify a physical late
// fsync, the public before/audit cuts, or the original resource retirement.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const source = name => readFileSync(new URL(name, import.meta.url), 'utf8');
const shellFile = fileURLToPath(new URL('../qualify-systemd-user.sh', import.meta.url));

test('the real late entry refuses missing delayed storage before any identity or host provisioning', () => {
  const child = spawnSync('/bin/bash', [shellFile, '--run-delivery-late-journey', process.execPath], {
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, timeout: 5000, maxBuffer: 4096,
  });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 2);
  assert.equal(child.stdout.toString('utf8'), '');
  assert.equal(child.stderr.toString('utf8'), 'the fixed publication-late campaign requires its owned delayed volume\n');
});

test('the real shell refuses duplicate, misplaced, unknown and mixed campaign flags before provisioning', () => {
  const otherModes = ['--installed', '--installed-retirement-refusal', '--secrets', '--credentials',
    '--credentials-model-input', '--credential-finalizer-shutdown', '--run-journey', '--run-final-source-limits-journey',
    '--run-verifier-journey', '--run-delivery-journey', '--run-delivery-delay-journey', '--run-delivery-stop-journey',
    '--run-failure-journey', '--run-retry-journey', '--run-authority-failure-journey', '--run-storage-failure-journey',
    '--run-request-resource-journey', '--run-shutdown-admission-journey', '--run-shutdown-session-journey',
    '--run-shutdown-preparation-journey', '--run-shutdown-received-tool-journey', '--run-shutdown-pending-model-journey',
    '--run-shutdown-startup-journey'];
  const invalid = [
    ['--delay-volume', '--delay-volume', '--run-delivery-late-journey'],
    ['--delay-volume', '--run-delivery-late-journey', '--run-delivery-late-journey'],
    ['--run-delivery-late-journey', '--delay-volume'],
    ['--delay-volume', '--run-delivery-late-journey', '--unknown-campaign'],
    ['--delay-volume', '--unknown-campaign', '--run-delivery-late-journey'],
    ['--delay-volume', '--run-delivery-late-journey', process.execPath, '--run-delivery-late-journey'],
    ...otherModes.flatMap(mode => [['--delay-volume', '--run-delivery-late-journey', mode],
      ['--delay-volume', mode, '--run-delivery-late-journey']]),
  ];
  for (const flags of invalid) {
    const child = spawnSync('/bin/bash', [shellFile, ...flags, process.execPath], {
      env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, timeout: 5000, maxBuffer: 4096,
    });
    assert.equal(child.error, undefined, flags.join(' ')); assert.equal(child.signal, null, flags.join(' '));
    assert.equal(child.status, 2, flags.join(' ')); assert.equal(child.stdout.toString('utf8'), '', flags.join(' '));
    assert.equal(child.stderr.toString('utf8'), 'campaign flags must be unique and precede the Node path\n', flags.join(' '));
  }
});

test('the late mode uses the same fixed Delivery entry with diagnostics and no other option', () => {
  const shell = source('../qualify-systemd-user.sh'), entry = source('../qualify-installed-delivery-journey.ts');
  assert(shell.includes('--run-delivery-late-journey) probe_campaign_kind=run-journey; probe_run_driver_mode=--delivery-late-campaign; shift ;;'));
  const guard = shell.indexOf('[[ "$probe_run_driver_mode" != --delivery-late-campaign || "$probe_volume_mode" = delay-50ms ]]');
  assert(guard >= 0 && guard < shell.indexOf('if [[ $(id -u)'));
  assert(shell.includes('|| "$probe_run_driver_mode" = --delivery-late-campaign || "$probe_run_driver_mode" = --delivery-stop-campaign ]]; then'));
  assert(shell.includes('--run-delivery-stop-journey|--run-delivery-late-journey|--run-failure-journey'));
  assert(shell.includes('readonly probe_run_driver="$probe_source_dir/qualify-installed-delivery-journey.ts"'));
  assert(shell.includes('"$probe_run_driver" "$probe_run_driver_mode" "$probe_ledger"'));
  assert(entry.includes("mode === '--delivery-late-campaign'"));
  assert(entry.includes("await runInstalledNodeJourney(filename, 'delivery', { publicationRetirementDiagnostics: true, publicationRetirementLate: true })"));
  for (const fixed of ["assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64')",
    'const [mode, filename, ...extra] = process.argv.slice(2)', 'assert(filename && extra.length === 0)',
    "assert.equal(mode, '--delivery-campaign')", "await runInstalledNodeJourney(filename, 'delivery')",
    "mode === '--delivery-delay-campaign'", "mode === '--delivery-stop-campaign'"])
    assert(entry.includes(fixed), fixed);
  const positionalGuard = entry.indexOf("assert(!filename.startsWith('--'))");
  assert(positionalGuard >= 0 && positionalGuard < entry.indexOf('await runInstalledNodeJourney('),
    'a second campaign flag cannot become the ledger filename');
  assert(!/process\.env|buildInstalledSupervisorPackage|new StateStore|publicationRetirementStop: true,.*publicationRetirementLate/u.test(entry));
});

test('the late-result job is independent and free with the original bounds and complete recovery checks', () => {
  const workflow = source('../../../.github/workflows/kernel-foundation.yml');
  const marker = '\n  linux-installed-delivery-late-result:\n', index = workflow.indexOf(marker);
  assert(index >= 0); assert.equal(workflow.split(marker).length, 2);
  const next = /\n  [a-z][a-z0-9-]*:\n/u.exec(workflow.slice(index + marker.length));
  const job = workflow.slice(index, next ? index + marker.length + next.index : undefined);
  for (const fixed of ['    runs-on: ubuntu-22.04\n', '    timeout-minutes: 20\n',
    'uses: actions/checkout@v4', 'persist-credentials: false', 'uses: actions/setup-node@v4', 'node-version: 22.13.0',
    '- run: npm ci', '- run: npm run build', 'id: build',
    'scripts/kernel/testing/installed-volume-guard.test.mjs', 'scripts/kernel/testing/installed-delivery-journey.test.mjs',
    'scripts/kernel/testing/installed-publication-late-entry.test.mjs', 'scripts/kernel/testing/installed-publication-late-wiring.test.mjs',
    'scripts/kernel/testing/supervisor-sea-builder.test.ts', 'scripts/kernel/testing/installed-delivery-result.test.ts',
    'scripts/kernel/testing/installed-delivery-publication-result.test.ts', 'scripts/kernel/testing/installed-publication-late-journal.test.ts',
    'scripts/kernel/testing/installed-publication-late-result.test.ts', 'scripts/kernel/testing/installed-publication-retirement.test.ts',
    'scripts/kernel/testing/installed-publication-journal.test.ts', 'scripts/kernel/testing/installed-publication-recovery.test.ts',
    'scripts/kernel/testing/installed-run-progress.test.ts',
    'sudo apt-get install -y gnome-keyring libglib2.0-dev libssl-dev musl-tools bubblewrap libcap-dev libselinux1-dev meson ninja-build e2fsprogs libext2fs-dev pkg-config dmsetup kmod',
    'test "$RUNNER_ENVIRONMENT" = github-hosted', 'test "$RUNNER_OS" = Linux', 'test "$RUNNER_ARCH" = X64',
    'sudo /usr/sbin/modprobe dm_delay', 'sudo /usr/bin/udevadm settle --timeout=5',
    'test -d /sys/module/dm_mod', 'test -d /sys/module/dm_delay', 'test -c /dev/mapper/control',
    'sudo "$probe_node" --test --test-concurrency=1 --import tsx scripts/kernel/testing/installed-publication-crash-observer.test.ts',
    "if: ${{ !cancelled() && steps.build.outcome == 'success' }}",
    '--delay-volume --run-delivery-late-journey "$probe_node" "$RUNNER_TEMP/cliq-installed-delivery-late-result"'])
    assert(job.includes(fixed), fixed);
  assert(!/self-hosted|    needs:|continue-on-error|drop_caches|modprobe -r|dmsetup (?:remove_all|suspend|reload)|--test-force-exit/u.test(job));
  assert.equal((job.match(/uses: actions\/upload-artifact@v4/gu) ?? []).length, 1);
  for (const fixed of ['if: always()', 'name: installed-delivery-late-result-${{ github.run_id }}-${{ github.run_attempt }}',
    'path: ${{ runner.temp }}/cliq-installed-delivery-late-result/*.json', 'if-no-files-found: warn', 'retention-days: 7'])
    assert(job.includes(fixed), fixed);
  for (const previous of ['linux-installed-delivery', 'linux-installed-delivery-delayed-volume', 'linux-installed-delivery-original-stop'])
    assert(workflow.includes(`\n  ${previous}:\n`));
});
