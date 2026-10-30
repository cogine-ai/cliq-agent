import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const workflowUrl = new URL('../../.github/workflows/kernel-foundation.yml', import.meta.url);

test('the locked Node source option rejects mixed modes and invalid archives before host inspection', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'cliq-qualification-options-'));
  try {
    const archive = path.join(root, 'owned-archive'), alias = path.join(root, 'alias');
    await writeFile(archive, 'owned parser fixture'); await symlink(archive, alias);
    const shell = fileURLToPath(new URL('../../scripts/kernel/qualify-systemd-user.sh', import.meta.url));
    const node = '/fixed-nonexistent-node';
    for (const args of [
      ['--locked-node', archive, node],
      ['--run-delivery-journey', '--locked-node', archive, node],
      ['--run-verifier-journey', '--locked-node'],
      ['--run-verifier-journey', '--locked-node', 'relative-archive', node],
      ['--run-verifier-journey', '--locked-node', root, node],
      ['--run-verifier-journey', '--locked-node', alias, node],
      ['--run-verifier-journey', '--locked-node', path.join(root, 'missing'), node],
    ]) {
      const result = spawnSync('/bin/bash', [shell, ...args], { encoding: 'utf8', timeout: 2000 });
      assert.ifError(result.error); assert.equal(result.status, 2); assert.equal(result.stdout, '');
      assert.equal(result.stderr, 'locked Node qualification requires its fixed verifier campaign and official archive\n');
    }
    for (const args of [
      ['--run-verifier-journey', '--locked-node', archive, '--locked-node', archive, node],
      ['--run-verifier-journey', '--locked-node', archive, '--run-delivery-journey', node],
      ['--run-verifier-journey', node, '--locked-node', archive],
    ]) {
      const result = spawnSync('/bin/bash', [shell, ...args], { encoding: 'utf8', timeout: 2000 });
      assert.ifError(result.error); assert.equal(result.status, 2); assert.equal(result.stdout, '');
      assert.equal(result.stderr, 'campaign flags must be unique and precede the Node path\n');
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

function stepBlocks(workflow: string): string[] {
  const lines = workflow.split('\n');
  const blocks: string[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const start = /^(\s*)- (?:uses|name|run):/.exec(lines[index]);
    if (!start) continue;

    let end = index + 1;
    while (end < lines.length && !new RegExp(`^${start[1]}- (?:uses|name|run):`).test(lines[end])) {
      end += 1;
    }
    blocks.push(lines.slice(index, end).join('\n'));
    index = end - 1;
  }

  return blocks;
}

test('Kernel foundation checkout never persists the GitHub credential', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  const checkouts = stepBlocks(workflow).filter((block) =>
    /- uses: actions\/checkout@/.test(block)
  );

  assert.ok(checkouts.length > 0, 'workflow must have checkout steps to verify');
  for (const checkout of checkouts) {
    assert.match(checkout, /\n\s+with:\n\s+persist-credentials: false(?:\n|$)/);
  }
});

test('Linux qualification cleanup kills and removes the whole delegated cgroup tree', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  const cleanup = stepBlocks(workflow).find((block) =>
    /- name: Remove delegated cgroup subtree/.test(block)
  );

  assert.ok(cleanup, 'cleanup step must exist');
  assert.match(
    cleanup,
    /printf '1\\n' \| sudo tee "\$CLIQ_CGROUP_PARENT\/cgroup\.kill"[\s\S]*grep -q '\^populated 0\$' "\$CLIQ_CGROUP_PARENT\/cgroup\.events"[\s\S]*while IFS= read -r -d '' child; do\n\s+sudo rmdir "\$child"\n\s+done < <\(find "\$CLIQ_CGROUP_PARENT" -mindepth 1 -depth -type d -print0\)\n\s+sudo rmdir "\$CLIQ_CGROUP_PARENT"/
  );
});

test('credential lifecycle and model-input coverage require independent unchanged-budget Linux jobs', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  for (const [jobId, mode, artifact] of [
    ['linux-credential-authority', '--credentials', 'credential-journey'],
    ['linux-credential-model-input', '--credentials-model-input', 'credential-model-input'],
  ]) {
    const job = workflow.match(new RegExp(`\\n  ${jobId}:\\n[\\s\\S]*?(?=\\n  [a-z][a-z0-9-]*:\\n|$)`))?.[0];
    assert(job, `missing independent required coverage job ${jobId}`);
    assert.match(job, /runs-on: ubuntu-22\.04\n/);
    assert.match(job, /timeout-minutes: 20\n/);
    assert.doesNotMatch(job, /(?:continue-on-error|needs):/);
    assert.match(job, new RegExp(`qualify-systemd-user\\.sh ${mode} "\\$probe_node"`));
    assert.match(job, new RegExp(`name: ${artifact}-\\$\\{\\{ github\\.run_id \\}\\}-\\$\\{\\{ github\\.run_attempt \\}\\}`));
    assert.match(job, /if: always\(\)[\s\S]*uses: actions\/upload-artifact@v4/);
    assert.match(job, /retention-days: 7/);
  }
});

test('real guest verifier stays in the existing free bounded job without replacing ordinary lifecycle coverage', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  const job = workflow.match(/\n  linux-run-execution:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u)?.[0];
  assert(job);
  assert.match(job, /runs-on: ubuntu-22\.04\n/); assert.match(job, /timeout-minutes: 20\n/);
  assert.doesNotMatch(job, /continue-on-error:/u);
  const nativeRegression = stepBlocks(job).find(block => block.includes('- name: Verify real worker seccomp ABI and syscall denials'));
  assert(nativeRegression);
  assert.match(nativeRegression, /musl-gcc -std=c11 -O2 -Wall -Wextra -Werror -static[\s\S]*native\/linux\/worker-channel\.test\.c -o "\$channel_regression"\n\s+"\$channel_regression"/u);
  assert.match(nativeRegression, /native\/linux\/worker-seccomp\.test\.c -o "\$regression"\n\s+"\$regression"/u);
  assert.match(nativeRegression, /musl-gcc -std=c11 -O2 -Wall -Wextra -Werror -static[\s\S]*native\/linux\/worker-sha256\.test\.c -o "\$hash_regression"\n\s+"\$hash_regression"/u,
    'the actual musl toolchain must execute both portable and real-CPUID-selected SHA vectors before the guest campaign');
  assert.match(job, /libext2fs-dev pkg-config/u);
  assert.match(job, /truncate -s 128M "\$image"/u, 'ordinary native capacity and all existing assertions stay intact');
  assert.match(job, /run-linux-worker-campaign\.ts/u);
  assert.match(job, /run-linux-guest-verifier-campaign\.ts --prepare/u, 'uses the checksum-pinned SEA carrier builder');
  assert.match(job, /truncate -s 512M "\$guest_state_image"/u, 'the complete 256 MiB image fits a separate disposable CAS volume');
  assert.match(job, /run-linux-guest-verifier-campaign\.ts --run/u);
  assert.match(job, /CLIQ_I1_GUEST_STATE_VOLUME[\s\S]*--clear-groups/u);
  const cleanup = stepBlocks(job).find(block => block.includes('- name: Retire disposable execution resources'));
  assert(cleanup); assert.match(cleanup, /if: always\(\)/u);
  assert.match(cleanup, /cgroup\.kill[\s\S]*populated 0[\s\S]*sudo rmdir/u);
  const guestCleanup = stepBlocks(job).find(block => block.includes('- name: Retire the independent guest StateRoot fixture'));
  assert(guestCleanup); assert.match(guestCleanup, /if: always\(\)/u);
  assert.match(guestCleanup, /mountpoint -q "\$CLIQ_I1_GUEST_VOLUME"; then sudo umount "\$CLIQ_I1_GUEST_VOLUME"/u);
  assert.match(job, /name: native-guest-verifier-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u);
  assert.match(job, /guest-extractor-report\.json[\s\S]*guest-verifier-report\.json[\s\S]*guest-campaign-failure\.json/u);
  assert.match(job, /retention-days: 7/u);
});

test('installed verifier uses its own free bounded manager journey without weakening any original campaign', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  const job = workflow.match(/\n  linux-installed-verifier:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u)?.[0];
  assert(job); assert.match(job, /runs-on: ubuntu-22\.04\n/u); assert.match(job, /timeout-minutes: 20\n/u);
  assert.doesNotMatch(job, /(?:continue-on-error|needs):/u);
  assert.match(job, /persist-credentials: false/u);
  assert.match(job, /libext2fs-dev pkg-config/u);
  assert.match(job, /qualify-systemd-user\.sh --run-verifier-journey --locked-node "\$probe_npm_archive" "\$probe_node"/u);
  const npmSource = stepBlocks(job).find(block => block.includes('- name: Acquire the exact official npm qualification source'));
  assert(npmSource);
  assert.match(npmSource, /fetch\(NPM_DATA_RECIPE\.officialArchive/u);
  assert.match(npmSource, /redirect: 'error', signal: AbortSignal\.timeout\(60000\)/u);
  assert.match(npmSource, /total <= NPM_DATA_RECIPE\.archiveBytes/u);
  assert.match(npmSource, /assert\.equal\(total, NPM_DATA_RECIPE\.archiveBytes\)/u);
  assert.match(npmSource, /buildInstalledNpmDataAsset\(archive\)/u);
  assert.match(npmSource, /O_EXCL \| constants\.O_NOFOLLOW/u);
  assert.match(npmSource, /finally \{ await file\.close\(\); \}/u);
  assert.match(job, /steps\.npm_source\.outcome == 'success'/u);
  assert.match(job, /if: always\(\)[\s\S]*actions\/upload-artifact@v4/u);
  assert.match(job, /name: installed-verifier-journey-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u);
  assert.match(job, /retention-days: 7/u);
  const shell = await readFile(new URL('../../scripts/kernel/qualify-systemd-user.sh', import.meta.url), 'utf8');
  assert.match(shell, /--run-verifier-journey\) probe_campaign_kind=run-journey; probe_run_driver_mode=--verifier-campaign;/u);
  assert.match(shell, /\/usr\/bin\/timeout --kill-after=1s 1s \/usr\/bin\/fuser -m -M -- "\$probe_home" >&2 \|\| true/u);
  assert.doesNotMatch(shell, /fuser[^\n]*(?:--kill|(?:^|\s)-[a-zA-Z]*k)/u);
  assert.match(shell, /probe_run_driver_mode" = --verifier-campaign[\s\S]*?qualify-installed-verifier-journey\.ts[\s\S]*?else[\s\S]*?qualify-installed-run-journey\.ts/u);
  const consumer = await readFile(new URL('../../scripts/kernel/qualify-installed-verifier-journey.ts', import.meta.url), 'utf8');
  assert.match(consumer, /import \{ runInstalledNodeJourney \} from '\.\/testing\/installed-node-journey\.js'/u);
  assert.match(consumer, /assert\.equal\(mode, '--verifier-campaign'\); assert\(filename\)/u);
  assert.match(consumer, /assert\(extra\.length === 0 \|\| extra\.length === 2 && extra\[0\] === '--locked-node' && extra\[1\]\)/u);
  assert.match(consumer, /constants\.O_RDONLY \| constants\.O_NOFOLLOW/u);
  assert.match(consumer, /before\.nlink === 1n && before\.size === BigInt\(NPM_DATA_RECIPE\.archiveBytes\)/u);
  assert.match(consumer, /buildInstalledNpmDataAsset\(npmDependencyArchive\)/u);
  assert.match(consumer, /await runInstalledNodeJourney\(filename, 'verifier', npmDependencyArchive \? \{ npmDependencyArchive \} : \{\}\)/u);
  const driver = await readFile(new URL('../../scripts/kernel/testing/installed-node-journey.ts', import.meta.url), 'utf8');
  assert.match(driver, /maxBytes: 512 \* 1024 \* 1024, maxStreams: 4096/u);
  assert.match(driver, /'required_pass', 'required_repair', 'advisory_failure', 'required_timeout'/u);
  assert.match(driver, /scanCredentialSecretCorpus\(\{ stateRoot: recipe\.stateRoot, uid: ledger\.uid, evidenceDirs: \[\], scanner \}\)/u);
  assert.match(driver, /stopped\.TimeoutStopUSec, '2s'/u);
  assert.match(driver, /setTimeout\(resolve,60000\)/u);
  assert.match(driver, /retries: kind === 'required_timeout' \? 1 : 0/u);
});

test('installed status deadlock regression observes the fixed original assertion without replacing candidate Linux coverage', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  const job = workflow.match(/\n  linux-installed-verifier:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u)?.[0];
  assert(job); assert.match(job, /runs-on: ubuntu-22\.04\n/u); assert.match(job, /timeout-minutes: 20\n/u);
  assert.doesNotMatch(job, /(?:continue-on-error|needs):/u);
  const experiment = stepBlocks(job).find(block => block.includes('- name: Observe the fixed original installed status deadlock'));
  assert(experiment, 'the original exact deadline assertion must really fail on the immutable original source');
  assert.match(experiment, /git cat-file -e 'b6140b57836e19b0fb937327af449e8138f47eca\^\{commit\}'/u);
  assert.match(experiment, /git fetch --no-tags --depth=1 origin b6140b57836e19b0fb937327af449e8138f47eca/u);
  assert.match(experiment, /node scripts\/kernel\/testing\/installed-status-regression\.mjs "\$RUNNER_TEMP\/cliq-installed-status-regression\/status-borrow-regression\.json"/u);
  assert.doesNotMatch(experiment, /NODE_OPTIONS=|NODE_V8_COVERAGE=|timeout |\|\| true|set \+e/u);
  assert.match(job, /node --test[^\n]*installed-status-regression\.test\.mjs/u);
  assert.match(job, /qualify-systemd-user\.sh --run-verifier-journey --locked-node "\$probe_npm_archive" "\$probe_node"/u);
  assert.match(job, /name: installed-status-regression-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u);
  assert.match(job, /path: \$\{\{ runner\.temp \}\}\/cliq-installed-status-regression\/status-borrow-regression\.json/u);
});

test('installed Delivery keeps its own free bounded production journey and cannot override its capability gate', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  const job = workflow.match(/\n  linux-installed-delivery:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u)?.[0];
  assert(job, 'Delivery requires its own real installed campaign');
  assert.match(job, /runs-on: ubuntu-22\.04\n/u); assert.match(job, /timeout-minutes: 20\n/u);
  assert.doesNotMatch(job, /(?:continue-on-error|needs):/u);
  assert.match(job, /persist-credentials: false/u);
  assert.match(job, /libext2fs-dev pkg-config/u);
  assert.match(job, /qualify-systemd-user\.sh --run-delivery-journey "\$probe_node"/u);
  assert.match(job, /if: always\(\)[\s\S]*actions\/upload-artifact@v4/u);
  assert.match(job, /name: installed-delivery-journey-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u);
  assert.match(job, /retention-days: 7/u);
  const consumer = await readFile(new URL('../../scripts/kernel/qualify-installed-delivery-journey.ts', import.meta.url), 'utf8');
  assert.match(consumer, /await runInstalledNodeJourney\(filename, 'delivery'\)/u);
  const driver = await readFile(new URL('../../scripts/kernel/testing/installed-node-journey.ts', import.meta.url), 'utf8');
  assert.match(driver, /assert\(supported,[\s\S]*the genuine production composition must advertise explicit Delivery/u);
  assert.doesNotMatch(driver, /INSTALLED_DELIVERY_COMPOSITION_COMPLETE|supportsInstalledDelivery\s*=|featureOverride/u);
});

test('normal daily coverage uses the signed command path and original joined fixture without replacing prior campaigns', async () => {
  const workflow = await readFile(workflowUrl, 'utf8');
  const job = workflow.match(/\n  linux-installed-daily:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u)?.[0];
  assert(job); assert.match(job, /runs-on: ubuntu-22\.04\n/u); assert.match(job, /timeout-minutes: 20\n/u);
  assert.doesNotMatch(job, /(?:continue-on-error|needs):/u); assert.match(job, /persist-credentials: false/u);
  assert.match(job, /node-version: 22\.13\.0/u); assert.match(job, /libext2fs-dev pkg-config/u);
  const build = job.indexOf('- run: npm run build'), files = job.indexOf('src/client/private-files.test.ts');
  assert(build >= 0 && files > build, 'a clean runner builds the actual native helper before filesystem/mutex preflight');
  const exercise = stepBlocks(job).find(block => block.includes('- name: Exercise the same signed image through its normal daily commands'));
  assert(exercise); assert.match(exercise, /steps\.build\.outcome == 'success'/u);
  for (const guard of ['test "$RUNNER_ENVIRONMENT" = github-hosted', 'test "$RUNNER_OS" = Linux', 'test "$RUNNER_ARCH" = X64'])
    assert(exercise.includes(guard));
  assert.match(exercise, /qualify-systemd-user\.sh --run-daily-journey "\$probe_node" "\$RUNNER_TEMP\/cliq-installed-daily-journey"/u);
  assert.doesNotMatch(exercise, /--delay-volume|--run-provider-journey|\|\| true|set \+e/u);
  const retained = stepBlocks(job).find(block => block.includes('- name: Retain original daily workflow and unchanged cleanup evidence'));
  assert(retained); assert.match(retained, /if: always\(\)/u); assert.match(retained, /actions\/upload-artifact@v4/u);
  assert.match(retained, /path: \$\{\{ runner\.temp \}\}\/cliq-installed-daily-journey\/\*\.json/u); assert.match(retained, /retention-days: 7/u);
  for (const [id, mode] of [['linux-installed-verifier', '--run-verifier-journey'], ['linux-installed-delivery', '--run-delivery-journey'],
    ['linux-credential-authority', '--credentials'], ['linux-credential-model-input', '--credentials-model-input']]) {
    const original = workflow.match(new RegExp(`\\n  ${id}:\\n[\\s\\S]*?(?=\\n  [a-z][a-z0-9-]*:\\n|$)`))?.[0];
    assert(original, `the original independent ${id} campaign remains`);
    assert(original.includes(`qualify-systemd-user.sh ${mode} `)); assert.doesNotMatch(original, /(?:continue-on-error|needs):/u);
  }
  const shell = await readFile(new URL('../../scripts/kernel/qualify-systemd-user.sh', import.meta.url), 'utf8');
  assert.match(shell, /--run-daily-journey\) probe_campaign_kind=run-journey; probe_run_driver_mode=--daily-campaign; shift/u);
  assert.match(shell, /probe_run_driver_mode" != --daily-campaign \|\| "\$probe_volume_mode" = loop/u);
  assert.match(shell, /probe_run_driver_mode" = --daily-campaign[\s\S]*?qualify-installed-daily-journey\.ts/u);
  const consumer = await readFile(new URL('../../scripts/kernel/qualify-installed-daily-journey.ts', import.meta.url), 'utf8');
  assert.match(consumer, /assert\.equal\(mode, '--daily-campaign'\); assert\(filename\); assert\.equal\(extra\.length, 0\)/u);
  assert.match(consumer, /await runInstalledNodeJourney\(filename, 'daily'\)/u);
  const driver = await readFile(new URL('../../scripts/kernel/testing/installed-node-journey.ts', import.meta.url), 'utf8');
  assert.match(driver, /if \(dailyJourney\) assert\.deepEqual\(Object\.keys\(options\), \[\]/u);
  assert.match(driver, /if \(dailyJourney\) await dailyCommand\(\['setup'\]\)/u);
  assert.match(driver, /if \(dailyJourney\) await dailyCommand\(\['models', 'add', dailyAlias, '--api-key-stdin'\], 60_000, secret\)/u);
  assert.match(driver, /runInstalledDailyProviderJourney\([\s\S]*?command: dailyCommand/u);
  assert.match(driver, /report\.normalCliCommands\.map\([\s\S]*?\['setup', 'models', 'run', 'result', 'apply'\]/u);
  assert.match(driver, /const dailyCommand = async[^\n]+\n\s*assert\(dailyJourney && \[30_000, 60_000, 90_000\]\.includes\(timeout\)\)/u,
    'the normal commands keep the original distinct command budgets');
  assert.match(driver, /await runInstalledDailyCommand\(\{ executable: '\/usr\/sbin\/runuser',[\s\S]*?path\.join\(recipe\.packageRoot, 'supervisor'\), \.\.\.argv[\s\S]*?deadlineMs: timeout, scanner \}/u);
  const command = await readFile(new URL('../../scripts/kernel/testing/installed-daily-command.ts', import.meta.url), 'utf8');
  assert.match(command, /Promise\.all\(\[closed, written, streamsClosed\]\)/u);
  const joined = command.indexOf('Promise.all([closed, streamsClosed, written.catch(() => {})])');
  const retired = command.indexOf('out.close(); err.close();', joined);
  const returned = command.indexOf('return { stdout: Buffer.concat(stdout)', retired);
  assert(joined > 0 && retired > joined && returned > retired,
    'the actual command child, complete stdin write and inherited pipes join before scanner retirement and success');
  assert.match(command, /descendantRetirement = 'outer_uid_coordinator_required'/u);
  assert.match(command, /if \(failure\) for \(const stream of streams\) stream\.destroy\(\)/u);
});
