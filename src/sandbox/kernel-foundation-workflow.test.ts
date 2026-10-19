import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../../.github/workflows/kernel-foundation.yml', import.meta.url);

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
  assert.match(job, /qualify-systemd-user\.sh --run-verifier-journey "\$probe_node"/u);
  assert.match(job, /if: always\(\)[\s\S]*actions\/upload-artifact@v4/u);
  assert.match(job, /name: installed-verifier-journey-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u);
  assert.match(job, /retention-days: 7/u);
  const shell = await readFile(new URL('../../scripts/kernel/qualify-systemd-user.sh', import.meta.url), 'utf8');
  assert.match(shell, /--run-verifier-journey\) probe_campaign_kind=run-journey; probe_run_driver_mode=--verifier-campaign;/u);
  assert.match(shell, /probe_run_driver_mode" = --verifier-campaign[\s\S]*?qualify-installed-verifier-journey\.ts[\s\S]*?else[\s\S]*?qualify-installed-run-journey\.ts/u);
  const consumer = await readFile(new URL('../../scripts/kernel/qualify-installed-verifier-journey.ts', import.meta.url), 'utf8');
  assert.match(consumer, /import \{ runInstalledNodeJourney \} from '\.\/testing\/installed-node-journey\.js'/u);
  assert.match(consumer, /assert\.equal\(mode, '--verifier-campaign'\); assert\(filename && extra\.length === 0\)/u);
  assert.match(consumer, /await runInstalledNodeJourney\(filename, 'verifier'\)/u);
  const driver = await readFile(new URL('../../scripts/kernel/testing/installed-node-journey.ts', import.meta.url), 'utf8');
  assert.match(driver, /maxBytes: 512 \* 1024 \* 1024, maxStreams: 4096/u);
  assert.match(driver, /'required_pass', 'required_repair', 'advisory_failure', 'required_timeout'/u);
  assert.match(driver, /scanCredentialSecretCorpus\(\{ stateRoot: recipe\.stateRoot, uid: ledger\.uid, evidenceDirs: \[\], scanner \}\)/u);
  assert.match(driver, /stopped\.TimeoutStopUSec, '2s'/u);
  assert.match(driver, /setTimeout\(resolve,60000\)/u);
  assert.match(driver, /retries: kind === 'required_timeout' \? 1 : 0/u);
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
