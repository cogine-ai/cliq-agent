import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

// Test-only projection. Validate every allowed routing addition before removing
// it, so existing immutable campaign hashes still check the ORIGINAL job bodies.
const routerJob = "  ci-route:\n    name: Select affected qualification groups\n    runs-on: ubuntu-22.04\n    timeout-minutes: 5\n    outputs:\n      typescript: ${{ steps.route.outputs.typescript }}\n      native: ${{ steps.route.outputs.native }}\n      credentials: ${{ steps.route.outputs.credentials }}\n      run: ${{ steps.route.outputs.run }}\n      verifier: ${{ steps.route.outputs.verifier }}\n      delivery: ${{ steps.route.outputs.delivery }}\n      upgrade: ${{ steps.route.outputs.upgrade }}\n      permission: ${{ steps.route.outputs.permission }}\n      full: ${{ steps.route.outputs.full }}\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n          fetch-depth: 0\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 22.13.0\n      - name: Check routing and preserved qualification wiring\n        run: node --test scripts/ci/route.test.mjs\n      - name: Select immutable-source qualification scope\n        id: route\n        run: node scripts/ci/route.mjs\n";
const triggers = '  workflow_dispatch:\n  merge_group:\n    types: [checks_requested]\n';
export const providerInputs = "    inputs:\n      qualification_group:\n        description: Manual free-runner diagnosis only; full remains the release gate\n        type: choice\n        options: [full, verifier, pr532, builtin]\n        default: full\n      real_provider:\n        description: Run only the explicitly funded, real-provider journey\n        type: boolean\n        default: false\n      diagnostic_cpu:\n        description: Controlled PR532 CPU sample only; intentionally does not qualify delivery\n        type: boolean\n        default: false\n      expected_revision:\n        description: Exact reviewed commit required for a targeted manual journey\n        type: string\n        default: ''\n";
const providerJob = "  real-provider:\n    if: ${{ github.event_name == 'workflow_dispatch' && inputs.real_provider && !inputs.diagnostic_cpu && inputs.qualification_group == 'full' && inputs.expected_revision == github.sha && github.repository == 'cogine-ai/cliq-agent' }}\n    uses: ./.github/workflows/kernel-provider.yml\n    with:\n      expected_revision: ${{ inputs.expected_revision }}\n    secrets:\n      provider_key: ${{ secrets.CLIQ_PROVIDER_QUALIFICATION_KEY }}\n";
const previewJob = funded => `  pr532-${funded ? 'provider' : 'controlled'}:
    if: ${'\${{'} github.event_name == 'workflow_dispatch' && ${funded ? '' : '!'}inputs.real_provider && ${funded ? '!inputs.diagnostic_cpu && ' : ''}inputs.qualification_group == 'pr532' && inputs.expected_revision == github.sha && github.repository == 'cogine-ai/cliq-agent' }}
    uses: ./.github/workflows/kernel-provider.yml
    with:
      expected_revision: ${'\${{'} inputs.expected_revision }}
      pr532: true
      funded: ${funded}
${funded ? '' : "      diagnostic_cpu: \${{ inputs.diagnostic_cpu }}\n"}${funded ? "    secrets:\n      provider_key: \${{ secrets.CLIQ_PROVIDER_QUALIFICATION_KEY }}\n" : ''}`;
const foundation = {
  "installed-runtime-upgrade": "upgrade",
  "typescript": "typescript",
  "linux-credential-authority": "credentials",
  "linux-credential-model-input": "credentials",
  "linux-installed-finalizer-shutdown": "credentials",
  "linux-installed-authority-stop": "credentials",
  "linux-installed-settlement-storage": "run",
  "linux-installed-shutdown": "run",
  "linux-installed-preparation-shutdown": "run",
  "linux-installed-effects-shutdown": "run",
  "linux-installed-request-resources": "run",
  "linux-installed-run": "run",
  "linux-supervisor-preflight": "native",
  "linux-strong-probe": "native",
  "linux-run-execution": "native",
  "linux-installed-daily": "verifier",
  "linux-installed-verifier": "verifier",
  "linux-installed-delivery": "delivery",
  "linux-installed-delivery-delayed-volume": "delivery",
  "linux-installed-delivery-original-stop": "delivery",
  "linux-installed-delivery-late-result": "delivery"
};
const permission = { 'linux-installed-permission': 'permission' };

function replaceOnce(text, part, replacement) {
  assert.equal(text.split(part).length, 2, 'routing addition must occur exactly once');
  return text.replace(part, replacement);
}

export function projectQualificationWorkflow(workflow, kind = 'foundation') {
  assert(kind === 'foundation' || kind === 'permission');
  if (kind === 'foundation') {
    // Recompose the original preflight for the immutable workflow check.
    // Only this job's disposable test step and its evidence move runners.
    const statePreflight = workflow.match(/^  linux-installed-state-preflight:\n[\s\S]*?(?=^  [a-z][a-z0-9-]*:$)/m)?.[0];
    const preflightSetup = workflow.match(/^  linux-supervisor-preflight:\n[\s\S]*?(?=^      # These independent disposable fixtures)/m)?.[0];
    assert(statePreflight && preflightSetup, 'both preflight jobs must be present');
    const stateSetup = preflightSetup.replace('linux-supervisor-preflight:', 'linux-installed-state-preflight:')
      .replace('name: Linux Supervisor image and actual user-manager diagnostics', 'name: Linux installed-state and native-retirement diagnostics')
      .replace('    # Component/OS facts only, not an installed I1 qualification. Standard\n    # public-repository runner; never substitute a detached child manager.\n', '');
    const stateTests = statePreflight.match(/^      - name: Verify installed-state and native-retirement boundaries on Linux 22.04\n[\s\S]*?(?=^      - name: Retain bounded endpoint crash evidence)/m)?.[0];
    assert(stateTests);
    const evidence = '            ${{ runner.temp }}/cliq-endpoint-crash-*/**\n';
    assert.equal(statePreflight, stateSetup + stateTests + '      - name: Retain bounded endpoint crash evidence\n' +
      '        if: always()\n        uses: actions/upload-artifact@v4\n        with:\n' +
      '          name: installed-state-preflight-${{ github.run_id }}-${{ github.run_attempt }}\n' +
      '          path: |\n' + evidence + '          if-no-files-found: warn\n          retention-days: 7\n\n');
    workflow = replaceOnce(workflow, statePreflight, '');
    const imageStep = '      - name: Qualify complete application image binding\n';
    workflow = replaceOnce(workflow, imageStep, stateTests + imageStep);
    const retirementArtifact = '            ${{ runner.temp }}/cliq-installed-retirement/*.json\n';
    workflow = replaceOnce(workflow, retirementArtifact, retirementArtifact + evidence);

    // Check the additive real seal/ownership regressions in their exact
    // original step; keep the historical campaign digest unchanged.
    const nativeTests = '          node --test --test-concurrency=1 --import tsx scripts/kernel/testing/dependency-native-family.test.ts scripts/kernel/testing/dependency-broker-lifecycle.test.ts scripts/kernel/testing/dependency-npm-stage.test.ts scripts/kernel/testing/preparing-git-native.test.ts scripts/kernel/testing/installed-genesis.test.ts\n';
    workflow = replaceOnce(workflow, nativeTests +
      '          node --test --test-concurrency=1 --import tsx src/sandbox/sealed-images.test.ts src/sandbox/builtin-tool-native.test.ts\n', nativeTests);
    // A separate diagnostic cannot replace or modify an original campaign.
    const probe = workflow.match(/^  linux-installed-builtin-node:\n[\s\S]*?(?=^  [a-z][a-z0-9-]*:$)/m);
    assert(probe, 'the fixed independent Node probe must be present');
    const original = "    if: ${{ !cancelled() && (needs.ci-route.result != 'success' || needs.ci-route.outputs.verifier != 'false') }}";
    const expanded = original.replace(" != 'false')", " != 'false' || (github.event_name == 'workflow_dispatch' && !inputs.real_provider && !inputs.diagnostic_cpu && inputs.qualification_group == 'builtin' && inputs.expected_revision == github.sha && github.repository == 'cogine-ai/cliq-agent'))");
    assert.equal(probe[0].split(expanded).length, 2, 'only the existing builtin probe gains exact manual diagnosis');
    const mountTest = '      - name: Check native bounded mount reads\n        run: node --test --import tsx src/sandbox/verifier-mount.test.ts\n';
    const originalProbe = replaceOnce(probe[0].replace(expanded, original), mountTest, '');
    assert.equal(createHash('sha256').update(originalProbe).digest('hex'), '87acfb7dc2ecbd5e76a85158104bb3d8e3f6b0a701e631225642c0f113e4ca82');
    workflow = replaceOnce(workflow, probe[0], '');
    const readCost = workflow.match(/^  linux-installed-read-cost:\n[\s\S]*?(?=^  [a-z][a-z0-9-]*:$)/m);
    assert(readCost, 'the independent read-cost diagnostic must remain separate');
    assert.equal(createHash('sha256').update(readCost[0]).digest('hex'), '70b7f47ebb22691d530451e394e0b90b4d81f215d593c17513e550120947eb95');
    workflow = replaceOnce(workflow, readCost[0], '');
    workflow = replaceOnce(workflow, '  workflow_dispatch:\n' + providerInputs, '  workflow_dispatch:\n');
    for (const funded of [true, false]) workflow = replaceOnce(workflow, previewJob(funded) + '\n', '');
    workflow = replaceOnce(workflow, 'jobs:\n' + providerJob + '\n', 'jobs:\n');
    workflow = replaceOnce(workflow,
      "  group: kernel-foundation-${{ github.workflow }}-${{ github.ref }}-${{ inputs.qualification_group == 'pr532' && 'pr532' || inputs.qualification_group == 'verifier' && 'verifier' || inputs.qualification_group == 'builtin' && 'builtin' || inputs.real_provider && 'provider' || 'checks' }}\n  cancel-in-progress: ${{ !inputs.real_provider }}\n",
      '  group: kernel-foundation-${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true\n');
  }
  const jobs = kind === 'foundation' ? foundation : permission;
  const events = "on:\n  pull_request:\n    branches: [main]\n  push:\n    branches: [main, 'cliq/**', 'codex/**']\n";
  let projected = replaceOnce(workflow, events + triggers, events);
  projected = replaceOnce(projected, 'jobs:\n' + routerJob + '\n', 'jobs:\n');
  assert.equal(projected.includes('ci-route:\n'), false, 'no duplicate or altered router job');
  assert.deepEqual([...projected.matchAll(/^  ([a-z][a-z0-9-]*):$/gm)].map(match => match[1])
    .filter(id => Object.hasOwn(jobs, id)), Object.keys(jobs), 'original job ordering remains');
  const jobSection = projected.slice(projected.indexOf('\njobs:\n') + 7);
  assert.deepEqual([...jobSection.matchAll(/^  ([a-z][a-z0-9-]*):$/gm)].map(match => match[1]),
    Object.keys(jobs), 'no original job can be omitted or silently added');
  for (const [id, group] of Object.entries(jobs)) {
    const original = '  ' + id + ':\n';
    const routed = original + '    needs: ci-route\n' +
      "    if: ${{ !cancelled() && (needs.ci-route.result != 'success' || needs.ci-route.outputs." + group + " != 'false') }}\n";
    assert.equal(projected.split(routed).length, 2, 'each job requires exactly its approved router dependency and conservative condition');
    projected = projected.replace(routed, original);
  }
  assert.doesNotMatch(projected, /^    (?:needs|if):/m, 'no additional job dependency or gate');
  assert.doesNotMatch(projected, /ci-route|workflow_dispatch|merge_group/, 'only the approved routing additions may be projected');
  return projected;
}

