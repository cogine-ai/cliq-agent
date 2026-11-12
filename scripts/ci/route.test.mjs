import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { groups, routeEvent, routePaths } from './route.mjs';
import { projectQualificationWorkflow, providerInputs } from './testing/workflow-projection.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const all = Object.fromEntries(groups.map(group => [group, true]));
function chosen(result) { return groups.filter(group => result.groups[group]); }

test('ordinary documentation selects no expensive jobs and reports its limited scope', () => {
  const result = routePaths(['README.md', 'docs/kernel/delivery-plan.md', 'docs/a file.md']);
  assert.deepEqual(chosen(result), []);
  assert.equal(result.full, false);
  assert.equal(result.reason, 'documentation-only');
  assert.equal(result.changedFiles, 3);
});

test('source tests and executable design contracts retain the complete host test matrix', () => {
  for (const filename of ['src/state/example.test.ts', 'src/client/example.test.tsx',
    'docs/rfcs/2026-08-11-durable-verified-run-kernel.md',
    'docs/backlog/durable-verified-run-kernel/01-durable-state-and-migration.md']) {
    assert.deepEqual(chosen(routePaths([filename])), ['typescript']);
  }
});

test('independent qualification inputs select their original campaigns and host checks', () => {
  const examples = [
    ['scripts/kernel/qualify-installed-verifier-journey.ts', ['typescript', 'verifier']],
    ['scripts/kernel/qualify-installed-delivery-journey.ts', ['typescript', 'delivery']],
    ['scripts/kernel/qualify-installed-permission-journey.ts', ['typescript', 'permission']],
    ['scripts/kernel/testing/installed-verifier-result.test.ts', ['typescript', 'verifier', 'permission']],
    ['scripts/kernel/testing/installed-upgrade-result.test.ts', ['typescript', 'upgrade']],
  ];
  for (const [filename, expected] of examples) assert.deepEqual(chosen(routePaths([filename])), expected);
  assert.deepEqual(chosen(routePaths(examples.map(([filename]) => filename))),
    ['typescript', 'verifier', 'delivery', 'upgrade', 'permission']);
});

test('shared imports, runtime, native, dependencies, routing and unknown inputs select everything', () => {
  for (const filename of ['src/state/store.ts', 'src/client/daily-actions.ts', 'native/linux/worker.c',
    'package.json', 'package-lock.json', 'tsconfig.json', 'scripts/build-sdk-types.mjs',
    'scripts/kernel/qualify-systemd-user.sh', 'scripts/kernel/testing/installed-node-journey.ts',
    'scripts/kernel/testing/installed-permission-journey.ts',
    'scripts/kernel/testing/installed-verifier-result.ts', 'scripts/kernel/testing/installed-verifier-evidence.ts',
    'scripts/ci/route.mjs', '.github/workflows/kernel-foundation.yml', 'skills/skill/SKILL.md', 'new-file']) {
    assert.deepEqual(routePaths([filename]).groups, all, filename);
    assert.equal(routePaths(['README.md', filename]).full, true, filename);
  }
});

test('empty, oversized or noncanonical changed-path inputs never produce an empty green scope', () => {
  for (const paths of [undefined, [], Array(20001).fill('README.md'), [null], [''], ['/docs/a'],
    ['../README.md'], ['docs/../a'], ['docs//a'], ['docs/a\nb'], ['docs/a\0b'], ['docs\\a']]) {
    assert.equal(routePaths(paths).full, true);
  }
});

test('main, merge queue and explicit manual qualification always select the complete job set', () => {
  for (const input of [{ eventName: 'push', ref: 'refs/heads/main' },
    { eventName: 'merge_group' }, { eventName: 'workflow_dispatch' }]) {
    const result = routeEvent({ ...input, cwd: '/no-such-repository' });
    assert.deepEqual(result.groups, all);
    assert.equal(result.reason, 'full-qualification');
  }
});

test('new branches, malformed events, unknown history and unsupported events are full', () => {
  for (const event of [{}, { before: '0'.repeat(40), after: '1'.repeat(40) },
    { before: '--help', after: '1'.repeat(40) }, { before: '2'.repeat(40), after: '1'.repeat(40) }]) {
    assert.equal(routeEvent({ eventName: 'push', ref: 'refs/heads/codex/test', event,
      cwd: '/no-such-repository' }).full, true);
  }
  assert.equal(routeEvent({ eventName: 'pull_request', event: {}, cwd: root }).full, true);
  assert.equal(routeEvent({ eventName: 'pull_request_target', event: {}, cwd: root }).full, true);
});

function repository(t) {
  const cwd = mkdtempSync(path.join(tmpdir(), 'cliq-ci-router-'));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const git = (...args) => execFileSync('git', ['-c', 'user.name=CI router fixture',
    '-c', 'user.email=ci-router@example.invalid', '-c', 'commit.gpgsign=false', ...args],
  { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } }).trim();
  git('init', '--initial-branch=main');
  const commit = (filename, bytes) => {
    mkdirSync(path.dirname(path.join(cwd, filename)), { recursive: true });
    writeFileSync(path.join(cwd, filename), bytes);
    git('add', '--', filename); git('commit', '-m', 'owned routing fixture');
    return git('rev-parse', 'HEAD');
  };
  return { cwd, git, commit };
}

test('PR scope uses the actual merge base and includes older commits in the same PR', t => {
  const { cwd, git, commit } = repository(t);
  const base = commit('README.md', 'base');
  git('switch', '-c', 'feature');
  const documentation = commit('docs/notes.md', 'feature');
  git('switch', 'main');
  const updatedBase = commit('src/shared.ts', 'base-only update');
  const input = head => ({ eventName: 'pull_request', cwd, event: {
    pull_request: { base: { sha: updatedBase }, head: { sha: head } },
  } });
  assert.equal(routeEvent(input(documentation)).reason, 'documentation-only',
    'base-only runtime changes must not be misread as a PR deletion');
  git('switch', 'feature');
  commit('src/feature.ts', 'production change');
  const head = commit('docs/notes.md', 'latest docs');
  assert.equal(routeEvent(input(head)).full, true, 'an older production commit remains in the complete PR range');
  const push = routeEvent({ eventName: 'push', ref: 'refs/heads/codex/feature', cwd,
    event: { before: git('rev-parse', 'HEAD~1'), after: head } });
  assert.equal(push.reason, 'documentation-only', 'push scope is incremental, not complete PR qualification');
  assert.notEqual(base, updatedBase);
});

test('only an explicit manual real-provider request at the actual exact commit selects its independent scope', t => {
  const { cwd, commit } = repository(t), head = commit('README.md', 'reviewed source');
  const event = { inputs: { real_provider: 'true', expected_revision: head } };
  const selected = routeEvent({ eventName: 'workflow_dispatch', event, cwd });
  assert.deepEqual(chosen(selected), []); assert.equal(selected.full, false);
  assert.equal(selected.reason, 'explicit-real-provider-only');
  for (const inputs of [{}, { real_provider: 'false', expected_revision: head },
    { real_provider: 'true', expected_revision: 'f'.repeat(40) },
    { real_provider: 'true', expected_revision: '--help' }])
    assert.equal(routeEvent({ eventName: 'workflow_dispatch', event: { inputs }, cwd }).full, true);
  for (const eventName of ['push', 'pull_request', 'merge_group'])
    assert.equal(routeEvent({ eventName, event, cwd }).full, true);
});

test('actual Git renames and deletions retain every affected old and new input', t => {
  const { cwd, git, commit } = repository(t);
  const base = commit('src/runtime.ts', 'unchanged bytes');
  mkdirSync(path.join(cwd, 'docs'));
  git('mv', 'src/runtime.ts', 'docs/moved.md'); git('commit', '-m', 'owned rename');
  const renamed = git('rev-parse', 'HEAD');
  const route = (before, after) => routeEvent({ eventName: 'push', ref: 'refs/heads/codex/rename',
    event: { before, after }, cwd });
  assert.equal(route(base, renamed).full, true, 'the deleted runtime path must not disappear behind a docs rename');
  git('rm', 'docs/moved.md'); git('commit', '-m', 'owned deletion');
  assert.equal(route(renamed, git('rev-parse', 'HEAD')).reason, 'documentation-only');
  assert.equal(route(renamed, renamed).full, true, 'an empty range is conservative');
});

test('CLI writes only fixed boolean outputs and labels limited coverage honestly', t => {
  const { cwd, commit } = repository(t);
  const before = commit('README.md', 'base');
  const after = commit('README.md', 'updated');
  const eventPath = path.join(cwd, 'event.json'), output = path.join(cwd, 'output'), summary = path.join(cwd, 'summary');
  writeFileSync(eventPath, JSON.stringify({ before, after }));
  const stdout = execFileSync(process.execPath, [path.join(root, 'scripts/ci/route.mjs')], {
    cwd, encoding: 'utf8', env: { ...process.env, GITHUB_EVENT_NAME: 'push',
      GITHUB_REF: 'refs/heads/codex/test', GITHUB_EVENT_PATH: eventPath,
      GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary },
  });
  assert.equal(JSON.parse(stdout).reason, 'documentation-only');
  assert.equal(readFileSync(output, 'utf8'), groups.map(group => `${group}=false\n`).join('') + 'full=false\n');
  assert.match(readFileSync(summary, 'utf8'), /does not establish complete qualification/u);
  writeFileSync(eventPath, 'not JSON');
  const fallback = execFileSync(process.execPath, [path.join(root, 'scripts/ci/route.mjs')], {
    cwd, encoding: 'utf8', env: { ...process.env, GITHUB_EVENT_PATH: eventPath,
      GITHUB_OUTPUT: '', GITHUB_STEP_SUMMARY: '' },
  });
  assert.deepEqual(JSON.parse(fallback).groups, all);
});

const workflowHashes = {
  foundation: ['kernel-foundation.yml', '85cdc704ce6b2e38d685ac54d0cf42d82fc63e8c1607756d609fb3dbff8108f2'],
  permission: ['kernel-permission.yml', 'ade44fa27919c6d692b6a1c910933975c061cba8745a74d80df269fa6187952b'],
};
function verifyWorkflow(workflow, kind) {
  const original = projectQualificationWorkflow(workflow, kind);
  assert.equal(createHash('sha256').update(original).digest('hex'), workflowHashes[kind][1],
    'every original runner, timeout, command, security check and artifact remains byte-identical');
}

test('both workflows retain every original job byte behind the exact conservative router', () => {
  for (const [kind, [filename]] of Object.entries(workflowHashes)) {
    verifyWorkflow(readFileSync(path.join(root, '.github/workflows', filename), 'utf8'), kind);
  }
});

test('routing projection rejects missing, duplicate, weakened or unexpected wiring', () => {
  for (const [kind, [filename]] of Object.entries(workflowHashes)) {
    const workflow = readFileSync(path.join(root, '.github/workflows', filename), 'utf8');
    const router = workflow.match(/  ci-route:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n)/u)?.[0];
    assert(router);
    const triggers = '  workflow_dispatch:\n' + (kind === 'foundation' ? providerInputs : '') + '  merge_group:\n    types: [checks_requested]\n';
    const mutations = [
      workflow.replace(router + '\n', '').replace('permissions:\n', 'permissions:\n' + router + '\n'),
      workflow.replace(triggers, '').replace('permissions:\n', 'permissions:\n' + triggers),
      workflow.replace('    needs: ci-route\n', ''),
      workflow.replace('    needs: ci-route\n', '    needs: [ci-route, typescript]\n'),
      workflow.replace("needs.ci-route.result != 'success' || ", ''),
      workflow.replace(" != 'false') }}", " == 'true') }}"),
      workflow.replace('!cancelled() && ', ''),
      workflow.replace('          persist-credentials: false\n', '          persist-credentials: true\n'),
      workflow.replace('          fetch-depth: 0\n', '          fetch-depth: 1\n'),
      workflow.replace('        run: node scripts/ci/route.mjs\n', '        run: echo success\n'),
      workflow.replace('  workflow_dispatch:\n', ''),
      workflow.replace('  workflow_dispatch:\n', '  workflow_dispatch:\n  workflow_dispatch:\n'),
      workflow.replace('    types: [checks_requested]\n', '    types: [other]\n'),
      workflow.replace('  ci-route:\n', '  renamed-router:\n'),
      workflow.replace('  ci-route:\n', '  ci-route:\n  ci-route:\n'),
      workflow.replace('    timeout-minutes: 20\n', '    timeout-minutes: 21\n'),
    ];
    for (const mutated of mutations) {
      assert.notEqual(mutated, workflow, 'each mutation must exercise actual wiring');
      assert.throws(() => verifyWorkflow(mutated, kind), { name: 'AssertionError' });
    }
  }
});
