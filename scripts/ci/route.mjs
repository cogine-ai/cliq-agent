import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const groups = Object.freeze([
  'typescript', 'native', 'credentials', 'run', 'verifier', 'delivery', 'upgrade', 'permission',
]);

// Only independently owned qualification inputs are narrowed. Runtime, native,
// dependency, shared harness and unknown changes retain the complete job set.
const ownedInputs = new Map([
  ['scripts/kernel/qualify-installed-verifier-journey.ts', ['verifier']],
  ['scripts/kernel/qualify-installed-delivery-journey.ts', ['delivery']],
  ['scripts/kernel/qualify-installed-permission-journey.ts', ['permission']],
  ['scripts/kernel/testing/installed-permission-result.test.ts', ['permission']],
  ['scripts/kernel/testing/installed-delivery-journey.test.mjs', ['delivery']],
  ['scripts/kernel/testing/installed-delivery-refusal.test.mjs', ['delivery']],
  ['scripts/kernel/testing/installed-publication-work.test.ts', ['delivery']],
  ['scripts/kernel/testing/installed-publication-stop-wiring.test.mjs', ['delivery']],
  ['scripts/kernel/testing/installed-publication-late-entry.test.mjs', ['delivery']],
  ['scripts/kernel/testing/installed-publication-late-wiring.test.mjs', ['delivery']],
  ['scripts/kernel/testing/installed-verifier-result.test.ts', ['verifier', 'permission']],
  ['scripts/kernel/testing/installed-verifier-evidence.test.ts', ['verifier', 'permission']],
  ['scripts/kernel/testing/installed-verifier-parent-evidence.test.ts', ['verifier']],
  ['scripts/kernel/testing/installed-upgrade-result.test.ts', ['upgrade']],
]);

function selection(selected, reason, changedFiles) {
  return Object.freeze({
    full: selected.size === groups.length,
    reason,
    changedFiles,
    groups: Object.freeze(Object.fromEntries(groups.map(group => [group, selected.has(group)]))),
  });
}

function full(reason) { return selection(new Set(groups), reason, null); }

export function routePaths(paths) {
  if (!Array.isArray(paths) || paths.length === 0 || paths.length > 20000) return full('unavailable-diff');
  const selected = new Set();
  for (const filename of paths) {
    if (typeof filename !== 'string' || !filename || filename.startsWith('/') ||
        /[\0\r\n\\]/u.test(filename) || filename.split('/').some(part => !part || part === '.' || part === '..')) {
      return full('unrecognized-path');
    }
    if (filename.startsWith('docs/rfcs/') || filename.startsWith('docs/backlog/durable-verified-run-kernel/')) {
      selected.add('typescript');
      continue;
    }
    if (filename.startsWith('docs/') || ['README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'LICENSE'].includes(filename)) continue;
    if (filename.startsWith('src/') && /\.test\.(?:ts|tsx)$/u.test(filename)) {
      selected.add('typescript');
      continue;
    }
    const owners = ownedInputs.get(filename);
    if (!owners) return full('shared-or-unrecognized-input');
    selected.add('typescript');
    for (const owner of owners) selected.add(owner);
  }
  return selection(selected, selected.size ? 'affected-groups' : 'documentation-only', paths.length);
}

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'] });
}

// No API pagination or path-filter limit: inspect the real immutable Git range.
// Disabling rename detection includes BOTH old and new paths as delete/add.
export function routeEvent({ eventName, ref, event, cwd }) {
  if (eventName === 'workflow_dispatch' || eventName === 'merge_group' ||
      eventName === 'push' && ref === 'refs/heads/main') return full('full-qualification');
  const sha = value => typeof value === 'string' && /^[a-f0-9]{40}$/u.test(value) && !/^0{40}$/u.test(value);
  let base, head;
  if (eventName === 'pull_request') {
    base = event?.pull_request?.base?.sha;
    head = event?.pull_request?.head?.sha;
  } else if (eventName === 'push' && typeof ref === 'string' && ref.startsWith('refs/heads/')) {
    base = event?.before;
    head = event?.after;
  } else return full('unsupported-event');
  if (!sha(base) || !sha(head)) return full('unavailable-history');
  try {
    if (eventName === 'pull_request') {
      base = git(cwd, ['merge-base', base, head]).trim();
      if (!sha(base)) return full('unavailable-history');
    }
    const output = git(cwd, ['diff', '--name-only', '--no-renames', '-z', base, head, '--']);
    if (!output.endsWith('\0')) return full('unavailable-diff');
    return routePaths(output.slice(0, -1).split('\0'));
  } catch { return full('unavailable-history'); }
}

function main() {
  let route;
  try {
    const bytes = readFileSync(process.env.GITHUB_EVENT_PATH);
    if (bytes.length > 8 * 1024 * 1024) throw new Error('event size');
    route = routeEvent({ eventName: process.env.GITHUB_EVENT_NAME, ref: process.env.GITHUB_REF,
      event: JSON.parse(bytes.toString('utf8')), cwd: process.cwd() });
  } catch { route = full('unavailable-event'); }
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT,
    groups.map(group => `${group}=${route.groups[group]}\n`).join('') + `full=${route.full}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY,
    `### CI scope\n\n${route.full ? 'Complete job set selected.' : 'Affected groups only; this run does not establish complete qualification.'}\n\n` +
    `Reason: ${route.reason}. Changed paths: ${route.changedFiles ?? 'not required or unavailable'}.\n\n` +
    groups.map(group => `- ${group}: ${route.groups[group] ? 'run' : 'not selected'}\n`).join(''));
  process.stdout.write(JSON.stringify(route) + '\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
