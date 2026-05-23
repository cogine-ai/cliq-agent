import assert from 'node:assert/strict';
import test from 'node:test';

import {
  bashCommandHasUnsafeAllowSyntax,
  extractShellInlineScript,
  parseBashCommandHead
} from './bash-parse.js';

test('parseBashCommandHead returns the plain command for a simple invocation', () => {
  assert.equal(parseBashCommandHead('npm test'), 'npm');
  assert.equal(parseBashCommandHead('ls'), 'ls');
  assert.equal(parseBashCommandHead('git pull --rebase'), 'git');
});

test('parseBashCommandHead skips leading KEY=VALUE env assignments', () => {
  assert.equal(parseBashCommandHead('VAR=1 npm test'), 'npm');
  assert.equal(parseBashCommandHead('FOO=bar BAZ=1 git pull'), 'git');
  assert.equal(parseBashCommandHead('NODE_ENV=production npm run build'), 'npm');
});

test('parseBashCommandHead unwraps sudo and env style wrappers', () => {
  assert.equal(parseBashCommandHead('sudo ls /tmp'), 'ls');
  assert.equal(parseBashCommandHead('sudo -u me ls'), 'ls');
  assert.equal(parseBashCommandHead('env ls'), 'ls');
  assert.equal(parseBashCommandHead('/usr/bin/env -S node script.js'), 'node');
  assert.equal(parseBashCommandHead('doas pacman -Syu'), 'pacman');
});

test('parseBashCommandHead skips nice argument-taking flags in all spellings', () => {
  // Regression for PR #71 CodeRabbit finding: `nice -n 10 npm test` used to
  // return "10" because skipWrapperFlags didn't consume the priority arg.
  assert.equal(parseBashCommandHead('nice npm test'), 'npm');
  assert.equal(parseBashCommandHead('nice -n 10 npm test'), 'npm');
  assert.equal(parseBashCommandHead('nice -n10 npm test'), 'npm');
  assert.equal(parseBashCommandHead('nice --adjustment 10 npm test'), 'npm');
  assert.equal(parseBashCommandHead('nice --adjustment=10 npm test'), 'npm');
  assert.equal(parseBashCommandHead('nice --priority=5 git push'), 'git');
});

test('parseBashCommandHead handles sudo long-form --user= attached value', () => {
  // Parallel coverage so the attached-value branch in skipWrapperFlags isn't
  // exercised only by nice.
  assert.equal(parseBashCommandHead('sudo --user=deploy ls'), 'ls');
});

test('parseBashCommandHead returns the basename for absolute paths', () => {
  assert.equal(parseBashCommandHead('/usr/local/bin/python -m pip'), 'python');
  assert.equal(parseBashCommandHead('  /usr/bin/git status'), 'git');
});

test('parseBashCommandHead returns null when no identifiable head exists', () => {
  assert.equal(parseBashCommandHead(''), null);
  assert.equal(parseBashCommandHead('   '), null);
  // Leading operator: refuse to guess so the allowlist matcher falls through
  // to ask/preset instead of accidentally approving the next token.
  assert.equal(parseBashCommandHead('&& ls'), null);
  assert.equal(parseBashCommandHead('| cat'), null);
  // Unterminated quote: tokenizer bails out.
  assert.equal(parseBashCommandHead('npm "test'), null);
});

test('parseBashCommandHead stops at shell pipelines and separators', () => {
  // Only the head of the FIRST command is returned; the rest of the pipeline
  // is intentionally invisible to allowlist matching.
  assert.equal(parseBashCommandHead('npm test && rm -rf /'), 'npm');
  assert.equal(parseBashCommandHead('git status; echo hi'), 'git');
  assert.equal(parseBashCommandHead('ls | head -n 1'), 'ls');
});

test('parseBashCommandHead refuses redirection-leading lines (regression pin for > / <)', () => {
  // CodeRabbit findings on PR #71 (one stale, one new) called out the `>` /
  // `<` cases. The regex already covers them; pin the behavior with explicit
  // tests so a future trim of the character class can't silently regress
  // "no identifiable head" for redirection-prefixed lines.
  assert.equal(parseBashCommandHead('> out.txt ls'), null);
  assert.equal(parseBashCommandHead('>> log.txt echo hi'), null);
  assert.equal(parseBashCommandHead('< in.txt cat'), null);
});

test('parseBashCommandHead handles quoted argv[0]', () => {
  assert.equal(parseBashCommandHead('"git" status'), 'git');
  assert.equal(parseBashCommandHead("'npm' test"), 'npm');
});

test('parseBashCommandHead survives mixed env + wrapper + quoted command', () => {
  assert.equal(parseBashCommandHead('NODE_ENV=production sudo -u deploy "npm" run start'), 'npm');
});

test('bashCommandHasUnsafeAllowSyntax detects executable syntax after the command head', () => {
  for (const command of [
    'git status && rm -rf /',
    'git status; rm -rf /',
    'git status | sh',
    'git status\nrm -rf /',
    'git status $(rm -rf /)',
    'git status `rm -rf /`',
    'git status <(rm -rf /)',
    'git status >(rm -rf /)',
    '"git" status && rm -rf /',
    'git "$(rm -rf /)"'
  ]) {
    assert.equal(bashCommandHasUnsafeAllowSyntax(command), true, command);
  }
});

test('bashCommandHasUnsafeAllowSyntax allows literal or escaped shell syntax', () => {
  for (const command of [
    '',
    'git status',
    "git '$(rm -rf /)'",
    'git "status && rm"',
    'git status 2>&1',
    'git status \\; echo',
    'git \\$(rm -rf /)',
    'git \\`rm -rf /\\`'
  ]) {
    assert.equal(bashCommandHasUnsafeAllowSyntax(command), false, command);
  }
});

test('extractShellInlineScript returns the -c script for shell interpreters', () => {
  assert.equal(extractShellInlineScript("bash -c 'git status'"), 'git status');
  assert.equal(extractShellInlineScript("bash -lc 'git status'"), 'git status');
  assert.equal(extractShellInlineScript("bash -euc 'git status'"), 'git status');
  assert.equal(extractShellInlineScript("bash -o pipefail -c 'git status'"), 'git status');
  assert.equal(extractShellInlineScript("bash --noprofile --norc -c 'git status'"), 'git status');
  assert.equal(extractShellInlineScript("busybox sh -c 'git status'"), 'git status');
  assert.equal(extractShellInlineScript('sh -c "npm test"'), 'npm test');
  assert.equal(extractShellInlineScript('sudo bash -c "git pull"'), 'git pull');
  assert.equal(extractShellInlineScript('npm test'), null);
});

test('bashCommandHasUnsafeAllowSyntax inspects compound syntax inside shell -c scripts', () => {
  for (const command of [
    "bash -c 'git status && rm -rf /'",
    "bash -lc 'git status && rm -rf /'",
    "bash -o pipefail -c 'git status && rm -rf /'",
    "bash --noprofile --norc -c 'git status && rm -rf /'",
    "bash -c 'bash -c \"git status && rm -rf /\"'",
    'bash -c "git status; rm -rf /"',
    'sh -c "git status | sh"',
    'sudo bash -c "git status $(rm -rf /)"',
    '/usr/bin/env bash -c "git status && rm -rf /"'
  ]) {
    assert.equal(bashCommandHasUnsafeAllowSyntax(command), true, command);
  }
  assert.equal(bashCommandHasUnsafeAllowSyntax("bash -c 'git status'"), false);
});
