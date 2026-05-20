import assert from 'node:assert/strict';
import test from 'node:test';

import { bashCommandHasCompoundSyntax, parseBashCommandHead } from './bash-parse.js';

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

test('bashCommandHasCompoundSyntax detects chained commands outside quotes', () => {
  assert.equal(bashCommandHasCompoundSyntax('npm test'), false);
  assert.equal(bashCommandHasCompoundSyntax('git status && rm -rf /'), true);
  assert.equal(bashCommandHasCompoundSyntax('git status; echo hi'), true);
  assert.equal(bashCommandHasCompoundSyntax('ls | head'), true);
  assert.equal(bashCommandHasCompoundSyntax('npm test & sleep 1'), true);
  assert.equal(bashCommandHasCompoundSyntax('"git" status && rm'), true);
  assert.equal(bashCommandHasCompoundSyntax('git "status && rm"'), false);
  assert.equal(bashCommandHasCompoundSyntax(''), false);
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
