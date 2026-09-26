import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { FrozenIgnoreRulesV1 } from '../kernel/types.js';
import { compileFrozenIgnoreMatcher, matchGitWildmatchV1 } from './frozen-ignore-matcher.js';
import { parseFrozenIgnoreSourceBytes } from './frozen-ignore-sources.js';

const REF = 'a'.repeat(64);

test('fixed byte wildmatch handles directory globstars and component boundaries', () => {
  const examples: Array<[string, string, boolean, boolean]> = [
    ['foo/**/bar', 'foo/bar', true, true],
    ['foo/**/bar', 'foo/x/bar', true, true],
    ['foo/**/bar', 'foo/x/y/bar', true, true],
    ['foo/*/bar', 'foo/bar', true, false],
    ['foo/*/bar', 'foo/x/bar', true, true],
    ['foo/*/bar', 'foo/x/y/bar', true, false],
    ['**/foo', 'foo', true, true],
    ['**/foo', 'x/y/foo', true, true],
    ['abc/**', 'abc/x/y', true, true],
    ['abc/**', 'abc', true, false],
    ['**/', 'c', true, false],
    ['foo*bar', 'foo/baz/bar', true, false],
    ['foo*bar', 'foo/baz/bar', false, true],
    ['foo\\*', 'foo*', true, true],
    ['foo\\*', 'foobar', true, false]
  ];
  for (const [pattern, candidate, pathname, expected] of examples) {
    assert.equal(matchGitWildmatchV1(pattern, candidate, pathname), expected,
      `${JSON.stringify(pattern)} against ${JSON.stringify(candidate)}`);
  }
});

test('fixed byte wildmatch handles classes, escapes and UTF-8 byte counts', () => {
  const examples: Array<[string, string, boolean]> = [
    ['t[a-g]n', 'ten', true],
    ['t[!a-g]n', 'ten', false],
    ['t[^a-g]n', 'ton', true],
    ['a[]-]b', 'a]b', true],
    ['a[]-]b', 'a-b', true],
    ['a[[:digit:]]', 'a5', true],
    ['a[[:alpha:]]', 'a5', false],
    ['a[[:xdigit:]]', 'aF', true],
    ['a[[:space:]]', 'a\t', true],
    ['[[:]ab]', '[ab]', true],
    ['[[::]ab]', '[ab]', false],
    ['a[[:unknown:]]', 'ax', false],
    ['foo[/]bar', 'foo/bar', false],
    ['[abc', 'a', false],
    ['?', 'é', false],
    ['??', 'é', true]
  ];
  for (const [pattern, candidate, expected] of examples) {
    assert.equal(matchGitWildmatchV1(pattern, candidate, true), expected,
      `${JSON.stringify(pattern)} against ${JSON.stringify(candidate)}`);
  }
});

test('fixed byte wildmatch does not exponentially backtrack on repeated stars', () => {
  assert.equal(matchGitWildmatchV1('a*'.repeat(80) + 'b', 'a'.repeat(80), true), false);
});

test('frozen matcher applies ancestor bases, last matching rule and ignored parents', () => {
  const sources: FrozenIgnoreRulesV1['sources'] = [
    { index: 0, kind: 'gitignore', canonicalRootRelativePath: '.gitignore',
      baseDirectory: '', contentRef: REF, contentDigest: REF },
    { index: 1, kind: 'gitignore', canonicalRootRelativePath: 'src/.gitignore',
      baseDirectory: 'src', contentRef: REF, contentDigest: REF }
  ];
  const rootRules = parseFrozenIgnoreSourceBytes(
    Buffer.from('cache/\n!cache/keep.txt\n*.log\n'), sources[0]!
  );
  const nestedRules = parseFrozenIgnoreSourceBytes(
    Buffer.from('!keep.log\n'), sources[1]!, rootRules.length
  );
  const manifest: FrozenIgnoreRulesV1 = {
    schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1',
    matcherVersion: 'cliq-git-wildmatch-v1', repositoryIdentityDigest: REF,
    sources, rules: [...rootRules, ...nestedRules], rulesDigest: REF
  };
  const ignored = compileFrozenIgnoreMatcher(manifest);
  assert.equal(ignored('cache', true), true);
  assert.equal(ignored('cache/keep.txt', false), true);
  assert.equal(ignored('src/keep.log', false), false);
  assert.equal(ignored('other/keep.log', false), true);
  assert.equal(ignored('src/deep/keep.log', false), false);
  assert.equal(ignored('src/deep/other.log', false), true);
  assert.equal(ignored('ordinary.txt', false), false);
  assert.throws(() => ignored('../escape', false), /canonical root-relative/);
  assert.throws(() => ignored('e\u0301', false), /canonical root-relative/);
});
