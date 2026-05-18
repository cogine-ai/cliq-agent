import assert from 'node:assert/strict';
import test from 'node:test';

import {
  formatPermissionRule,
  parsePermissionRuleString,
  parsePermissionRuleStrings,
  PermissionGrammarError
} from './permissions-grammar.js';

test('parsePermissionRuleString parses the canonical "<channel>: <pattern>" form', () => {
  assert.deepEqual(parsePermissionRuleString('bash: git *', 'workspace', 'permissions.allow[0]'), {
    channel: 'bash',
    pattern: 'git *',
    source: 'workspace'
  });
  assert.deepEqual(parsePermissionRuleString('fs-write: .env', 'cli', '--deny'), {
    channel: 'fs-write',
    pattern: '.env',
    source: 'cli'
  });
});

test('parsePermissionRuleString tolerates surrounding whitespace and stray spaces around the colon', () => {
  assert.deepEqual(
    parsePermissionRuleString('  bash :   git *  ', 'cli', '--allow'),
    { channel: 'bash', pattern: 'git *', source: 'cli' }
  );
});

test('parsePermissionRuleString keeps colons inside the pattern intact', () => {
  // Patterns may contain colons (e.g. URL prefixes, sentinel strings). Only
  // the FIRST colon separates channel from pattern.
  assert.deepEqual(
    parsePermissionRuleString('network: api.example.com:8080', 'cli', '--allow'),
    { channel: 'network', pattern: 'api.example.com:8080', source: 'cli' }
  );
});

test('parsePermissionRuleString rejects non-string input', () => {
  assert.throws(
    () => parsePermissionRuleString(42 as unknown, 'workspace', 'permissions.allow[0]'),
    PermissionGrammarError
  );
});

test('parsePermissionRuleString rejects empty strings, missing colons, empty channels/patterns', () => {
  assert.throws(
    () => parsePermissionRuleString('', 'cli', '--allow'),
    /must be a non-empty string/
  );
  assert.throws(
    () => parsePermissionRuleString('bash git *', 'cli', '--allow'),
    /missing a colon/
  );
  assert.throws(
    () => parsePermissionRuleString(': git *', 'cli', '--allow'),
    /empty channel/
  );
  assert.throws(
    () => parsePermissionRuleString('bash:   ', 'cli', '--allow'),
    /empty pattern/
  );
});

test('parsePermissionRuleString rejects unknown channels with the valid set in the message', () => {
  try {
    parsePermissionRuleString('files: docs/*', 'cli', '--allow');
    assert.fail('expected throw');
  } catch (err) {
    assert.ok(err instanceof PermissionGrammarError);
    assert.match(err.message, /unknown channel "files"/);
    assert.match(err.message, /fs-read.*fs-write.*bash.*mcp.*network/);
  }
});

test('parsePermissionRuleStrings returns [] for undefined and parses arrays in order', () => {
  assert.deepEqual(parsePermissionRuleStrings(undefined, 'cli', '--allow'), []);
  const parsed = parsePermissionRuleStrings(['bash: git *', 'fs-read: docs/*'], 'workspace', 'permissions.allow');
  assert.deepEqual(parsed, [
    { channel: 'bash', pattern: 'git *', source: 'workspace' },
    { channel: 'fs-read', pattern: 'docs/*', source: 'workspace' }
  ]);
});

test('parsePermissionRuleStrings reports the offending index in the error context', () => {
  try {
    parsePermissionRuleStrings(['bash: git *', 'invalid-no-colon'], 'workspace', 'permissions.allow');
    assert.fail('expected throw');
  } catch (err) {
    assert.ok(err instanceof PermissionGrammarError);
    assert.match(err.message, /permissions\.allow\[1\]/);
  }
});

test('parsePermissionRuleStrings rejects non-array input', () => {
  assert.throws(
    () => parsePermissionRuleStrings({ allow: [] } as unknown, 'workspace', 'permissions.allow'),
    /must be an array/
  );
});

test('formatPermissionRule round-trips back into parsePermissionRuleString', () => {
  const input = { channel: 'bash' as const, pattern: 'npm run *', source: 'workspace' as const };
  const formatted = formatPermissionRule(input);
  assert.equal(formatted, 'bash: npm run *');
  assert.deepEqual(parsePermissionRuleString(formatted, 'workspace', 'rt'), input);
});
