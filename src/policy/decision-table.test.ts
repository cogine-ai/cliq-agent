import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BUILTIN_DENY,
  composePermissionTable,
  EMPTY_PERMISSION_TABLE,
  matchAgainstTable,
  type PermissionRule,
  type PermissionTable
} from './decision-table.js';

const tableWith = (overrides: Partial<PermissionTable>): PermissionTable => ({
  deny: [...(overrides.deny ?? [])],
  allow: [...(overrides.allow ?? [])],
  ask: [...(overrides.ask ?? [])]
});

const wsRule = (channel: PermissionRule['channel'], pattern: string): PermissionRule => ({
  channel,
  pattern,
  source: 'workspace'
});

test('EMPTY_PERMISSION_TABLE and BUILTIN_DENY are deeply frozen (no shared-singleton mutation)', () => {
  // Regression for PR #71 CodeRabbit finding: the default table singleton is
  // reused as PolicyEngine's default `table`. A shallow freeze would let a
  // stray `EMPTY_PERMISSION_TABLE.deny.push(...)` poison every later
  // PolicyEngine call. assert it via mutation attempts under strict mode
  // (Node test runner uses ES modules → strict by default).
  assert.throws(() => {
    (EMPTY_PERMISSION_TABLE.deny as PermissionRule[]).push({
      channel: 'bash',
      pattern: '*',
      source: 'workspace'
    });
  }, /read[- ]?only|frozen|extensible|object is not extensible/i);

  assert.throws(() => {
    (BUILTIN_DENY as PermissionRule[]).push({
      channel: 'bash',
      pattern: 'sh',
      source: 'workspace'
    });
  }, /read[- ]?only|frozen|extensible|object is not extensible/i);

  // Individual builtin rules are also frozen, so a stray rewrite (e.g.
  // changing source to bypass the "builtin never overridable" invariant)
  // is rejected too.
  const firstBuiltin = BUILTIN_DENY[0]!;
  assert.throws(() => {
    (firstBuiltin as PermissionRule).source = 'workspace';
  }, /read[- ]?only|cannot assign|object is not extensible/i);
});

test('EMPTY_PERMISSION_TABLE has no rules and falls through for every channel', () => {
  const channels = [
    { kind: 'fs-read', path: 'README.md' },
    { kind: 'fs-write', path: 'src/foo.ts', op: 'modify' },
    { kind: 'bash', commandHead: 'npm' }
  ] as const;
  for (const channel of channels) {
    assert.deepEqual(matchAgainstTable(EMPTY_PERMISSION_TABLE, channel), { kind: 'fallthrough' });
  }
});

test('composePermissionTable always seeds builtin deny on top', () => {
  const composed = composePermissionTable();
  assert.deepEqual(composed.deny, [...BUILTIN_DENY]);
  assert.deepEqual(composed.allow, []);
  assert.deepEqual(composed.ask, []);
});

test('composePermissionTable stacks layers without removing earlier deny rules', () => {
  const composed = composePermissionTable(
    { allow: [wsRule('bash', 'git *')] },
    { deny: [wsRule('fs-write', 'src/index.ts')] }
  );
  assert.equal(composed.allow.length, 1);
  assert.equal(composed.allow[0]!.pattern, 'git *');
  assert.equal(composed.deny.length, BUILTIN_DENY.length + 1);
});

test('matchAgainstTable: deny wins over allow even at the same channel', () => {
  const table = tableWith({
    deny: [wsRule('bash', 'git *')],
    allow: [wsRule('bash', 'git *')]
  });
  const decision = matchAgainstTable(table, { kind: 'bash', commandHead: 'git' });
  assert.equal(decision.kind, 'deny');
  if (decision.kind === 'deny') {
    assert.equal(decision.rule.pattern, 'git *');
  }
});

test('matchAgainstTable: BUILTIN deny rules are never overridable by a later allow', () => {
  // Compose puts BUILTIN_DENY first; even a perfect allow match for
  // "bash: rm" must not flip the decision.
  const table = composePermissionTable({ allow: [wsRule('bash', 'rm')] });
  const decision = matchAgainstTable(table, { kind: 'bash', commandHead: 'rm' });
  assert.equal(decision.kind, 'deny');
  if (decision.kind === 'deny') {
    assert.equal(decision.rule.source, 'builtin');
  }
});

test('matchAgainstTable: allow precedes ask when both match', () => {
  const table = tableWith({
    allow: [wsRule('bash', 'npm *')],
    ask: [wsRule('bash', 'npm *')]
  });
  const decision = matchAgainstTable(table, { kind: 'bash', commandHead: 'npm' });
  assert.equal(decision.kind, 'allow');
});

test('matchAgainstTable: wildcard, exact, prefix " *", and trailing "/*" patterns', () => {
  const table = tableWith({
    allow: [
      wsRule('bash', '*'),
      wsRule('fs-read', 'docs/*'),
      wsRule('fs-write', 'src/exact.ts'),
      wsRule('bash', 'npm *')
    ]
  });

  assert.equal(matchAgainstTable(table, { kind: 'bash', commandHead: 'arbitrary' }).kind, 'allow');
  assert.equal(matchAgainstTable(table, { kind: 'bash', commandHead: 'npm' }).kind, 'allow');
  assert.equal(
    matchAgainstTable(table, { kind: 'fs-read', path: 'docs/README.md' }).kind,
    'allow'
  );
  assert.equal(
    matchAgainstTable(table, { kind: 'fs-write', path: 'src/exact.ts', op: 'modify' }).kind,
    'allow'
  );
  assert.equal(
    matchAgainstTable(table, { kind: 'fs-write', path: 'src/other.ts', op: 'modify' }).kind,
    'fallthrough'
  );
});

test('matchAgainstTable: compound bash never matches allow (chains hidden commands)', () => {
  const table = tableWith({
    allow: [wsRule('bash', 'npm *'), wsRule('bash', 'git *')]
  });
  const decision = matchAgainstTable(table, { kind: 'bash', commandHead: 'npm', compound: true });
  assert.equal(decision.kind, 'ask');
});

test('matchAgainstTable: bash with empty commandHead never matches allow/ask', () => {
  const table = tableWith({
    allow: [wsRule('bash', '*'), wsRule('bash', '')]
  });
  const decision = matchAgainstTable(table, { kind: 'bash', commandHead: '' });
  // Even a literal "" pattern or wildcard "*" must not approve an
  // unidentified bash invocation; the matcher falls through so the preset
  // can ask the user.
  assert.equal(decision.kind, 'fallthrough');
});

test('matchAgainstTable: empty-commandHead bash still hits deny rules (no escape hatch)', () => {
  const table = composePermissionTable({ deny: [wsRule('bash', '*')] });
  const decision = matchAgainstTable(table, { kind: 'bash', commandHead: '' });
  // Deny precedence runs before the empty-head shortcut, so a sweeping
  // "deny: bash *" still applies.
  assert.equal(decision.kind, 'deny');
});

test('matchAgainstTable: channel kind mismatch is never a match', () => {
  const table = tableWith({
    allow: [wsRule('fs-read', 'README.md')]
  });
  const decision = matchAgainstTable(table, { kind: 'bash', commandHead: 'README.md' });
  assert.equal(decision.kind, 'fallthrough');
});

test('matchAgainstTable: mcp + network channels (type-only today)', () => {
  const table = tableWith({
    allow: [
      wsRule('mcp', 'context7/*'),
      wsRule('network', 'api.example.com')
    ]
  });
  assert.equal(
    matchAgainstTable(table, { kind: 'mcp', server: 'context7', tool: 'search' }).kind,
    'allow'
  );
  assert.equal(
    matchAgainstTable(table, { kind: 'network', host: 'api.example.com' }).kind,
    'allow'
  );
  assert.equal(
    matchAgainstTable(table, { kind: 'network', host: 'other.example.com' }).kind,
    'fallthrough'
  );
});
