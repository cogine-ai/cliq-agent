import type { AccessChannel, AccessChannelKind } from './types.js';

/**
 * Source of a permission rule, used purely for diagnostics ("decidedBy: rule
 * from workspace allow-list") and for the "builtin deny is never overridable"
 * invariant in matchAgainstTable. Ordered roughly by trust: BUILTIN deny
 * always wins; everything else only competes within the same kind (allow vs
 * deny vs ask).
 */
export type PermissionRuleSource = 'builtin' | 'cli' | 'workspace' | 'persisted' | 'session' | 'hook';

export type PermissionRule = {
  channel: AccessChannelKind;
  /**
   * Match pattern. v0 grammar (#62-A):
   *   - "*"                  — wildcard
   *   - literal string       — exact match on the channel's primary key
   *                            (commandHead for bash, path for fs-*, etc.)
   *   - prefix + " *"        — e.g. "npm *", "git *", "docs/*"
   *   - "**\/**" (glob)      — Not yet supported; treated as literal.
   *
   * TODO(no-issue: shell-allowlist-richer-matching): real glob + argv-aware
   * matching land alongside the user-visible allowlist surface in #62-B.
   */
  pattern: string;
  source: PermissionRuleSource;
};

export type PermissionTable = {
  deny: PermissionRule[];
  allow: PermissionRule[];
  ask: PermissionRule[];
};

export const EMPTY_PERMISSION_TABLE: PermissionTable = Object.freeze({
  deny: [],
  allow: [],
  ask: []
}) as PermissionTable;

/**
 * Built-in deny shadow list. These rules are loaded as `source: 'builtin'`
 * and the matcher refuses to let any later allow rule override them. Keep
 * this list tight; err on the side of "ask" (in the preset) rather than
 * "deny" so legitimate flows are never silently broken.
 *
 * TODO(no-issue: builtin-deny-shadow-curation): curate with telemetry from
 * #62-B once the user-visible allowlist surface lands. v0 only covers the
 * obviously-dangerous lines.
 */
export const BUILTIN_DENY: readonly PermissionRule[] = Object.freeze([
  // Recursive removals that target the filesystem root or the user's home.
  rule('bash', 'rm', 'builtin'),
  // .git is application state, not user content. Direct writes corrupt the
  // repo and bypass tx review entirely.
  rule('fs-write', '.git/*', 'builtin'),
  rule('fs-write', '.git', 'builtin')
]);

function rule(
  channel: AccessChannelKind,
  pattern: string,
  source: PermissionRuleSource
): PermissionRule {
  return { channel, pattern, source };
}

/**
 * Compose a final {@link PermissionTable} from layered inputs. Later layers
 * are not allowed to remove earlier deny rules — they can only stack more
 * deny on top, or add allow/ask. This keeps the "deny is sticky" guarantee
 * across config/CLI/session layers and matches the precedence documented in
 * AGENTS.md (Layer 2 boundary: trust ≠ permission).
 */
export function composePermissionTable(...layers: Partial<PermissionTable>[]): PermissionTable {
  const out: PermissionTable = {
    deny: [...BUILTIN_DENY],
    allow: [],
    ask: []
  };
  for (const layer of layers) {
    if (layer.deny) out.deny.push(...layer.deny);
    if (layer.allow) out.allow.push(...layer.allow);
    if (layer.ask) out.ask.push(...layer.ask);
  }
  return out;
}

export type TableDecision =
  | { kind: 'deny'; rule: PermissionRule }
  | { kind: 'allow'; rule: PermissionRule }
  | { kind: 'ask'; rule: PermissionRule }
  | { kind: 'fallthrough' };

/**
 * Evaluate the table against a fully-resolved {@link AccessChannel}.
 *
 * Precedence: builtin deny → other deny → allow → ask → fallthrough.
 * "Fallthrough" means the caller should fall back to the {@link PolicyMode}
 * preset (the legacy 5-step decision). Builtin deny rules win even against
 * later allow rules — this is the invariant that lets us ship a deny shadow
 * list without users accidentally papering over it with a broad allow.
 *
 * An empty `commandHead` on a bash channel (the explicit "no identifiable
 * head" sentinel from {@link buildToolApprovalSubject}) NEVER matches an
 * allow rule. The matcher treats it as fallthrough so the user sees a
 * confirmation prompt instead of an accidental approval.
 */
export function matchAgainstTable(table: PermissionTable, channel: AccessChannel): TableDecision {
  for (const denyRule of table.deny) {
    if (matchesRule(denyRule, channel)) {
      return { kind: 'deny', rule: denyRule };
    }
  }

  if (isBashWithoutHead(channel)) {
    // Refuse to match this against allow/ask; let preset decide. See above.
    return { kind: 'fallthrough' };
  }

  for (const allowRule of table.allow) {
    if (matchesRule(allowRule, channel)) {
      return { kind: 'allow', rule: allowRule };
    }
  }
  for (const askRule of table.ask) {
    if (matchesRule(askRule, channel)) {
      return { kind: 'ask', rule: askRule };
    }
  }
  return { kind: 'fallthrough' };
}

function isBashWithoutHead(channel: AccessChannel): boolean {
  return channel.kind === 'bash' && channel.commandHead === '';
}

function matchesRule(rule: PermissionRule, channel: AccessChannel): boolean {
  if (rule.channel !== channel.kind) return false;
  return matchPattern(rule.pattern, primaryKey(channel));
}

function primaryKey(channel: AccessChannel): string {
  switch (channel.kind) {
    case 'fs-read':
      return channel.path;
    case 'fs-write':
      return channel.path;
    case 'bash':
      return channel.commandHead;
    case 'mcp':
      return `${channel.server}/${channel.tool}`;
    case 'network':
      return channel.host ?? '';
  }
}

function matchPattern(pattern: string, value: string): boolean {
  if (pattern === '*') return true;
  if (pattern === value) return true;
  if (pattern.endsWith(' *')) {
    // "npm *" should match "npm" and any string starting with "npm "
    // (e.g. matched against the commandHead "npm"). For path channels the
    // same shape (`docs/*`) matches strings that start with the literal
    // prefix.
    const prefix = pattern.slice(0, -2);
    if (value === prefix) return true;
    return value.startsWith(`${prefix} `) || value.startsWith(`${prefix}/`);
  }
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -1); // keep trailing slash
    return value.startsWith(prefix);
  }
  return false;
}
