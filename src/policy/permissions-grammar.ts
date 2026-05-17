import type { PermissionRule, PermissionRuleSource } from './decision-table.js';
import type { AccessChannelKind } from './types.js';

/**
 * Shared "<channel>: <pattern>" grammar for permission rules. Used by:
 *   - workspace config `permissions.{allow,deny,ask}` arrays
 *   - CLI flags `--allow`, `--deny`, `--ask` (repeatable)
 *   - the TUI session-memory allow list (when the user picks "Allow this
 *     session" / "Always in workspace")
 *
 * Grammar (v0):
 *   <rule>    ::= <channel> ":" SP* <pattern>
 *   <channel> ::= "fs-read" | "fs-write" | "bash" | "mcp" | "network"
 *   <pattern> ::= any non-empty string up to end-of-rule
 *
 * Examples:
 *   "bash: git *"             — allow `git push`, `git status`, …
 *   "fs-write: .env"          — deny modifying the exact path `.env`
 *   "fs-read: docs/*"         — allow any path starting with `docs/`
 *   "mcp: context7/search"    — allow the search tool on the context7 server
 *   "network: api.example.com"
 *
 * What the matcher does with the pattern is documented in
 * src/policy/decision-table.ts (`matchPattern`). This module only deals with
 * the *string* representation: parsing config/CLI input into PermissionRule
 * and rejecting clearly malformed input early.
 */

const VALID_CHANNELS: ReadonlySet<AccessChannelKind> = new Set<AccessChannelKind>([
  'fs-read',
  'fs-write',
  'bash',
  'mcp',
  'network'
]);

export class PermissionGrammarError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PermissionGrammarError';
  }
}

/**
 * Parse a single "<channel>: <pattern>" string into a {@link PermissionRule}.
 * Throws {@link PermissionGrammarError} with a human-actionable message for
 * any malformed input; callers compose those into a multi-rule error.
 */
export function parsePermissionRuleString(
  raw: unknown,
  source: PermissionRuleSource,
  context: string
): PermissionRule {
  if (typeof raw !== 'string') {
    throw new PermissionGrammarError(
      `${context} must be a string of the form "<channel>: <pattern>" (got ${typeof raw})`
    );
  }

  const trimmed = raw.trim();
  if (trimmed === '') {
    throw new PermissionGrammarError(`${context} must be a non-empty string`);
  }

  const colonIdx = trimmed.indexOf(':');
  if (colonIdx === -1) {
    throw new PermissionGrammarError(
      `${context}="${raw}" is missing a colon — expected "<channel>: <pattern>"`
    );
  }

  const channelRaw = trimmed.slice(0, colonIdx).trim();
  const pattern = trimmed.slice(colonIdx + 1).trim();

  if (channelRaw === '') {
    throw new PermissionGrammarError(
      `${context}="${raw}" has an empty channel — expected "<channel>: <pattern>"`
    );
  }
  if (pattern === '') {
    throw new PermissionGrammarError(
      `${context}="${raw}" has an empty pattern — expected "<channel>: <pattern>"`
    );
  }
  if (!VALID_CHANNELS.has(channelRaw as AccessChannelKind)) {
    throw new PermissionGrammarError(
      `${context}="${raw}" uses unknown channel "${channelRaw}" — expected one of: ${[...VALID_CHANNELS].join(', ')}`
    );
  }

  return {
    channel: channelRaw as AccessChannelKind,
    pattern,
    source
  };
}

/**
 * Parse an array of rule strings. Throws on the first malformed entry so the
 * error message can pinpoint the offending index without burying the user in
 * a wall of warnings.
 */
export function parsePermissionRuleStrings(
  raw: unknown,
  source: PermissionRuleSource,
  context: string
): PermissionRule[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    throw new PermissionGrammarError(`${context} must be an array of "<channel>: <pattern>" strings`);
  }
  return raw.map((entry, index) =>
    parsePermissionRuleString(entry, source, `${context}[${index}]`)
  );
}

/**
 * Inverse of {@link parsePermissionRuleString} — used by the TUI status line
 * and `/policy list-allow` slash command to display rules back to the user
 * in the same form they wrote them.
 */
export function formatPermissionRule(rule: PermissionRule): string {
  return `${rule.channel}: ${rule.pattern}`;
}
