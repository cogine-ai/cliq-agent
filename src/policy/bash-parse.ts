/**
 * Extract a stable "command head" from a bash invocation string so the
 * decision-table matcher can group rules like `bash: npm *` without false
 * positives from leading env assignments or `sudo`/`env` wrappers.
 *
 * Examples:
 *   "npm test"              -> "npm"
 *   "VAR=1 npm test"        -> "npm"
 *   "FOO=bar BAZ=1 git pull" -> "git"
 *   "sudo -u me ls /tmp"    -> "ls"
 *   "/usr/bin/env -S node script.js" -> "node"
 *   "  /usr/local/bin/python -m pip" -> "python"
 *   ""                      -> null
 *   "&& ls"                 -> null  (operator-leading; refuse to guess)
 *
 * Limitations (v0):
 *   - Only inspects the leading "word" of the first command in the line.
 *   - Does not unfold pipelines / `;` separators; later commands are
 *     intentionally invisible to allowlist matching so users can't write
 *     `allow: bash: git *` and then sneak `git status && rm -rf /` past it.
 *     The decision-table evaluator MUST refuse to match such a line and
 *     fall through to `ask`/preset, never to `allow`.
 *
 * TODO(no-issue: shell-allowlist-richer-matching): argv-aware matching
 * (e.g. distinguishing `git push` from `git status`), POSIX-compliant
 * quoting, and explicit pipeline/control-operator handling land in #62-B
 * alongside the user-visible allowlist surface.
 */
export function parseBashCommandHead(commandLine: string): string | null {
  if (typeof commandLine !== 'string') return null;
  const trimmed = commandLine.trim();
  if (trimmed === '') return null;

  // Refuse to guess when the line starts with a shell operator / redirection.
  // The caller must treat these as "no identifiable head" so allowlist
  // matching falls through instead of silently approving the next token.
  if (/^[&|;<>(){}!]/.test(trimmed)) return null;

  const tokens = tokenizeLeadingWords(trimmed);
  if (tokens.length === 0) return null;

  let i = 0;

  // Skip leading KEY=VALUE env assignments (POSIX-compatible prefix form).
  while (i < tokens.length && isEnvAssignment(tokens[i]!)) {
    i += 1;
  }
  if (i >= tokens.length) return null;

  // Unwrap `sudo`/`env` style wrappers, skipping their option flags.
  while (i < tokens.length && isCommandWrapper(tokens[i]!)) {
    i = skipWrapperFlags(tokens, i + 1);
    if (i >= tokens.length) return null;
  }

  const head = tokens[i]!;
  if (head === '') return null;

  // Strip directory prefix and trailing args; we only want the basename so
  // `/usr/local/bin/python` and `python` collapse to the same matcher key.
  const basename = head.includes('/') ? head.split('/').filter(Boolean).pop()! : head;
  return basename || null;
}

function isEnvAssignment(token: string): boolean {
  // POSIX env-prefix shape: NAME=value with NAME starting [A-Za-z_].
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

function isCommandWrapper(token: string): boolean {
  const basename = token.includes('/') ? token.split('/').filter(Boolean).pop()! : token;
  return basename === 'sudo' || basename === 'env' || basename === 'doas' || basename === 'nice';
}

/**
 * Wrapper commands like `sudo` / `env` accept short and long options before
 * the actual command. Skip flag tokens until we hit a non-flag word, which
 * is the wrapped command. For `env -u VAR cmd` and `sudo -u user cmd`,
 * a single flag-argument follows; we err on the side of "consume one extra
 * token after a known argument-taking flag" rather than try to model every
 * option exactly.
 */
function skipWrapperFlags(tokens: string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (!token.startsWith('-')) return i;
    // Flags known to take a follow-up arg in sudo/env: -u, -g, -p, -S (env),
    // -i (env without arg, harmless if we don't skip).
    if (token === '-u' || token === '-g' || token === '-p') {
      i += 2;
      continue;
    }
    // `env -S` takes a single string with embedded args; the wrapped command
    // is in that string itself ("env -S node script.js" → "node"). Treat
    // the next token as the wrapped command line and re-parse it.
    if (token === '-S') {
      const remainder = tokens.slice(i + 1).join(' ');
      const reparsed = parseBashCommandHead(remainder);
      // Encode the result by terminating the outer scan; caller will read
      // tokens[len-1] which we override via a synthetic slot.
      if (reparsed === null) return tokens.length;
      tokens[tokens.length - 1] = reparsed;
      return tokens.length - 1;
    }
    i += 1;
  }
  return i;
}

/**
 * Lightweight tokenizer that only needs to recover the leading words. Handles
 * single/double quotes well enough to not split mid-string, and treats
 * unmatched quotes as a parse failure (returns empty). This is intentionally
 * stricter than a full bash tokenizer: when in doubt we want the caller to
 * fall through to the preset rather than guess.
 */
function tokenizeLeadingWords(input: string): string[] {
  const out: string[] = [];
  let buf = '';
  let i = 0;
  let quote: '"' | "'" | null = null;

  while (i < input.length) {
    const ch = input[i]!;

    if (quote) {
      if (ch === '\\' && quote === '"' && i + 1 < input.length) {
        buf += input[i + 1]!;
        i += 2;
        continue;
      }
      if (ch === quote) {
        quote = null;
        i += 1;
        continue;
      }
      buf += ch;
      i += 1;
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      i += 1;
      continue;
    }

    if (ch === ' ' || ch === '\t') {
      if (buf !== '') {
        out.push(buf);
        buf = '';
      }
      i += 1;
      continue;
    }

    // Stop at shell operators; we don't try to chase pipelines.
    if (ch === '|' || ch === '&' || ch === ';' || ch === '\n') {
      break;
    }

    buf += ch;
    i += 1;
  }

  if (quote !== null) {
    // Unterminated quote — give up; the caller will treat this as "no head".
    return [];
  }
  if (buf !== '') {
    out.push(buf);
  }
  return out;
}
