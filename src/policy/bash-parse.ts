const SHELL_INTERPRETER_HEADS = new Set([
  'ash',
  'bash',
  'dash',
  'fish',
  'ksh',
  'sh',
  'zsh'
]);

const BUSYBOX_HEAD = 'busybox';
const MAX_SHELL_INLINE_DEPTH = 8;

const SHELL_OPTION_VALUE_FLAGS: ReadonlySet<string> = new Set([
  '-o',
  '+o',
  '-O',
  '+O',
  '--init-file',
  '--rcfile'
]);

const SHELL_OPTION_ATTACHED_VALUE_PREFIXES: readonly string[] = [
  '--init-file=',
  '--rcfile='
];

/**
 * True when a bash line contains syntax that can execute more than the
 * command head matched by a `bash: <head> *` allow rule.
 *
 * Also inspects inline scripts passed to shell interpreters via `-c` / `--command`
 * so `bash -c 'git status && rm -rf /'` cannot bypass allow rules through quoting.
 */
export function bashCommandHasUnsafeAllowSyntax(commandLine: string): boolean {
  return bashCommandHasUnsafeAllowSyntaxInner(commandLine, 0);
}

function bashCommandHasUnsafeAllowSyntaxInner(commandLine: string, depth: number): boolean {
  if (unsafeAllowSyntaxInFragment(commandLine)) return true;
  const nested = extractShellInlineScript(commandLine);
  if (nested === null) return false;
  if (depth >= MAX_SHELL_INLINE_DEPTH) return true;
  return bashCommandHasUnsafeAllowSyntaxInner(nested, depth + 1);
}

/**
 * Extract the inline script argument from `sh -c`, `bash -c`, etc., when present.
 * Returns null for non-interpreter invocations or when no `-c` script is found.
 */
export function extractShellInlineScript(commandLine: string): string | null {
  if (typeof commandLine !== 'string') return null;
  const trimmed = commandLine.trim();
  if (trimmed === '') return null;

  const tokens = tokenizeWords(trimmed);
  if (tokens.length === 0) return null;

  let i = 0;
  while (i < tokens.length && isEnvAssignment(tokens[i]!)) {
    i += 1;
  }
  while (i < tokens.length && isCommandWrapper(tokens[i]!)) {
    const expanded = expandEnvSplitString(tokens, i);
    if (expanded) {
      tokens.splice(i, expanded.consumed, ...expanded.tokens);
      continue;
    }
    i = skipWrapperFlags(tokens, i);
    if (i >= tokens.length) return null;
  }
  if (i >= tokens.length) return null;

  let head = tokenBasename(tokens[i]!);
  i += 1;

  if (head === BUSYBOX_HEAD) {
    if (i >= tokens.length) return null;
    head = tokenBasename(tokens[i]!);
    i += 1;
  }

  if (!SHELL_INTERPRETER_HEADS.has(head)) return null;

  while (i < tokens.length) {
    const token = tokens[i]!;
    if (isShellCommandStringFlag(token)) {
      return tokens[i + 1] ?? null;
    }
    if (token.startsWith('--command=')) {
      return token.slice('--command='.length);
    }
    if (
      SHELL_OPTION_VALUE_FLAGS.has(token) ||
      SHELL_OPTION_ATTACHED_VALUE_PREFIXES.some((prefix) => token.startsWith(prefix))
    ) {
      i += SHELL_OPTION_VALUE_FLAGS.has(token) ? 2 : 1;
      continue;
    }
    if (token.startsWith('-')) {
      i += 1;
      continue;
    }
    break;
  }
  return null;
}

function tokenBasename(token: string): string {
  return token.includes('/') ? token.split('/').filter(Boolean).pop()! : token;
}

function expandEnvSplitString(tokens: string[], wrapperIndex: number): { consumed: number; tokens: string[] } | null {
  if (tokenBasename(tokens[wrapperIndex]!) !== 'env') return null;
  let splitFlagIndex: number | null = null;
  let i = wrapperIndex + 1;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '-S' || token === '--split-string') {
      splitFlagIndex = i;
      break;
    }
    if (token.startsWith('--split-string=')) {
      const splitTokens = tokenizeWords(token.slice('--split-string='.length));
      if (splitTokens.length === 0) return null;
      return {
        consumed: i - wrapperIndex + 1,
        tokens: splitTokens
      };
    }
    const skipped = skipEnvOption(tokens, i);
    if (skipped === i) break;
    i = skipped;
  }
  if (splitFlagIndex === null) return null;
  const splitString = tokens[splitFlagIndex + 1];
  if (splitString === undefined) return null;
  const splitTokens = tokenizeWords(splitString);
  if (splitTokens.length === 0) return null;
  return {
    consumed: splitFlagIndex - wrapperIndex + 2,
    tokens: splitTokens
  };
}

function skipEnvOption(tokens: string[], index: number): number {
  const token = tokens[index]!;
  // POSIX end-of-options markers must be consumed so a following `-S` split
  // string is visible to expandEnvSplitString (e.g. `env - -S bash -c '...'`).
  if (token === '-' || token === '--') return index + 1;
  if (isEnvAssignment(token)) return index + 1;
  if (!token.startsWith('-')) return index;
  if (
    token === '-u' ||
    token === '--unset' ||
    token === '-C' ||
    token === '--chdir' ||
    token === '--block-signal' ||
    token === '--ignore-signal' ||
    token === '--default-signal'
  ) {
    return index + 2;
  }
  if (
    token.startsWith('--unset=') ||
    token.startsWith('--chdir=') ||
    token.startsWith('--block-signal=') ||
    token.startsWith('--ignore-signal=') ||
    token.startsWith('--default-signal=')
  ) {
    return index + 1;
  }
  return index + 1;
}

function isShellCommandStringFlag(token: string): boolean {
  if (token === '-c' || token === '--command') return true;
  // Shells commonly combine short flags, e.g. `bash -lc "..."` or
  // `bash -euc "..."`. Treat any combined short option containing `c`
  // as the command-string form and inspect the following token.
  return /^-[A-Za-z]*c[A-Za-z]*$/.test(token);
}

function unsafeAllowSyntaxInFragment(commandLine: string): boolean {
  if (typeof commandLine !== 'string') return false;
  const trimmed = commandLine.trim();
  if (trimmed === '') return false;

  // Operator-leading lines already have no command head, so the matcher
  // falls through without consulting allow rules.
  if (/^[&|;<>(){}!]/.test(trimmed)) return false;

  let quote: '"' | "'" | null = null;

  for (let i = 0; i < trimmed.length; i += 1) {
    const ch = trimmed[i]!;
    const next = trimmed[i + 1];

    if (ch === '\\') {
      i += 1;
      continue;
    }

    if (quote === "'") {
      if (ch === "'") quote = null;
      continue;
    }

    if (quote === '"') {
      if (ch === '"') {
        quote = null;
        continue;
      }
      if (ch === '`') return true;
      if (ch === '$' && next === '(') return true;
      continue;
    }

    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }

    if (ch === '\n' || ch === ';' || ch === '|') return true;
    if (ch === '&' && next !== '>' && trimmed[i - 1] !== '>') return true;
    if (ch === '`') return true;
    if (ch === '$' && next === '(') return true;
    if ((ch === '<' || ch === '>') && next === '(') return true;
  }

  return false;
}

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
    const expanded = expandEnvSplitString(tokens, i);
    if (expanded) {
      tokens.splice(i, expanded.consumed, ...expanded.tokens);
      continue;
    }
    i = skipWrapperFlags(tokens, i);
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
 * Wrapper commands like `sudo` / `env` / `nice` accept short and long options
 * before the actual command. Skip flag tokens until we hit a non-flag word,
 * which is the wrapped command. For `env -u VAR cmd`, `sudo -u user cmd`,
 * `nice -n 10 cmd`, etc., a single flag-argument follows; we err on the
 * side of "consume one extra token after a known argument-taking flag"
 * rather than try to model every option exactly.
 *
 * Long-form / attached-value spellings (`-n10`, `--adjustment=10`,
 * `--user=me`) carry the value inside the same token, so we don't consume
 * an extra one for them.
 */
const SEPARATED_VALUE_FLAGS: ReadonlySet<string> = new Set([
  // sudo
  '-u', '-g', '-p',
  // nice priority
  '-n', '--priority', '--adjustment'
]);

const ATTACHED_VALUE_FLAG_PREFIXES: readonly string[] = [
  // sudo
  '--user=', '--group=', '--prompt=',
  // nice priority
  '--priority=', '--adjustment='
];

function skipWrapperFlags(tokens: string[], wrapperIndex: number): number {
  if (tokenBasename(tokens[wrapperIndex]!) === 'env') {
    return skipEnvWrapperFlags(tokens, wrapperIndex + 1);
  }

  let i = wrapperIndex + 1;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '--') return i + 1;
    if (!token.startsWith('-')) return i;

    // Flags whose argument is in the NEXT token: `nice -n 10`, `sudo -u me`.
    // Attached forms like `-n10` carry the value inside the same token and
    // do not advance an extra slot.
    if (SEPARATED_VALUE_FLAGS.has(token)) {
      i += 2;
      continue;
    }

    // Long-form attached-value spellings: `--adjustment=10`, `--user=me`, …
    if (ATTACHED_VALUE_FLAG_PREFIXES.some((prefix) => token.startsWith(prefix))) {
      i += 1;
      continue;
    }

    i += 1;
  }
  return i;
}

function skipEnvWrapperFlags(tokens: string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '-' || token === '--') {
      i += 1;
      break;
    }

    const skipped = skipEnvOption(tokens, i);
    if (skipped === i) break;
    i = skipped;
  }

  while (i < tokens.length && isEnvAssignment(tokens[i]!)) {
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
  return tokenizeWords(input, { stopAtShellOperators: true });
}

function tokenizeWords(input: string, options: { stopAtShellOperators?: boolean } = {}): string[] {
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
    if (options.stopAtShellOperators && (ch === '|' || ch === '&' || ch === ';' || ch === '\n')) {
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
