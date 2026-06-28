import { BUILTIN_BASH_DENY_HEADS } from './decision-table.js';

const SHELL_INTERPRETER_HEADS = new Set([
  'ash',
  'bash',
  'dash',
  'fish',
  'ksh',
  'sh',
  'zsh'
]);

/**
 * Shell metacommands that can run a different program than the parsed head.
 * A `bash: git *` (or `bash: *`) allow rule must never auto-approve these,
 * otherwise `exec bash -c '…'` bypasses nested-script inspection.
 */
const BASH_DELEGATION_HEADS = new Set(['builtin', 'command', 'eval', 'exec', 'source', '.', 'xargs']);

/**
 * Non-shell interpreters that accept inline scripts via `-c` / `--command`.
 * Allow rules keyed on command heads cannot constrain their payloads.
 */
const SCRIPT_INTERPRETER_HEADS = new Set([
  'node',
  'nodejs',
  'perl',
  'php',
  'python',
  'python3',
  'ruby',
  'lua',
  'luajit'
]);

const VERSIONED_SCRIPT_INTERPRETER_PATTERNS: readonly RegExp[] = [
  /^node(?:js)?\d*(?:\.\d+)*$/,
  /^perl\d*(?:\.\d+)*$/,
  /^php\d*(?:\.\d+)*$/,
  /^pypy\d*(?:\.\d+)*$/,
  /^python\d*(?:\.\d+)*$/,
  /^ruby\d*(?:\.\d+)*$/,
  /^lua\d*(?:\.\d+)*$/,
  /^luajit(?:-\d+(?:\.\d+)*)?$/
];

const BUSYBOX_HEAD = 'busybox';
const DIRECT_WRAPPED_DENY_HEADS = new Set([BUSYBOX_HEAD, 'builtin']);
const PREFIX_COMMAND_WRAPPER_HEADS = new Set([
  'catchsegv',
  'chronic',
  'flock',
  'ionice',
  'nohup',
  'setsid',
  'stdbuf',
  'taskset',
  'time',
  'timeout',
  'unshare',
  'watch'
]);
const PRIVILEGE_WRAPPER_HEADS = new Set(['runuser', 'su', 'sudo']);
const SCRIPT_WRAPPER_HEADS = new Set(['script']);
const GIT_HEAD = 'git';
const TIME_NO_VALUE_SHORT_FLAGS = new Set(['a', 'h', 'l', 'p', 'q', 'v']);
const IONICE_NO_VALUE_SHORT_FLAGS = new Set(['p', 't']);
const UNSHARE_NO_VALUE_SHORT_FLAGS = new Set(['f', 'i', 'm', 'n', 'p', 'r', 'U']);
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

/**
 * Returns the first builtin-deny bash head found in nested shell inline scripts,
 * or null when no such head is present.
 */
export function bashNestedBuiltinDenyHead(commandLine: string): string | null {
  const direct = bashDirectWrappedBuiltinDenyHead(commandLine);
  if (direct) return direct;

  const privilegeScript = extractPrivilegeWrapperInlineScript(commandLine);
  if (privilegeScript !== null) {
    const head = parseBashCommandHead(privilegeScript);
    if (head && BUILTIN_BASH_DENY_HEADS.has(head)) return head;
    const nested = bashNestedBuiltinDenyHeadInner(privilegeScript, 0);
    if (nested) return nested;
  }

  return bashNestedBuiltinDenyHeadInner(commandLine, 0);
}

function bashDirectWrappedBuiltinDenyHead(commandLine: string): string | null {
  if (typeof commandLine !== 'string') return null;
  const trimmed = commandLine.trim();
  if (trimmed === '') return null;

  const tokens = tokenizeWords(trimmed);
  let i = 0;
  while (i < tokens.length && isEnvAssignment(tokens[i]!)) {
    i += 1;
  }
  i = skipExecutionWrappers(tokens, i);
  if (i >= tokens.length) return null;

  const privilegeDeny = privilegeWrapperBuiltinDenyHead(tokens, i);
  if (privilegeDeny) return privilegeDeny;

  const head = tokenBasename(tokens[i]!);
  if (BUILTIN_BASH_DENY_HEADS.has(head)) return head;
  if (!DIRECT_WRAPPED_DENY_HEADS.has(head)) return null;

  let j = i + 1;
  while (j < tokens.length && tokens[j]!.startsWith('-')) {
    j += 1;
  }
  if (j >= tokens.length) return null;

  const sub = tokenBasename(tokens[j]!);
  return BUILTIN_BASH_DENY_HEADS.has(sub) ? sub : null;
}

function extractPrivilegeWrapperInlineScript(commandLine: string): string | null {
  if (typeof commandLine !== 'string') return null;
  const trimmed = commandLine.trim();
  if (trimmed === '') return null;

  const tokens = tokenizeWords(trimmed);
  let i = 0;
  while (i < tokens.length && isEnvAssignment(tokens[i]!)) {
    i += 1;
  }
  i = skipExecutionWrappers(tokens, i);
  if (i >= tokens.length) return null;

  return extractPrivilegeWrapperInlineScriptFromTokens(tokens, i);
}

function skipExecutionWrappers(tokens: string[], startIndex: number): number {
  let i = startIndex;
  while (i < tokens.length) {
    const expanded = expandEnvSplitString(tokens, i);
    if (expanded) {
      tokens.splice(i, expanded.consumed, ...expanded.tokens);
      continue;
    }
    if (isCommandWrapper(tokens[i]!)) {
      i = skipWrapperFlags(tokens, i);
      continue;
    }
    if (isPrefixCommandWrapper(tokens[i]!)) {
      i = skipPrefixCommandWrapper(tokens, i);
      continue;
    }
    return i;
  }
  return i;
}

function extractPrivilegeWrapperInlineScriptFromTokens(tokens: string[], startIndex: number): string | null {
  const head = tokenBasename(tokens[startIndex]!);
  if (!PRIVILEGE_WRAPPER_HEADS.has(head)) return null;

  for (let i = startIndex + 1; i < tokens.length; i += 1) {
    const token = tokens[i]!;
    if (token === '-c' || token === '--command') {
      return tokens[i + 1] ?? null;
    }
    if (token.startsWith('--command=')) {
      return token.slice('--command='.length);
    }
    if (/^-[A-Za-z]*c[A-Za-z]*$/.test(token)) {
      return tokens[i + 1] ?? null;
    }
  }
  return null;
}

function bashNestedBuiltinDenyHeadInner(commandLine: string, depth: number): string | null {
  const splitDeny = envSplitExpansionsNestedBuiltinDenyHead(commandLine);
  if (splitDeny) return splitDeny;

  const gitAliasDeny = gitShellAliasBuiltinDenyHead(commandLine);
  if (gitAliasDeny) return gitAliasDeny;

  const embedded = analyzeEmbeddedInlineScripts(commandLine);
  const shellScripts = new Set<string>();
  const leadingShell = extractShellInlineScript(commandLine);
  if (leadingShell !== null) shellScripts.add(leadingShell);
  for (const script of embedded.shellScripts) shellScripts.add(script);

  for (const nested of shellScripts) {
    const head = parseBashCommandHead(nested);
    if (head && BUILTIN_BASH_DENY_HEADS.has(head)) return head;
    if (depth >= MAX_SHELL_INLINE_DEPTH) continue;
    const deeper = bashNestedBuiltinDenyHeadInner(nested, depth + 1);
    if (deeper) return deeper;
  }
  return null;
}

function envSplitExpansionsNestedBuiltinDenyHead(commandLine: string): string | null {
  if (typeof commandLine !== 'string') return null;
  const trimmed = commandLine.trim();
  if (trimmed === '') return null;

  const tokens = tokenizeWords(trimmed);
  let i = 0;
  while (i < tokens.length) {
    const expanded = expandEnvSplitString(tokens, i);
    if (!expanded) {
      i += 1;
      continue;
    }

    const denyHead = builtinDenyHeadFromCommandTokens(expanded.tokens);
    if (denyHead) return denyHead;

    tokens.splice(i, expanded.consumed, ...expanded.tokens);
  }
  return null;
}

function builtinDenyHeadFromCommandTokens(tokens: string[]): string | null {
  if (tokens.length === 0) return null;

  const commandLine = tokens.join(' ');
  const head = parseBashCommandHead(commandLine);
  if (head && BUILTIN_BASH_DENY_HEADS.has(head)) return head;

  return bashDirectWrappedBuiltinDenyHead(commandLine);
}

function bashCommandHasUnsafeAllowSyntaxInner(commandLine: string, depth: number): boolean {
  if (unsafeAllowSyntaxInFragment(commandLine)) return true;
  if (envSplitExpansionsHaveUnsafeSyntax(commandLine)) return true;
  if (gitShellAliasHasUnsafeAllowSyntax(commandLine)) return true;

  const head = parseBashCommandHead(commandLine);
  if (head && (head.startsWith('-') || BASH_DELEGATION_HEADS.has(head))) return true;

  const embedded = analyzeEmbeddedInlineScripts(commandLine);
  if (embedded.hasScriptInterpreter || embedded.hasFindExec) return true;
  if (bashNestedBuiltinDenyHead(commandLine) !== null) return true;

  const shellScripts = new Set<string>();
  const leadingShell = extractShellInlineScript(commandLine);
  if (leadingShell !== null) shellScripts.add(leadingShell);
  for (const script of embedded.shellScripts) shellScripts.add(script);

  for (const nested of shellScripts) {
    if (depth >= MAX_SHELL_INLINE_DEPTH) return true;
    if (bashCommandHasUnsafeAllowSyntaxInner(nested, depth + 1)) return true;
  }
  return false;
}

/**
 * Scan every argv position for inline shell / script-interpreter payloads.
 * Prefix wrappers such as `timeout` or `nohup` hide `bash -c` from head-based
 * parsing; embedded detection keeps `allow: bash: *` from auto-approving them.
 */
function analyzeEmbeddedInlineScripts(commandLine: string): {
  shellScripts: string[];
  hasScriptInterpreter: boolean;
  hasFindExec: boolean;
} {
  if (typeof commandLine !== 'string') {
    return { shellScripts: [], hasScriptInterpreter: false, hasFindExec: false };
  }
  const trimmed = commandLine.trim();
  if (trimmed === '') return { shellScripts: [], hasScriptInterpreter: false, hasFindExec: false };

  const tokens = tokenizeWords(trimmed);
  const shellScripts: string[] = [];
  let hasScriptInterpreter = false;
  let hasFindExec = false;
  let i = 0;
  while (i < tokens.length) {
    const expanded = expandEnvSplitString(tokens, i);
    if (expanded) {
      tokens.splice(i, expanded.consumed, ...expanded.tokens);
      continue;
    }
    const token = tokens[i]!;
    if (token === '-exec' || token === '-execdir' || token.startsWith('-exec=') || token.startsWith('-execdir=')) {
      hasFindExec = true;
    }
    if (extractScriptInterpreterInlineFromTokens(tokens, i) !== null) {
      hasScriptInterpreter = true;
    }
    const shellScript = extractShellInlineScriptFromTokens(tokens, i);
    if (shellScript !== null) shellScripts.push(shellScript);
    const scriptWrapperScript = extractScriptWrapperInlineFromTokens(tokens, i);
    if (scriptWrapperScript !== null) shellScripts.push(scriptWrapperScript);
    i += 1;
  }
  return { shellScripts, hasScriptInterpreter, hasFindExec };
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

  return extractShellInlineScriptFromTokens(tokens, i);
}

function extractShellInlineScriptFromTokens(tokens: string[], startIndex: number): string | null {
  if (startIndex >= tokens.length) return null;

  let i = startIndex;
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

function extractScriptWrapperInlineFromTokens(tokens: string[], startIndex: number): string | null {
  if (startIndex >= tokens.length) return null;
  if (!SCRIPT_WRAPPER_HEADS.has(tokenBasename(tokens[startIndex]!))) return null;

  for (let i = startIndex + 1; i < tokens.length; i += 1) {
    const token = tokens[i]!;
    if (token === '-c' || token === '--command') {
      return tokens[i + 1] ?? null;
    }
    if (token.startsWith('--command=')) {
      return token.slice('--command='.length);
    }
    if (/^-[A-Za-z]*c[A-Za-z]*$/.test(token)) {
      return tokens[i + 1] ?? null;
    }
  }
  return null;
}

function gitShellAliasHasUnsafeAllowSyntax(commandLine: string): boolean {
  const payloads = extractGitShellAliasPayloads(commandLine);
  if (payloads.length > 0) return true;
  return false;
}

function gitShellAliasBuiltinDenyHead(commandLine: string): string | null {
  for (const payload of extractGitShellAliasPayloads(commandLine)) {
    const head = parseBashCommandHead(payload);
    if (head && BUILTIN_BASH_DENY_HEADS.has(head)) return head;
    const direct = bashDirectWrappedBuiltinDenyHead(payload);
    if (direct) return direct;
    const nested = bashNestedBuiltinDenyHeadInner(payload, 0);
    if (nested) return nested;
  }
  return null;
}

function extractGitShellAliasPayloads(commandLine: string): string[] {
  if (typeof commandLine !== 'string') return [];
  const trimmed = commandLine.trim();
  if (trimmed === '') return [];

  const tokens = tokenizeWords(trimmed);
  let i = 0;
  while (i < tokens.length && isEnvAssignment(tokens[i]!)) {
    i += 1;
  }
  if (i >= tokens.length || tokenBasename(tokens[i]!) !== GIT_HEAD) return [];

  const payloads: string[] = [];
  for (let j = i + 1; j < tokens.length; j += 1) {
    const token = tokens[j]!;
    if (token === '-c' || token === '--config') {
      const assignment = tokens[j + 1];
      if (assignment === undefined) break;
      const payload = gitShellAliasPayloadFromAssignment(assignment);
      if (payload !== null) payloads.push(payload);
      j += 1;
      continue;
    }
    const attachedConfig = gitConfigAssignmentFromToken(token);
    if (attachedConfig) {
      const payload = gitShellAliasPayloadFromAssignment(attachedConfig);
      if (payload !== null) payloads.push(payload);
    }
  }
  return payloads;
}

function gitConfigAssignmentFromToken(token: string): string | null {
  if (token.startsWith('--config=')) return token.slice('--config='.length);
  if (token.startsWith('-c') && token.length > 2) return token.slice(2);
  return null;
}

function gitShellAliasPayloadFromAssignment(assignment: string): string | null {
  const eq = assignment.indexOf('=');
  if (eq <= 0) return null;
  const key = assignment.slice(0, eq);
  if (!key.startsWith('alias.')) return null;
  let value = assignment.slice(eq + 1);
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1);
  }
  if (!value.startsWith('!')) return null;
  const payload = value.slice(1).trim();
  return payload === '' ? null : payload;
}

/**
 * Extract inline script text from `python -c`, `node -e`, etc. Returns null when
 * the invocation is not a known script interpreter or has no script argument.
 */
function extractScriptInterpreterInlineFromTokens(tokens: string[], startIndex: number): string | null {
  if (startIndex >= tokens.length) return null;

  const head = tokenBasename(tokens[startIndex]!);
  if (!isScriptInterpreterHead(head)) return null;

  for (let i = startIndex + 1; i < tokens.length; i += 1) {
    const token = tokens[i]!;
    const attached = extractAttachedScriptInline(head, token);
    if (attached !== null) {
      return attached;
    }
    if (isScriptInlineFlag(head, token)) {
      return tokens[i + 1] ?? null;
    }
  }
  return null;
}

function isScriptInterpreterHead(head: string): boolean {
  return (
    SCRIPT_INTERPRETER_HEADS.has(head) ||
    VERSIONED_SCRIPT_INTERPRETER_PATTERNS.some((pattern) => pattern.test(head))
  );
}

function isPhpInterpreterHead(head: string): boolean {
  return /^php\d*(?:\.\d+)*$/.test(head);
}

function isNodeInterpreterHead(head: string): boolean {
  return /^node(?:js)?\d*(?:\.\d+)*$/.test(head);
}

function isPythonInterpreterHead(head: string): boolean {
  return /^(?:python|pypy)\d*(?:\.\d+)*$/.test(head);
}

function isPerlInterpreterHead(head: string): boolean {
  return /^perl\d*(?:\.\d+)*$/.test(head);
}

function isRubyInterpreterHead(head: string): boolean {
  return /^ruby\d*(?:\.\d+)*$/.test(head);
}

function isLuaInterpreterHead(head: string): boolean {
  return /^lua\d*(?:\.\d+)*$/.test(head) || /^luajit(?:-\d+(?:\.\d+)*)?$/.test(head);
}

function scriptInlineShortFlags(head: string): ReadonlySet<string> {
  if (isNodeInterpreterHead(head)) return new Set(['e', 'p']);
  if (isPythonInterpreterHead(head)) return new Set(['c']);
  if (isPerlInterpreterHead(head)) return new Set(['e', 'E']);
  if (isRubyInterpreterHead(head)) return new Set(['e']);
  if (isPhpInterpreterHead(head)) return new Set(['r']);
  if (isLuaInterpreterHead(head)) return new Set(['e']);
  return new Set();
}

function isScriptInlineFlag(head: string, token: string): boolean {
  if (token === '--command' || token === '--eval') return true;
  if (isNodeInterpreterHead(head) && token === '--print') return true;
  if (!token.startsWith('-') || token.startsWith('--')) return false;

  const flags = scriptInlineShortFlags(head);
  if (flags.size === 0) return false;
  return token
    .slice(1)
    .split('')
    .some((flag) => flags.has(flag));
}

function extractAttachedScriptInline(head: string, token: string): string | null {
  if (token.startsWith('--command=') || token.startsWith('--eval=')) {
    return token.slice(token.indexOf('=') + 1);
  }
  if (isNodeInterpreterHead(head) && token.startsWith('--print=')) {
    return token.slice('--print='.length);
  }
  if (!token.startsWith('-') || token.startsWith('--')) return null;

  const flags = scriptInlineShortFlags(head);
  for (let i = 1; i < token.length; i += 1) {
    if (flags.has(token[i]!)) {
      const script = token.slice(i + 1);
      return script === '' ? null : script;
    }
  }
  return null;
}

function tokenBasename(token: string): string {
  return token.includes('/') ? token.split('/').filter(Boolean).pop()! : token;
}

/**
 * `env -S` / `env --split-string=` execute the split payload as a real argv
 * vector, so compound operators inside the quoted split string are live syntax,
 * not literals. Outer-line quote scanning hides them from
 * {@link unsafeAllowSyntaxInFragment}; expand and re-check the payload here.
 */
function envSplitExpansionsHaveUnsafeSyntax(commandLine: string): boolean {
  if (typeof commandLine !== 'string') return false;
  const trimmed = commandLine.trim();
  if (trimmed === '') return false;

  const tokens = tokenizeWords(trimmed);
  let i = 0;
  while (i < tokens.length) {
    const expanded = expandEnvSplitString(tokens, i);
    if (!expanded) {
      i += 1;
      continue;
    }
    const splitCommand = expanded.tokens.join(' ');
    if (unsafeAllowSyntaxInFragment(splitCommand)) return true;
    tokens.splice(i, expanded.consumed, ...expanded.tokens);
  }
  return false;
}

function expandEnvSplitString(tokens: string[], wrapperIndex: number): { consumed: number; tokens: string[] } | null {
  if (tokenBasename(tokens[wrapperIndex]!) !== 'env') return null;
  let splitFlagIndex: number | null = null;
  let i = wrapperIndex + 1;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '-' || token === '--') {
      i += 1;
      continue;
    }
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
    const shortSplit = extractEnvShortSplitString(token);
    if (shortSplit) {
      if (shortSplit.attached !== null) {
        const splitTokens = tokenizeWords(shortSplit.attached);
        if (splitTokens.length === 0) return null;
        return {
          consumed: i - wrapperIndex + 1,
          tokens: splitTokens
        };
      }
      splitFlagIndex = i;
      break;
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

function extractEnvShortSplitString(token: string): { attached: string | null } | null {
  if (!token.startsWith('-') || token.startsWith('--') || token === '-') return null;
  const splitFlagOffset = token.indexOf('S', 1);
  if (splitFlagOffset === -1) return null;
  const precedingShortFlags = token.slice(1, splitFlagOffset);
  if (!/^[iv]*$/.test(precedingShortFlags)) return null;
  const attached = token.slice(splitFlagOffset + 1);
  return { attached: attached === '' ? null : attached };
}

function skipEnvOption(tokens: string[], index: number): number {
  const token = tokens[index]!;
  if (token === '-' || token === '--') return index;
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
  // Option-looking heads (e.g. env - -- -S … mis-parse) must not match allow rules.
  if (basename.startsWith('-')) return null;
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

function isPrivilegeWrapper(token: string): boolean {
  return PRIVILEGE_WRAPPER_HEADS.has(tokenBasename(token));
}

function isPrefixCommandWrapper(token: string): boolean {
  return PREFIX_COMMAND_WRAPPER_HEADS.has(tokenBasename(token));
}

function privilegeWrapperBuiltinDenyHead(tokens: string[], startIndex: number): string | null {
  if (!isPrivilegeWrapper(tokens[startIndex]!)) return null;

  const inlineScript = extractPrivilegeWrapperInlineScriptFromTokens(tokens, startIndex);
  if (inlineScript !== null) {
    return builtinDenyHeadFromCommandTokens(tokenizeWords(inlineScript));
  }

  const wrappedIndex = skipPrivilegeWrapperForWrappedCommand(tokens, startIndex);
  if (wrappedIndex >= tokens.length) return null;
  const head = tokenBasename(tokens[wrappedIndex]!);
  return BUILTIN_BASH_DENY_HEADS.has(head) ? head : null;
}

function skipPrivilegeWrapperForWrappedCommand(tokens: string[], wrapperIndex: number): number {
  let i = wrapperIndex + 1;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '--') return i + 1;
    if (token === '-c' || token === '--command' || token.startsWith('--command=')) {
      return tokens.length;
    }
    if (/^-[A-Za-z]*c[A-Za-z]*$/.test(token)) {
      return tokens.length;
    }
    if (
      token === '-u' ||
      token === '-g' ||
      token === '-l' ||
      token === '--user' ||
      token === '--group' ||
      token === '--login' ||
      token === '--session-command'
    ) {
      i += 2;
      continue;
    }
    if (
      token.startsWith('--user=') ||
      token.startsWith('--group=') ||
      token.startsWith('--login=') ||
      token.startsWith('--session-command=')
    ) {
      i += 1;
      continue;
    }
    if (token.startsWith('-') && !token.startsWith('--')) {
      i += 1;
      continue;
    }
    break;
  }
  return i;
}

function skipPrefixCommandWrapper(tokens: string[], wrapperIndex: number): number {
  const head = tokenBasename(tokens[wrapperIndex]!);
  if (head === 'timeout') return skipTimeoutWrapperArgs(tokens, wrapperIndex + 1);
  if (head === 'time') return skipTimeWrapperArgs(tokens, wrapperIndex + 1);
  if (head === 'nohup') return skipNohupWrapperArgs(tokens, wrapperIndex + 1);
  if (head === 'stdbuf') return skipStdbufWrapperArgs(tokens, wrapperIndex + 1);
  if (head === 'ionice') return skipIoniceWrapperArgs(tokens, wrapperIndex + 1);
  if (head === 'taskset') return skipTasksetWrapperArgs(tokens, wrapperIndex + 1);
  if (head === 'watch') return skipWatchWrapperArgs(tokens, wrapperIndex + 1);
  if (head === 'unshare') return skipUnshareWrapperArgs(tokens, wrapperIndex + 1);
  if (head === 'flock') return skipFlockWrapperArgs(tokens, wrapperIndex + 1);
  return wrapperIndex + 1;
}

function skipIoniceWrapperArgs(tokens: string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '--') return i + 1;
    if (token === '-c' || token === '-n' || token === '--class' || token === '--priority') {
      i += 2;
      continue;
    }
    if (token.startsWith('--class=') || token.startsWith('--priority=')) {
      i += 1;
      continue;
    }
    const shortOptionSkip = skipShortOptionToken(token, IONICE_NO_VALUE_SHORT_FLAGS, new Set(['c', 'n']));
    if (shortOptionSkip !== null) {
      i += shortOptionSkip;
      continue;
    }
    break;
  }
  return i;
}

function skipTasksetWrapperArgs(tokens: string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '--') return i + 1;
    if (token === '-c' || token === '-p' || token === '--cpu-list' || token === '--pid') {
      i += 2;
      continue;
    }
    if (token.startsWith('--cpu-list=') || token.startsWith('--pid=')) {
      i += 1;
      continue;
    }
    if (/^-[cp].+/.test(token)) {
      i += 1;
      continue;
    }
    break;
  }
  return i;
}

function skipWatchWrapperArgs(tokens: string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '--') return i + 1;
    if (token === '-n' || token === '-t' || token === '-x' || token === '--interval' || token === '--no-title') {
      i += token === '--no-title' ? 1 : 2;
      continue;
    }
    if (token.startsWith('--interval=')) {
      i += 1;
      continue;
    }
    if (/^-[nt].+/.test(token)) {
      i += 1;
      continue;
    }
    break;
  }
  return i;
}

function skipUnshareWrapperArgs(tokens: string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '--') return i + 1;
    if (token === '--mount-proc' || token === '--propagation') {
      i += token === '--propagation' ? 2 : 1;
      continue;
    }
    if (token.startsWith('--propagation=')) {
      i += 1;
      continue;
    }
    const shortOptionSkip = skipShortOptionToken(token, UNSHARE_NO_VALUE_SHORT_FLAGS, new Set());
    if (shortOptionSkip !== null) {
      i += shortOptionSkip;
      continue;
    }
    break;
  }
  return i;
}

function skipFlockWrapperArgs(tokens: string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '--') return i + 1;
    if (
      token === '-n' ||
      token === '-x' ||
      token === '-o' ||
      token === '-w' ||
      token === '--nonblock' ||
      token === '--exclusive' ||
      token === '--shared' ||
      token === '--timeout' ||
      token === '--close'
    ) {
      i += token === '--timeout' ? 2 : 1;
      continue;
    }
    if (token.startsWith('--timeout=')) {
      i += 1;
      continue;
    }
    if (token.startsWith('-')) {
      i += 1;
      continue;
    }
    // flock requires a file descriptor/path before the wrapped command.
    i += 1;
    break;
  }
  return i;
}

function skipShortOptionToken(
  token: string,
  noValueFlags: ReadonlySet<string>,
  valueFlags: ReadonlySet<string>
): number | null {
  if (!token.startsWith('-') || token.startsWith('--') || token === '-') return null;

  for (let i = 1; i < token.length; i += 1) {
    const flag = token[i]!;
    if (valueFlags.has(flag)) {
      return i === token.length - 1 ? 2 : 1;
    }
    if (!noValueFlags.has(flag)) return null;
  }
  return 1;
}

function skipNohupWrapperArgs(tokens: string[], start: number): number {
  return tokens[start] === '--' ? start + 1 : start;
}

function skipTimeoutWrapperArgs(tokens: string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '--') {
      i += 1;
      break;
    }
    if (token === '-k' || token === '--kill-after' || token === '-s' || token === '--signal') {
      i += 2;
      continue;
    }
    if (/^-[ks].+/.test(token)) {
      i += 1;
      continue;
    }
    if (token.startsWith('--kill-after=') || token.startsWith('--signal=')) {
      i += 1;
      continue;
    }
    if (
      token === '--foreground' ||
      token === '--preserve-status' ||
      token === '-v' ||
      token === '--verbose'
    ) {
      i += 1;
      continue;
    }
    break;
  }
  // `timeout` requires a duration before the command.
  return i < tokens.length ? i + 1 : i;
}

function skipStdbufWrapperArgs(tokens: string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '--') return i + 1;
    if (
      token === '-i' ||
      token === '--input' ||
      token === '-o' ||
      token === '--output' ||
      token === '-e' ||
      token === '--error'
    ) {
      i += 2;
      continue;
    }
    if (
      /^-[ioe].+/.test(token) ||
      token.startsWith('--input=') ||
      token.startsWith('--output=') ||
      token.startsWith('--error=')
    ) {
      i += 1;
      continue;
    }
    break;
  }
  return i;
}

function skipTimeWrapperArgs(tokens: string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token === '--') return i + 1;
    if (token === '-f' || token === '--format' || token === '-o' || token === '--output') {
      i += 2;
      continue;
    }
    if (token.startsWith('--format=') || token.startsWith('--output=')) {
      i += 1;
      continue;
    }
    const shortOptionSkip = skipTimeShortOptionToken(token);
    if (shortOptionSkip !== null) {
      i += shortOptionSkip;
      continue;
    }
    if (
      token === '--append' ||
      token === '--portability' ||
      token === '--quiet' ||
      token === '--verbose'
    ) {
      i += 1;
      continue;
    }
    break;
  }
  return i;
}

function skipTimeShortOptionToken(token: string): number | null {
  if (!token.startsWith('-') || token.startsWith('--') || token === '-') return null;

  for (let i = 1; i < token.length; i += 1) {
    const flag = token[i]!;
    if (flag === 'f' || flag === 'o') {
      return i === token.length - 1 ? 2 : 1;
    }
    if (!TIME_NO_VALUE_SHORT_FLAGS.has(flag)) return null;
  }
  return 1;
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
    // POSIX/GNU env treat a lone `-` or `--` as end-of-options; keep scanning
    // so a following `-S` / `--split-string` is still visible to the parser.
    if (token === '-' || token === '--') {
      i += 1;
      continue;
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
