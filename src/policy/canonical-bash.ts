/** Fixed, non-executable cliq-bash-head-parser-v1. Unsupported syntax cannot produce an allow-rule key. */
type Word = { text: string; start: number };
type Command = { words: Word[]; start: number };

const SHELLS = new Set(['sh', 'bash', 'dash', 'ash', 'ksh', 'zsh', 'fish']);
const DYNAMIC_HEADS = new Set(['eval', 'source', '.', 'xargs', 'find']);
const SCRIPT_INTERPRETER = /^(?:node(?:js)?|python|pypy|perl|php|ruby|lua|luajit)[\d.-]*$/u;
const basename = (value: string) => value.split('/').at(-1)!;

/** Locate a retained substitution without evaluating it. Unsupported/unclosed fragments have no trusted head. */
function substitutionEnd(script: string, start: number, backtick: boolean): number | undefined {
  let quote = '', depth = 1;
  for (let i = start; i < script.length; i++) {
    const c = script[i]!;
    if (c === '\\' && quote !== "'") { i++; continue; }
    if (backtick && c === '`') return i;
    if (quote) { if (c === quote) quote = ''; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (!backtick && c === '(') depth++;
    if (!backtick && c === ')' && --depth === 0) return i;
  }
  return undefined;
}

function lex(script: string, substitution: (script: string, position: number) => void): { commands: Command[]; unsafe: boolean; unsupported: boolean } {
  const commands: Command[] = [];
  let words: Word[] = [], text = '', start = 0, inWord = false, quote = '';
  let unsafe = false, unsupported = false, needsCommand = false;
  const endWord = () => { if (inWord) words.push({ text, start }); text = ''; inWord = false; };
  const endCommand = () => { endWord(); if (words.length) commands.push({ words, start: words[0]!.start }); words = []; };
  for (let i = 0; i < script.length; i++) {
    const c = script[i]!;
    if (quote !== "'" && (c === '`' || (['$', '<', '>'].includes(c) && script[i + 1] === '('))) {
      unsupported = true;
      if (!inWord) { start = i; inWord = true; needsCommand = false; }
      const bodyStart = i + (c === '`' ? 1 : 2);
      const end = substitutionEnd(script, bodyStart, c === '`');
      if (end === undefined) break;
      substitution(script.slice(bodyStart, end), i);
      // This word is dynamic. Do not reinterpret its expansion as literal inline-shell source or count it twice.
      text += '\0';
      i = end;
    } else if (c === '\\' && quote !== "'") {
      if (!inWord) { start = i; inWord = true; needsCommand = false; }
      if (++i === script.length) { unsupported = true; break; }
      if (script[i] === '\n') { unsafe = true; continue; }
      if (quote === '"' && !['$', '`', '"', '\\'].includes(script[i]!)) text += '\\';
      text += script[i];
    } else if (quote) {
      if (c === quote) quote = '';
      else { text += c; if (quote === '"' && (c === '$' || c === '`')) unsupported = true; }
    } else if (c === "'" || c === '"') {
      if (!inWord) { start = i; inWord = true; needsCommand = false; }
      quote = c;
    } else if (c === '#' && !inWord) {
      unsafe = true;
      const newline = script.indexOf('\n', i);
      if (newline < 0) break;
      i = newline - 1;
    } else if (';&|\n'.includes(c)) {
      unsafe = true;
      if (c !== '\n' && !inWord && !words.length) unsupported = true;
      endCommand();
      needsCommand = c === '&' || c === '|';
      if ((c === '&' || c === '|') && script[i + 1] === c) i++;
    } else if (c === ' ' || c === '\t') endWord();
    else {
      if (!inWord) { start = i; inWord = true; }
      needsCommand = false;
      if ('$`(){}<>!'.includes(c)) unsupported = true;
      if ('*?[]'.includes(c)) unsafe = true;
      text += c;
    }
  }
  if (quote || needsCommand) unsupported = true;
  endCommand();
  return { commands, unsafe, unsupported };
}

/** Return deny occurrences recognized by the fixed grammar without executing or consulting a host shell. */
export function parseCanonicalBash(shellText: string): {
  outerCommandHead?: string; nestedBuiltinDenyHeads: string[]; unsafeForAllow: boolean;
} {
  if (typeof shellText !== 'string' || !shellText.trim() || shellText.includes('\0') || shellText !== shellText.normalize('NFC')) {
    throw new TypeError('shell request must be nonempty NFC text without NUL');
  }
  let unsupported = false, unsafe = false;
  const denies: Array<{ position: number[]; directOuter: boolean }> = [];
  let outer: string | undefined;
  const inspect = (script: string, depth: number, isOuter: boolean, position: number[]) => {
    if (depth > 8) { unsupported = true; return; }
    const parsed = lex(script, (source, offset) => inspect(source, depth + 1, false, [...position, offset]));
    unsupported ||= parsed.unsupported;
    unsafe ||= parsed.unsafe || parsed.commands.length !== 1;
    for (const [commandIndex, command] of parsed.commands.entries()) {
      const words = command.words.map((word) => word.text);
      let i = 0;
      while (/^[A-Za-z_][A-Za-z0-9_]*=/u.test(words[i] ?? '')) { unsafe = true; i++; }
      let head = basename(words[i] ?? '');
      while (['env', 'command', 'exec', 'builtin', 'nohup', 'sudo'].includes(head)) {
        unsafe = true; i++;
        if (head === 'env') {
          while (/^[A-Za-z_][A-Za-z0-9_]*=/u.test(words[i] ?? '')) i++;
          if (words[i] === '--') i++;
        } else if (words[i] === '--') i++;
        if (words[i]?.startsWith('-')) { unsupported = true; break; }
        head = basename(words[i] ?? '');
      }
      if (!head || Buffer.byteLength(head) > 4096 || /[^\p{L}\p{N}_.+:-]/u.test(head)) { unsupported = true; continue; }
      const first = isOuter && commandIndex === 0;
      if (first) outer = head;
      if (head === 'rm') denies.push({ position: [...position, command.words[i]!.start], directOuter: first && i === 0 });
      if (denies.length > 65) throw new TypeError('shell deny evidence exceeds 64 occurrences');
      if (SHELLS.has(head)) {
        unsafe = true;
        const option = words[i + 1];
        if (option && (/^-[a-z]*c$/u.test(option) || option === '--command') && words[i + 2] !== undefined && !words[i + 2]!.includes('\0')) {
          inspect(words[i + 2]!, depth + 1, false, [...position, command.words[i + 2]!.start]);
        }
        else unsupported = true;
      } else if (DYNAMIC_HEADS.has(head) || SCRIPT_INTERPRETER.test(head) ||
          ['busybox', 'time', 'timeout', 'su', 'runuser', 'setsid', 'flock', 'script', 'nice', 'ionice', 'chronic',
            'catchsegv', 'stdbuf', 'taskset', 'unshare', 'watch'].includes(head) ||
          (head === 'git' && words.slice(i + 1).some((word) => word.startsWith('-')))) {
        // A head allow-list cannot constrain these programs' delegated commands or inline code.
        unsafe = true;
        unsupported = true;
      }
    }
  };
  inspect(shellText, 0, true, []);
  // Lexical position tuples preserve repeated occurrences, including substitutions, without duplicating one parse visit.
  const nested = denies.filter((deny) => unsupported || !deny.directOuter).sort((left, right) => {
    for (let i = 0; i < Math.min(left.position.length, right.position.length); i++) {
      const difference = left.position[i]! - right.position[i]!;
      if (difference !== 0) return difference;
    }
    return left.position.length - right.position.length;
  }).map(() => 'rm');
  if (nested.length > 64) throw new TypeError('shell deny evidence exceeds 64 occurrences');
  return { ...(unsupported || outer === undefined ? {} : { outerCommandHead: outer }),
    nestedBuiltinDenyHeads: nested, unsafeForAllow: unsafe || unsupported };
}
