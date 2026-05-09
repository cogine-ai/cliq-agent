const VALID_SHORT_ESCAPES = new Set(['"', '\\', '/', 'b', 'f', 'n', 'r', 't']);
const HEX = /^[0-9a-fA-F]{4}$/;

export function repairJsonStrings(raw: string): string {
  let out = '';
  let i = 0;
  let inString = false;

  while (i < raw.length) {
    const c = raw[i];

    if (!inString) {
      if (c === '"') {
        inString = true;
      }
      out += c;
      i += 1;
      continue;
    }

    if (c === '"') {
      inString = false;
      out += c;
      i += 1;
      continue;
    }

    if (c === '\\') {
      const next = raw[i + 1];
      if (next === undefined) {
        out += '\\\\';
        i += 1;
        continue;
      }
      if (VALID_SHORT_ESCAPES.has(next)) {
        out += '\\' + next;
        i += 2;
        continue;
      }
      if (next === 'u' && HEX.test(raw.slice(i + 2, i + 6))) {
        out += raw.slice(i, i + 6);
        i += 6;
        continue;
      }
      out += '\\\\';
      i += 1;
      continue;
    }

    const code = c.charCodeAt(0);
    if (code < 0x20) {
      switch (c) {
        case '\b':
          out += '\\b';
          break;
        case '\f':
          out += '\\f';
          break;
        case '\n':
          out += '\\n';
          break;
        case '\r':
          out += '\\r';
          break;
        case '\t':
          out += '\\t';
          break;
        default:
          out += '\\u' + code.toString(16).padStart(4, '0');
      }
      i += 1;
      continue;
    }

    out += c;
    i += 1;
  }

  return out;
}
