const JSON_WHITESPACE = new Set([' ', '\t', '\n', '\r']);
const NUMBER_PREFIX = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u;
const MAX_JSON_DEPTH = 32;
const MAX_JSON_CONTAINER_ENTRIES = 10_000;

export class StrictJsonError extends SyntaxError {
  constructor(message: string, readonly offset: number) {
    super(`${message} at byte offset ${offset}`);
    this.name = 'StrictJsonError';
  }
}

class StrictJsonParser {
  private offset = 0;
  private containerEntries = 0;

  constructor(private readonly source: string) {}

  parse(): unknown {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.offset !== this.source.length) this.fail('unexpected trailing JSON content');
    return value;
  }

  private parseValue(depth: number): unknown {
    const current = this.source[this.offset];
    if ((current === '{' || current === '[') && depth >= MAX_JSON_DEPTH) {
      this.fail(`JSON nesting exceeds ${MAX_JSON_DEPTH}`);
    }
    if (current === '"') return this.parseString();
    if (current === '{') return this.parseObject(depth + 1);
    if (current === '[') return this.parseArray(depth + 1);
    if (current === 't') return this.parseLiteral('true', true);
    if (current === 'f') return this.parseLiteral('false', false);
    if (current === 'n') return this.parseLiteral('null', null);
    if (current === '-' || (current !== undefined && current >= '0' && current <= '9')) {
      return this.parseNumber();
    }
    this.fail('expected a JSON value');
  }

  private parseLiteral<T>(literal: string, value: T): T {
    if (this.source.slice(this.offset, this.offset + literal.length) !== literal) {
      this.fail(`expected ${literal}`);
    }
    this.offset += literal.length;
    return value;
  }

  private parseString(): string {
    const start = this.offset;
    this.offset += 1;
    let escaped = false;
    while (this.offset < this.source.length) {
      const character = this.source[this.offset]!;
      if (escaped) {
        escaped = false;
        this.offset += 1;
        continue;
      }
      if (character === '\\') {
        escaped = true;
        this.offset += 1;
        continue;
      }
      if (character === '"') {
        this.offset += 1;
        const token = this.source.slice(start, this.offset);
        try {
          return JSON.parse(token) as string;
        } catch {
          this.fail('invalid JSON string', start);
        }
      }
      if (character.charCodeAt(0) <= 0x1f) this.fail('unescaped control character in JSON string');
      this.offset += 1;
    }
    this.fail('unterminated JSON string', start);
  }

  private parseNumber(): number {
    const token = NUMBER_PREFIX.exec(this.source.slice(this.offset))?.[0];
    if (token === undefined) this.fail('invalid JSON number');
    const start = this.offset;
    this.offset += token.length;
    const next = this.source[this.offset];
    if (next !== undefined && !JSON_WHITESPACE.has(next) && next !== ',' && next !== ']' && next !== '}') {
      this.fail('invalid character after JSON number');
    }
    const value = Number(token);
    if (!Number.isFinite(value)) this.fail('JSON number is outside the finite range', start);
    return value;
  }

  private parseArray(depth: number): unknown[] {
    this.offset += 1;
    this.skipWhitespace();
    const values: unknown[] = [];
    if (this.source[this.offset] === ']') {
      this.offset += 1;
      return values;
    }
    while (true) {
      this.countContainerEntry();
      values.push(this.parseValue(depth));
      this.skipWhitespace();
      const delimiter = this.source[this.offset];
      if (delimiter === ']') {
        this.offset += 1;
        return values;
      }
      if (delimiter !== ',') this.fail('expected comma or closing bracket');
      this.offset += 1;
      this.skipWhitespace();
      if (this.source[this.offset] === ']') this.fail('trailing comma is not valid JSON');
    }
  }

  private parseObject(depth: number): Record<string, unknown> {
    this.offset += 1;
    this.skipWhitespace();
    const value: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    const keys = new Set<string>();
    if (this.source[this.offset] === '}') {
      this.offset += 1;
      return value;
    }
    while (true) {
      if (this.source[this.offset] !== '"') this.fail('expected a JSON object key');
      const keyOffset = this.offset;
      const key = this.parseString();
      if (keys.has(key)) this.fail(`duplicate JSON object key ${JSON.stringify(key)}`, keyOffset);
      keys.add(key);
      this.countContainerEntry();
      this.skipWhitespace();
      if (this.source[this.offset] !== ':') this.fail('expected colon after JSON object key');
      this.offset += 1;
      this.skipWhitespace();
      value[key] = this.parseValue(depth);
      this.skipWhitespace();
      const delimiter = this.source[this.offset];
      if (delimiter === '}') {
        this.offset += 1;
        return value;
      }
      if (delimiter !== ',') this.fail('expected comma or closing brace');
      this.offset += 1;
      this.skipWhitespace();
      if (this.source[this.offset] === '}') this.fail('trailing comma is not valid JSON');
    }
  }

  private skipWhitespace(): void {
    while (this.offset < this.source.length && JSON_WHITESPACE.has(this.source[this.offset]!)) {
      this.offset += 1;
    }
  }

  private countContainerEntry(): void {
    this.containerEntries += 1;
    if (this.containerEntries > MAX_JSON_CONTAINER_ENTRIES) {
      this.fail(`JSON contains more than ${MAX_JSON_CONTAINER_ENTRIES} container entries`);
    }
  }

  private fail(message: string, offset = this.offset): never {
    throw new StrictJsonError(message, Buffer.byteLength(this.source.slice(0, offset), 'utf8'));
  }
}

export function parseJsonStrict(source: string): unknown {
  return new StrictJsonParser(source).parse();
}

export function assertBoundedJsonValue(value: unknown, label = 'JSON value'): void {
  let entries = 0;
  const ancestors = new Set<object>();
  const visit = (current: unknown, depth: number): void => {
    if (current === null || typeof current === 'boolean' || typeof current === 'string') return;
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) throw new TypeError(`${label} contains a non-finite number`);
      return;
    }
    if (typeof current !== 'object') throw new TypeError(`${label} is outside the JSON domain`);
    if (depth >= MAX_JSON_DEPTH) throw new TypeError(`${label} exceeds JSON depth ${MAX_JSON_DEPTH}`);
    if (ancestors.has(current)) throw new TypeError(`${label} contains a cycle`);
    ancestors.add(current);
    try {
      if (Array.isArray(current)) {
        for (let index = 0; index < current.length; index += 1) {
          if (!Object.hasOwn(current, index)) throw new TypeError(`${label} contains a sparse array`);
          entries += 1;
          if (entries > MAX_JSON_CONTAINER_ENTRIES) {
            throw new TypeError(`${label} contains more than ${MAX_JSON_CONTAINER_ENTRIES} container entries`);
          }
          visit(current[index], depth + 1);
        }
        return;
      }
      const prototype = Object.getPrototypeOf(current);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError(`${label} contains a non-plain object`);
      }
      for (const key of Object.keys(current)) {
        entries += 1;
        if (entries > MAX_JSON_CONTAINER_ENTRIES) {
          throw new TypeError(`${label} contains more than ${MAX_JSON_CONTAINER_ENTRIES} container entries`);
        }
        visit((current as Record<string, unknown>)[key], depth + 1);
      }
    } finally {
      ancestors.delete(current);
    }
  };
  visit(value, 0);
}
