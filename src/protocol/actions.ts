export type EditAction = {
  path: string;
  old_text: string;
  new_text: string;
};

export type ReadAction = {
  path: string;
  start_line?: number;
  end_line?: number;
};

export type LsAction = {
  path?: string;
};

export type FindAction = {
  path?: string;
  name: string;
};

export type GrepAction = {
  path?: string;
  pattern: string;
};

export type ModelAction =
  | { bash: string }
  | { edit: EditAction }
  | { read: ReadAction }
  | { ls: LsAction }
  | { find: FindAction }
  | { grep: GrepAction }
  | { message: string };

const TOP_LEVEL_ACTIONS = ['bash', 'edit', 'read', 'ls', 'find', 'grep', 'message'] as const;

export function parseModelAction(content: string): ModelAction {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid JSON from model: ${message}\n${content}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Model returned invalid action object:\n${content}`);
  }

  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 1) {
    throw new Error(`Model action must contain exactly one top-level key:\n${content}`);
  }
  const topLevelKey = keys[0];

  if (typeof record.bash === 'string') {
    return { bash: record.bash };
  }

  if (typeof record.message === 'string') {
    return { message: record.message };
  }

  if (record.edit && typeof record.edit === 'object' && !Array.isArray(record.edit)) {
    const edit = record.edit as Record<string, unknown>;
    if (typeof edit.path === 'string' && typeof edit.old_text === 'string' && typeof edit.new_text === 'string') {
      return {
        edit: {
          path: edit.path,
          old_text: edit.old_text,
          new_text: edit.new_text
        }
      };
    }
  }

  if (record.read && typeof record.read === 'object' && !Array.isArray(record.read)) {
    const read = record.read as Record<string, unknown>;
    if (
      typeof read.path === 'string' &&
      (read.start_line === undefined || typeof read.start_line === 'number') &&
      (read.end_line === undefined || typeof read.end_line === 'number')
    ) {
      return {
        read: {
          path: read.path,
          start_line: read.start_line as number | undefined,
          end_line: read.end_line as number | undefined
        }
      };
    }
  }

  if (record.ls && typeof record.ls === 'object' && !Array.isArray(record.ls)) {
    const ls = record.ls as Record<string, unknown>;
    if (ls.path === undefined || typeof ls.path === 'string') {
      return {
        ls: {
          path: ls.path as string | undefined
        }
      };
    }
  }

  if (record.find && typeof record.find === 'object' && !Array.isArray(record.find)) {
    const find = record.find as Record<string, unknown>;
    if ((find.path === undefined || typeof find.path === 'string') && typeof find.name === 'string') {
      return {
        find: {
          path: find.path as string | undefined,
          name: find.name
        }
      };
    }
  }

  if (record.grep && typeof record.grep === 'object' && !Array.isArray(record.grep)) {
    const grep = record.grep as Record<string, unknown>;
    if ((grep.path === undefined || typeof grep.path === 'string') && typeof grep.pattern === 'string') {
      return {
        grep: {
          path: grep.path as string | undefined,
          pattern: grep.pattern
        }
      };
    }
  }

  if (!TOP_LEVEL_ACTIONS.includes(topLevelKey as (typeof TOP_LEVEL_ACTIONS)[number])) {
    throw new Error(`Unknown top-level key in model action: ${topLevelKey}\n${content}`);
  }

  throw new Error(`Model returned unsupported action:\n${content}`);
}
