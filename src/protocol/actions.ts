export type EditAction = {
  path: string;
  old_text: string;
  new_text: string;
};

export type ModelAction =
  | { bash: string }
  | { edit: EditAction }
  | { message: string };

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

  if (!['bash', 'edit', 'message'].includes(topLevelKey)) {
    throw new Error(`Unknown top-level key in model action: ${topLevelKey}\n${content}`);
  }

  throw new Error(`Model returned unsupported action:\n${content}`);
}
