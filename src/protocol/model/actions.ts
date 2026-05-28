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

export type SkillAction = {
  name: string;
};

export type SkillResourceAction = {
  skill: string;
  path?: string;
  mode?: 'read' | 'list';
};

export type PlanItemAction = {
  id?: string;
  title: string;
  status?: 'pending' | 'in_progress' | 'completed';
  notes?: string;
};

export type TodoItemAction = {
  id?: string;
  title: string;
  status: 'pending' | 'in_progress' | 'completed';
  activeForm: string;
  notes?: string;
};

export type PlanAction =
  | {
      op: 'draft';
      title: string;
      content: string;
      items?: PlanItemAction[];
    }
  | {
      op: 'update';
      planId?: string;
      title?: string;
      content: string;
      items?: PlanItemAction[];
    }
  | {
      op: 'finalize';
      planId?: string;
    };

export type TodoAction = {
  planId?: string;
  items: TodoItemAction[];
};

import { repairJsonStrings } from './json-repair.js';

export type ModelAction =
  | { bash: string }
  | { edit: EditAction }
  | { read: ReadAction }
  | { ls: LsAction }
  | { find: FindAction }
  | { grep: GrepAction }
  | { skill: SkillAction }
  | { skillResource: SkillResourceAction }
  | { plan: PlanAction }
  | { todo: TodoAction }
  | { message: string };

const TOP_LEVEL_ACTIONS = ['bash', 'edit', 'read', 'ls', 'find', 'grep', 'skill', 'skillResource', 'plan', 'todo', 'message'] as const;

export function parseModelAction(content: string): ModelAction {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (firstError) {
    try {
      parsed = JSON.parse(repairJsonStrings(content));
    } catch {
      const message = firstError instanceof Error ? firstError.message : String(firstError);
      throw new Error(`Invalid JSON from model: ${message}\n${content}`);
    }
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

  if (record.skill && typeof record.skill === 'object' && !Array.isArray(record.skill)) {
    const skill = record.skill as Record<string, unknown>;
    if (typeof skill.name === 'string') {
      return {
        skill: {
          name: skill.name
        }
      };
    }
  }

  if (record.skillResource && typeof record.skillResource === 'object' && !Array.isArray(record.skillResource)) {
    const resource = record.skillResource as Record<string, unknown>;
    if (
      typeof resource.skill === 'string' &&
      (resource.path === undefined || typeof resource.path === 'string') &&
      (resource.mode === undefined || resource.mode === 'read' || resource.mode === 'list')
    ) {
      return {
        skillResource: {
          skill: resource.skill,
          ...(resource.path !== undefined ? { path: resource.path as string } : {}),
          ...(resource.mode !== undefined ? { mode: resource.mode as 'read' | 'list' } : {})
        }
      };
    }
  }

  if (record.plan && typeof record.plan === 'object' && !Array.isArray(record.plan)) {
    const plan = record.plan as Record<string, unknown>;
    const items = parsePlanItems(plan.items);
    if (items === null) {
      throw new Error(`Model returned unsupported action:\n${content}`);
    }
    if (plan.op === 'draft' && typeof plan.title === 'string' && typeof plan.content === 'string') {
      return {
        plan: {
          op: 'draft',
          title: plan.title,
          content: plan.content,
          ...(items !== undefined ? { items } : {})
        }
      };
    }
    if (
      plan.op === 'update' &&
      (plan.planId === undefined || typeof plan.planId === 'string') &&
      (plan.title === undefined || typeof plan.title === 'string') &&
      typeof plan.content === 'string'
    ) {
      return {
        plan: {
          op: 'update',
          ...(plan.planId !== undefined ? { planId: plan.planId as string } : {}),
          ...(plan.title !== undefined ? { title: plan.title as string } : {}),
          content: plan.content,
          ...(items !== undefined ? { items } : {})
        }
      };
    }
    if (plan.op === 'finalize' && (plan.planId === undefined || typeof plan.planId === 'string')) {
      return {
        plan: {
          op: 'finalize',
          ...(plan.planId !== undefined ? { planId: plan.planId as string } : {})
        }
      };
    }
  }

  if (record.todo && typeof record.todo === 'object' && !Array.isArray(record.todo)) {
    const todo = record.todo as Record<string, unknown>;
    const items = parseTodoItems(todo.items);
    if (
      items !== null &&
      (todo.planId === undefined || typeof todo.planId === 'string')
    ) {
      return {
        todo: {
          ...(todo.planId !== undefined ? { planId: todo.planId as string } : {}),
          items
        }
      };
    }
  }

  if (!TOP_LEVEL_ACTIONS.includes(topLevelKey as (typeof TOP_LEVEL_ACTIONS)[number])) {
    throw new Error(`Unknown top-level key in model action: ${topLevelKey}\n${content}`);
  }

  throw new Error(`Model returned unsupported action:\n${content}`);
}

export function parsePlanItemAction(value: unknown): PlanItemAction | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  if (typeof item.title !== 'string' || !item.title.trim()) return null;
  if (item.id !== undefined && typeof item.id !== 'string') return null;
  if (
    item.status !== undefined &&
    item.status !== 'pending' &&
    item.status !== 'in_progress' &&
    item.status !== 'completed'
  ) {
    return null;
  }
  if (item.notes !== undefined && typeof item.notes !== 'string') return null;
  return {
    ...(item.id !== undefined ? { id: item.id } : {}),
    title: item.title,
    ...(item.status !== undefined ? { status: item.status } : {}),
    ...(item.notes !== undefined ? { notes: item.notes } : {})
  };
}

function parsePlanItems(value: unknown): PlanItemAction[] | undefined | null {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) return null;
  const items: PlanItemAction[] = [];
  for (const raw of value) {
    const item = parsePlanItemAction(raw);
    if (item === null) return null;
    items.push(item);
  }
  return items;
}

export function parseTodoItemAction(value: unknown): TodoItemAction | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  if (item.id !== undefined && typeof item.id !== 'string') return null;
  if (typeof item.title !== 'string' || !item.title.trim()) return null;
  if (item.status !== 'pending' && item.status !== 'in_progress' && item.status !== 'completed') return null;
  if (typeof item.activeForm !== 'string' || !item.activeForm.trim()) return null;
  if (item.notes !== undefined && typeof item.notes !== 'string') return null;
  return {
    ...(item.id !== undefined ? { id: item.id } : {}),
    title: item.title,
    status: item.status,
    activeForm: item.activeForm,
    ...(item.notes !== undefined ? { notes: item.notes } : {})
  };
}

function parseTodoItems(value: unknown): TodoItemAction[] | null {
  if (!Array.isArray(value)) return null;
  const items: TodoItemAction[] = [];
  for (const raw of value) {
    const item = parseTodoItemAction(raw);
    if (item === null) return null;
    items.push(item);
  }
  return items;
}
