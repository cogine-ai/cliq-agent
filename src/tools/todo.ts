import { parseTodoItemAction, type TodoAction } from '../protocol/model/actions.js';
import { updatePlanProgress } from '../plans/store.js';
import type { PlanProgress } from '../plans/types.js';
import type { ToolDefinition, ToolResult } from './types.js';

export const todoTool: ToolDefinition<{ todo: TodoAction }> = {
  name: 'todo',
  access: 'plan',
  modelSpec: {
    name: 'todo',
    description: 'Update progress items for an approved plan.',
    inputSchema: {
      type: 'object',
      properties: {
        planId: { type: 'string' },
        items: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              title: { type: 'string' },
              status: { type: 'string', enum: ['pending', 'in_progress', 'completed'] },
              activeForm: { type: 'string' },
              notes: { type: 'string' }
            },
            required: ['title', 'status'],
            additionalProperties: false
          }
        }
      },
      required: ['items'],
      additionalProperties: false
    },
    actionFromInput(input) {
      return { todo: input as unknown as TodoAction };
    }
  },
  supports(action): action is { todo: TodoAction } {
    return isTodoAction((action as { todo?: unknown }).todo);
  },
  async execute(action, context): Promise<ToolResult> {
    try {
      const progress = await updatePlanProgress(context.cwd, context.session, {
        ...(action.todo.planId !== undefined ? { planId: action.todo.planId } : {}),
        items: action.todo.items
      });
      return todoResult(progress);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        tool: 'todo',
        status: 'error',
        meta: {
          ...(action.todo.planId ? { planId: action.todo.planId } : {}),
          error: message
        },
        content: `TOOL_RESULT todo ERROR\n${message}`
      };
    }
  }
};

function isTodoAction(value: unknown): value is TodoAction {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const todo = value as Partial<TodoAction> & {
    planId?: unknown;
    items?: unknown;
  };
  if (todo.planId !== undefined && typeof todo.planId !== 'string') return false;
  if (!Array.isArray(todo.items)) return false;
  return todo.items.every((raw) => parseTodoItemAction(raw) !== null);
}

function todoResult(progress: PlanProgress): ToolResult {
  const completed = progress.items.filter((item) => item.status === 'completed').length;
  const inProgress = progress.items.filter((item) => item.status === 'in_progress').length;
  const pending = progress.items.filter((item) => item.status === 'pending').length;
  return {
    tool: 'todo',
    status: 'ok',
    meta: {
      planId: progress.planId,
      title: progress.title,
      path: progress.paths.json,
      itemCount: progress.items.length,
      completed,
      inProgress,
      pending
    },
    content: [
      'TOOL_RESULT todo OK',
      `plan=${progress.planId}`,
      `items=${progress.items.length}`,
      `completed=${completed}`,
      `in_progress=${inProgress}`,
      `pending=${pending}`,
      '',
      'Todos have been modified successfully. Ensure that you continue to use the todo list to track your progress.',
      ...progress.items.map((item, index) => `${index + 1}. [${item.status}] ${item.title}`)
    ].join('\n')
  };
}
