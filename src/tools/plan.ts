import { parsePlanItemAction, type PlanAction } from '../protocol/model/actions.js';
import { createDraftPlan, finalizePlan, updatePlan } from '../plans/store.js';
import type { PlanArtifact } from '../plans/types.js';
import type { ToolDefinition, ToolResult } from './types.js';

export const planTool: ToolDefinition<{ plan: PlanAction }> = {
  name: 'plan',
  access: 'plan',
  modelSpec: {
    name: 'plan',
    description: 'Create, update, or finalize a persisted plan artifact.',
    inputSchema: {
      type: 'object',
      properties: {
        op: { type: 'string', enum: ['draft', 'update', 'finalize'] },
        planId: { type: 'string' },
        title: { type: 'string' },
        content: { type: 'string' },
        items: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              title: { type: 'string' },
              status: { type: 'string', enum: ['pending', 'in_progress', 'completed'] },
              notes: { type: 'string' }
            },
            required: ['title'],
            additionalProperties: false
          }
        }
      },
      required: ['op'],
      additionalProperties: false
    },
    actionFromInput(input) {
      return { plan: input as unknown as PlanAction };
    }
  },
  supports(action): action is { plan: PlanAction } {
    return isPlanAction((action as { plan?: unknown }).plan);
  },
  async execute(action, context): Promise<ToolResult> {
    try {
      let artifact: PlanArtifact;
      switch (action.plan.op) {
        case 'draft':
          artifact = await createDraftPlan(context.cwd, context.session, {
            title: action.plan.title,
            contentMarkdown: action.plan.content,
            ...(action.plan.items !== undefined ? { items: action.plan.items } : {})
          });
          break;
        case 'update':
          artifact = await updatePlan(context.cwd, context.session, {
            ...(action.plan.planId !== undefined ? { planId: action.plan.planId } : {}),
            ...(action.plan.title !== undefined ? { title: action.plan.title } : {}),
            contentMarkdown: action.plan.content,
            ...(action.plan.items !== undefined ? { items: action.plan.items } : {})
          });
          break;
        case 'finalize':
          artifact = await finalizePlan(context.cwd, context.session, {
            ...(action.plan.planId !== undefined ? { planId: action.plan.planId } : {})
          });
          break;
        default:
          return invalidPlanResult((action.plan as { op?: unknown }).op);
      }

      return planResult(action.plan.op, artifact);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        tool: 'plan',
        status: 'error',
        meta: {
          op: String((action.plan as { op?: unknown }).op ?? ''),
          ...('planId' in action.plan && action.plan.planId ? { planId: action.plan.planId } : {}),
          error: message
        },
        content: `TOOL_RESULT plan ERROR\nop=${String((action.plan as { op?: unknown }).op ?? '')}\n${message}`
      };
    }
  }
};

function isPlanAction(value: unknown): value is PlanAction {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const plan = value as Partial<PlanAction> & {
    op?: unknown;
    planId?: unknown;
    title?: unknown;
    content?: unknown;
    items?: unknown;
  };
  if (plan.op === 'draft') {
    return typeof plan.title === 'string' && typeof plan.content === 'string' && isPlanItemActionArray(plan.items);
  }
  if (plan.op === 'update') {
    return (
      (plan.planId === undefined || typeof plan.planId === 'string') &&
      (plan.title === undefined || typeof plan.title === 'string') &&
      typeof plan.content === 'string' &&
      isPlanItemActionArray(plan.items)
    );
  }
  if (plan.op === 'finalize') {
    return plan.planId === undefined || typeof plan.planId === 'string';
  }
  return false;
}

function invalidPlanResult(op: unknown): ToolResult {
  const message = `unsupported plan op: ${String(op)}`;
  return {
    tool: 'plan',
    status: 'error',
    meta: {
      op: String(op ?? ''),
      error: message
    },
    content: `TOOL_RESULT plan ERROR\nop=${String(op ?? '')}\n${message}`
  };
}

function isPlanItemActionArray(value: unknown): boolean {
  if (value === undefined) return true;
  if (!Array.isArray(value)) return false;
  return value.every((raw) => parsePlanItemAction(raw) !== null);
}

function planResult(op: PlanAction['op'], artifact: PlanArtifact): ToolResult {
  return {
    tool: 'plan',
    status: 'ok',
    meta: {
      op,
      planId: artifact.id,
      planStatus: artifact.status,
      title: artifact.title,
      path: artifact.paths.json,
      planFile: artifact.paths.markdown,
      markdownPath: artifact.paths.markdown,
      itemCount: artifact.items.length
    },
    content: [
      'TOOL_RESULT plan OK',
      `plan=${artifact.id}`,
      `status=${artifact.status}`,
      `title=${artifact.title}`,
      `artifact=${artifact.paths.json}`,
      `planFile=${artifact.paths.markdown}`,
      `items=${artifact.items.length}`,
      '',
      artifact.contentMarkdown
    ].join('\n')
  };
}
