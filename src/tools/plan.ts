import type { PlanAction } from '../protocol/model/actions.js';
import { createDraftPlan, finalizePlan, updatePlan } from '../plans/store.js';
import type { PlanArtifact } from '../plans/types.js';
import type { ToolDefinition, ToolResult } from './types.js';

export const planTool: ToolDefinition<{ plan: PlanAction }> = {
  name: 'plan',
  access: 'plan',
  supports(action): action is { plan: PlanAction } {
    return typeof (action as { plan?: unknown }).plan === 'object' && !!(action as { plan?: unknown }).plan;
  },
  async execute(action, context): Promise<ToolResult> {
    try {
      const artifact =
        action.plan.op === 'draft'
          ? await createDraftPlan(context.cwd, context.session, {
              title: action.plan.title,
              contentMarkdown: action.plan.content
            })
          : action.plan.op === 'update'
            ? await updatePlan(context.cwd, context.session, {
                ...(action.plan.planId !== undefined ? { planId: action.plan.planId } : {}),
                ...(action.plan.title !== undefined ? { title: action.plan.title } : {}),
                contentMarkdown: action.plan.content
              })
            : await finalizePlan(context.cwd, context.session, {
                ...(action.plan.planId !== undefined ? { planId: action.plan.planId } : {})
              });

      return planResult(action.plan.op, artifact);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        tool: 'plan',
        status: 'error',
        meta: {
          op: action.plan.op,
          ...('planId' in action.plan && action.plan.planId ? { planId: action.plan.planId } : {}),
          error: message
        },
        content: `TOOL_RESULT plan ERROR\nop=${action.plan.op}\n${message}`
      };
    }
  }
};

function planResult(op: PlanAction['op'], artifact: PlanArtifact): ToolResult {
  return {
    tool: 'plan',
    status: 'ok',
    meta: {
      op,
      planId: artifact.id,
      planStatus: artifact.status,
      title: artifact.title,
      path: artifact.paths.json
    },
    content: [
      'TOOL_RESULT plan OK',
      `plan=${artifact.id}`,
      `status=${artifact.status}`,
      `title=${artifact.title}`,
      `artifact=${artifact.paths.json}`,
      '',
      artifact.contentMarkdown
    ].join('\n')
  };
}
