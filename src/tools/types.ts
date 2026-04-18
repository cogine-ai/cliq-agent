import type { EditAction, ModelAction } from '../protocol/actions.js';
import type { ToolAccess } from '../policy/types.js';
import type { Session } from '../session/types.js';

export type ToolStatus = 'ok' | 'error';

export type ToolResult = {
  tool: string;
  status: ToolStatus;
  content: string;
  meta: Record<string, string | number | boolean | null>;
};

export type ToolContext = {
  cwd: string;
  session: Session;
};

export type ToolDefinition<TAction extends ModelAction = ModelAction> = {
  name: string;
  access: ToolAccess;
  supports(action: ModelAction): action is TAction;
  execute(action: TAction, context: ToolContext): Promise<ToolResult>;
};

export type EditModelAction = { edit: EditAction };
