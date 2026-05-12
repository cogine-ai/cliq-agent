import type { EditAction, ModelAction } from '../protocol/model/actions.js';
import type { ToolAccess } from '../policy/types.js';
import type { WorkspaceWriter } from '../runtime/workspace-writer.js';
import type { Session } from '../session/types.js';
import type { TxBashPolicy } from '../workspace/config.js';
import type { BashEffect } from '../workspace/transactions/types.js';

export type ToolStatus = 'ok' | 'error';

export type ToolResult = {
  tool: string;
  status: ToolStatus;
  content: string;
  meta: Record<string, string | number | boolean | null>;
};

export type ToolContextTxFacade = {
  mode: 'edit';
  bashPolicy: TxBashPolicy;
  txId: string;
  headless: boolean;
  recordBashEffect(eff: BashEffect): Promise<void>;
};

export type ToolContext = {
  cwd: string;
  session: Session;
  signal?: AbortSignal;
  writer?: WorkspaceWriter;
  tx?: ToolContextTxFacade;
};

export type ToolDefinition<TAction extends ModelAction = ModelAction> = {
  name: string;
  access: ToolAccess;
  supports(action: ModelAction): action is TAction;
  execute(action: TAction, context: ToolContext): Promise<ToolResult>;
};

export type EditModelAction = { edit: EditAction };
