import { DEFAULT_POLICY_MODE, MAX_LOOPS } from '../config.js';
import type { InstructionMessage } from '../instructions/types.js';
import type { ChatMessage, ModelClient } from '../model/types.js';
import { createPolicyEngine } from '../policy/engine.js';
import { parseModelAction } from '../protocol/actions.js';
import { appendRecord, makeId, nowIso, saveSession } from '../session/store.js';
import type { Session } from '../session/types.js';
import { createToolRegistry } from '../tools/registry.js';
import type { ToolResult } from '../tools/types.js';
import { runHooks, type RuntimeHook } from './hooks.js';

function buildChatMessages(session: Session, instructions: InstructionMessage[]): ChatMessage[] {
  return [
    ...instructions.map<ChatMessage>(({ role, content }) => ({ role, content })),
    ...session.records.map<ChatMessage>((record) =>
      record.kind === 'tool'
        ? { role: 'user', content: record.content }
        : { role: record.role, content: record.content }
    )
  ];
}

export function createRunner({
  model,
  registry = createToolRegistry(),
  hooks = [],
  policy = createPolicyEngine({ mode: DEFAULT_POLICY_MODE }),
  instructions = async () => []
}: {
  model: ModelClient;
  registry?: ReturnType<typeof createToolRegistry>;
  hooks?: RuntimeHook[];
  policy?: ReturnType<typeof createPolicyEngine>;
  instructions?: (session: Session) => Promise<InstructionMessage[]>;
}) {
  return {
    async runTurn(session: Session, userInput: string): Promise<string> {
      const cwd = session.cwd;
      try {
        session.lifecycle.status = 'running';
        session.lifecycle.turn += 1;
        session.lifecycle.lastUserInputAt = nowIso();
        await appendRecord(cwd, session, {
          id: makeId('usr'),
          ts: nowIso(),
          kind: 'user',
          role: 'user',
          content: userInput
        });

        await runHooks(hooks, 'beforeTurn', session, userInput);

        for (let i = 0; i < MAX_LOOPS; i += 1) {
          const rawContent = await model.complete(buildChatMessages(session, await instructions(session)));
          const action = parseModelAction(rawContent);

          session.lifecycle.lastAssistantOutputAt = nowIso();
          await appendRecord(cwd, session, {
            id: makeId('ast'),
            ts: nowIso(),
            kind: 'assistant',
            role: 'assistant',
            content: rawContent,
            action
          });

          await runHooks(hooks, 'afterAssistantAction', session, action, rawContent);

          if ('message' in action) {
            const finalMessage = action.message.trim() || '(no content)';
            await runHooks(hooks, 'afterTurn', session, finalMessage);
            return finalMessage;
          }

          const { definition } = registry.resolve(action);
          let result: ToolResult | null = null;
          let authorization: Awaited<ReturnType<typeof policy.authorize>> | null = null;

          try {
            authorization = await policy.authorize(definition);
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            result = {
              tool: definition.name,
              status: 'error',
              content: `TOOL_RESULT ${definition.name} ERROR\npolicy=${policy.mode}\n${message}`,
              meta: {
                policy: policy.mode,
                error: error instanceof Error ? (error.stack ?? error.message) : message
              }
            };
          }

          if (result === null && authorization !== null && !authorization.allowed) {
            result = {
              tool: definition.name,
              status: 'error',
              content: `TOOL_RESULT ${definition.name} ERROR\npolicy=${policy.mode}\n${authorization.reason}`,
              meta: {
                policy: policy.mode
              }
            };
          } else if (result === null && authorization !== null) {
            await runHooks(hooks, 'beforeTool', session, action);
            try {
              result = await definition.execute(action as never, { cwd, session });
            } catch (error) {
              const message = error instanceof Error ? error.message : String(error);
              result = {
                tool: definition.name,
                status: 'error',
                content: `TOOL_RESULT ${definition.name} ERROR\n${message}`,
                meta: {
                  error: error instanceof Error ? (error.stack ?? error.message) : message
                }
              };
            }
          }

          if (result === null) {
            throw new Error(`No tool result produced for ${definition.name}`);
          }

          await appendRecord(cwd, session, {
            id: makeId('tool'),
            ts: nowIso(),
            kind: 'tool',
            role: 'user',
            tool: result.tool,
            status: result.status,
            content: result.content,
            meta: result.meta
          });
          await runHooks(hooks, 'afterTool', session, result);
        }

        throw new Error('Exceeded action loop limit');
      } finally {
        session.lifecycle.status = 'idle';
        await saveSession(cwd, session);
      }
    }
  };
}
