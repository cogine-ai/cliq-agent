import { fetchWithTimeout, joinUrl, readJsonResponse, readNdjsonDeltas } from '../http.js';
import { emitModelErrorEvent } from '../events.js';
import { isModelPromptRequest } from '../prompt.js';
import type { ChatMessage, ModelClient, ModelCompleteOptions, ModelCompleteRequest, ModelPromptRequest, ResolvedModelConfig } from '../types.js';
import {
  effectiveTypedRequest,
  maybeParseStructuredOutput,
  parseOllamaToolCalls,
  selectTypedRequestMode,
  toolSpecsToOpenAIChatTools,
  typedPromptToOpenAIMessages,
  typedRequestShouldStream
} from './prompt-mapping.js';

type OllamaResp = {
  message?: {
    content?: string;
    tool_calls?: Array<{
      id?: string;
      function?: {
        name?: string;
        arguments?: unknown;
      };
    }>;
  };
};

type OllamaToolCallPart = {
  id?: string;
  function?: {
    name?: string;
    arguments?: unknown;
  };
};

function typedChatBody(request: ModelPromptRequest, mode: ReturnType<typeof selectTypedRequestMode>, stream: boolean) {
  return {
    model: request.model.model,
    messages: typedPromptToOpenAIMessages(request, mode),
    stream,
    ...(mode === 'native-tools' ? { tools: toolSpecsToOpenAIChatTools(request.toolSpecs) } : {}),
    ...(mode === 'structured-output' ? { format: request.outputSchema.schema } : {})
  };
}

function mergeOllamaToolArguments(current: unknown, next: unknown) {
  if (typeof current === 'string' && typeof next === 'string') {
    return current + next;
  }
  return next ?? current;
}

function captureOllamaToolCalls(message: OllamaResp['message'], parts: Map<number, OllamaToolCallPart>) {
  for (const [index, call] of (message?.tool_calls ?? []).entries()) {
    const existing = parts.get(index) ?? {};
    parts.set(index, {
      ...existing,
      ...call,
      function: {
        ...existing.function,
        ...call.function,
        arguments: mergeOllamaToolArguments(existing.function?.arguments, call.function?.arguments)
      }
    });
  }
}

async function completeTypedWithoutStreaming(config: ResolvedModelConfig, request: ModelPromptRequest, options?: ModelCompleteOptions) {
  const mode = selectTypedRequestMode(request);
  await options?.onEvent?.({
    type: 'start',
    provider: config.provider,
    model: config.model,
    streaming: false
  });

  const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/api/chat'), {
    method: 'POST',
    headers: {
      'content-type': 'application/json'
    },
    body: JSON.stringify(typedChatBody(request, mode, false)),
    signal: options?.signal
  });

  const json = await readJsonResponse<OllamaResp>(response, 'Ollama');
  const message = json.message;
  if (!message) {
    throw new Error(`Ollama response missing message: ${JSON.stringify(json)}`);
  }
  const toolCalls = parseOllamaToolCalls(message);
  const content = message.content?.trim() ?? '';
  if (!content && toolCalls.length === 0) {
    throw new Error(`Ollama response missing message/content: ${JSON.stringify(json)}`);
  }
  const structuredOutput = content ? maybeParseStructuredOutput(mode, content) : undefined;

  await options?.onEvent?.({ type: 'end' });
  return {
    content,
    provider: config.provider,
    model: config.model,
    ...(toolCalls.length > 0 ? { toolCalls } : {}),
    ...(structuredOutput ? { structuredOutput } : {}),
    effectiveRequest: effectiveTypedRequest(request, mode, false)
  };
}

async function completeTypedWithStreaming(config: ResolvedModelConfig, request: ModelPromptRequest, options?: ModelCompleteOptions) {
  const mode = selectTypedRequestMode(request);
  await options?.onEvent?.({
    type: 'start',
    provider: config.provider,
    model: config.model,
    streaming: true
  });

  const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/api/chat'), {
    method: 'POST',
    headers: {
      'content-type': 'application/json'
    },
    body: JSON.stringify(typedChatBody(request, mode, true)),
    signal: options?.signal
  });

  const toolCallParts = new Map<number, OllamaToolCallPart>();
  const content = (
    await readNdjsonDeltas(
      response,
      (json) => {
        const message = (json as OllamaResp).message;
        captureOllamaToolCalls(message, toolCallParts);
        return message?.content ?? null;
      },
      async (text) => options?.onEvent?.({ type: 'text-delta', text }),
      { signal: options?.signal }
    )
  ).trim();
  const toolCalls = parseOllamaToolCalls({ tool_calls: [...toolCallParts.entries()].sort(([left], [right]) => left - right).map(([, call]) => call) });
  if (!content && toolCalls.length === 0) {
    throw new Error('Ollama stream missing message/tool content');
  }
  const structuredOutput = content ? maybeParseStructuredOutput(mode, content) : undefined;

  await options?.onEvent?.({ type: 'end' });
  return {
    content,
    provider: config.provider,
    model: config.model,
    ...(toolCalls.length > 0 ? { toolCalls } : {}),
    ...(structuredOutput ? { structuredOutput } : {}),
    effectiveRequest: effectiveTypedRequest(request, mode, true)
  };
}

export function createOllamaClient(config: ResolvedModelConfig): ModelClient {
  return {
    async complete(request: ModelCompleteRequest, options?: ModelCompleteOptions) {
      try {
        if (isModelPromptRequest(request)) {
          if (typedRequestShouldStream(request)) {
            return await completeTypedWithStreaming(config, request, options);
          }
          return await completeTypedWithoutStreaming(config, request, options);
        }

        await options?.onEvent?.({
          type: 'start',
          provider: config.provider,
          model: config.model,
          streaming: config.streaming !== 'off'
        });

        if (config.streaming !== 'off') {
          const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/api/chat'), {
            method: 'POST',
            headers: {
              'content-type': 'application/json'
            },
            body: JSON.stringify({
              model: config.model,
              messages: request,
              stream: true
            }),
            signal: options?.signal
          });

          const content = (
            await readNdjsonDeltas(
              response,
              (json) => {
                const event = json as { message?: { content?: string } };
                return event.message?.content ?? null;
              },
              async (text) => options?.onEvent?.({ type: 'text-delta', text }),
              { signal: options?.signal }
            )
          ).trim();

          if (!content) {
            throw new Error('Ollama stream missing message/content');
          }

          await options?.onEvent?.({ type: 'end' });
          return {
            content,
            provider: config.provider,
            model: config.model
          };
        }

        const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/api/chat'), {
          method: 'POST',
          headers: {
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            model: config.model,
            messages: request,
            stream: false
          }),
          signal: options?.signal
        });

        const json = await readJsonResponse<OllamaResp>(response, 'Ollama');
        const content = json.message?.content?.trim();
        if (!content) {
          throw new Error(`Ollama response missing message/content: ${JSON.stringify(json)}`);
        }

        await options?.onEvent?.({ type: 'end' });
        return {
          content,
          provider: config.provider,
          model: config.model
        };
      } catch (error) {
        await emitModelErrorEvent(options, error);
        throw error;
      }
    }
  };
}
