import { fetchWithTimeout, joinUrl, readJsonResponse, readSseDeltas } from '../http.js';
import { emitModelErrorEvent } from '../events.js';
import { isModelPromptRequest } from '../prompt.js';
import type { ChatMessage, ModelClient, ModelCompleteOptions, ModelCompleteRequest, ModelPromptRequest, ResolvedModelConfig } from '../types.js';
import {
  captureOpenAIToolCallDeltas,
  effectiveTypedRequest,
  maybeParseStructuredOutput,
  openAIToolCallsFromDeltaParts,
  openAIJsonSchemaResponseFormat,
  parseOpenAIToolCalls,
  selectTypedRequestMode,
  toolSpecsToOpenAIChatTools,
  typedPromptToOpenAIMessages
} from './prompt-mapping.js';

type OpenRouterResp = {
  choices: Array<{
    message?: {
      role?: 'assistant';
      content?: string;
      tool_calls?: Array<{
        id?: string;
        function?: {
          name?: string;
          arguments?: unknown;
        };
      }>;
    };
  }>;
};

function openRouterHeaders(config: ResolvedModelConfig) {
  return {
    'content-type': 'application/json',
    authorization: `Bearer ${config.apiKey}`,
    'HTTP-Referer': 'https://local.cliq',
    'X-Title': 'cliq-agent'
  };
}

function typedRequestShouldStream(request: ModelPromptRequest) {
  return request.streaming.mode !== 'off' && request.providerCapabilities.streaming;
}

function typedChatBody(request: ModelPromptRequest, mode: ReturnType<typeof selectTypedRequestMode>, stream: boolean) {
  return {
    model: request.model.model,
    messages: typedPromptToOpenAIMessages(request, mode),
    stream,
    ...(mode === 'native-tools'
      ? {
          tools: toolSpecsToOpenAIChatTools(request.toolSpecs),
          tool_choice: 'auto'
        }
      : {}),
    ...(mode === 'structured-output' ? { response_format: openAIJsonSchemaResponseFormat(request) } : {})
  };
}

async function completeTypedWithoutStreaming(config: ResolvedModelConfig, request: ModelPromptRequest, options?: ModelCompleteOptions) {
  const mode = selectTypedRequestMode(request);
  await options?.onEvent?.({
    type: 'start',
    provider: config.provider,
    model: config.model,
    streaming: false
  });

  const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/chat/completions'), {
    method: 'POST',
    headers: openRouterHeaders(config),
    body: JSON.stringify(typedChatBody(request, mode, false)),
    signal: options?.signal
  });

  const json = await readJsonResponse<OpenRouterResp>(response, 'OpenRouter');
  const message = json.choices?.[0]?.message;
  if (!message) {
    throw new Error(`OpenRouter response missing choices/message: ${JSON.stringify(json)}`);
  }
  const toolCalls = parseOpenAIToolCalls(message);
  const content = message.content?.trim() ?? '';
  if (!content && toolCalls.length === 0) {
    throw new Error(`OpenRouter response missing choices/content: ${JSON.stringify(json)}`);
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

  const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/chat/completions'), {
    method: 'POST',
    headers: openRouterHeaders(config),
    body: JSON.stringify(typedChatBody(request, mode, true)),
    signal: options?.signal
  });

  const toolCallParts = new Map();
  const content = (
    await readSseDeltas(
      response,
      (json) => captureOpenAIToolCallDeltas(json, toolCallParts),
      async (text) => options?.onEvent?.({ type: 'text-delta', text }),
      { signal: options?.signal }
    )
  ).trim();
  const toolCalls = openAIToolCallsFromDeltaParts(toolCallParts);
  if (!content && toolCalls.length === 0) {
    throw new Error('OpenRouter stream missing text/tool content');
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

export function createOpenRouterClient(config: ResolvedModelConfig): ModelClient {
  return {
    async complete(request: ModelCompleteRequest, options?: ModelCompleteOptions) {
      if (!config.apiKey) {
        const error = new Error('OPENROUTER_API_KEY is required');
        await emitModelErrorEvent(options, error);
        throw error;
      }

      if (isModelPromptRequest(request)) {
        try {
          if (typedRequestShouldStream(request)) {
            return await completeTypedWithStreaming(config, request, options);
          }
          return await completeTypedWithoutStreaming(config, request, options);
        } catch (error) {
          await emitModelErrorEvent(options, error);
          throw error;
        }
      }

      await options?.onEvent?.({
        type: 'start',
        provider: config.provider,
        model: config.model,
        streaming: config.streaming !== 'off'
      });

      try {
        if (config.streaming !== 'off') {
          const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/chat/completions'), {
            method: 'POST',
            headers: openRouterHeaders(config),
            body: JSON.stringify({
              model: config.model,
              messages: request,
              stream: true
            }),
            signal: options?.signal
          });

          const content = (
            await readSseDeltas(
              response,
              (json) => {
                const choice = (json as { choices?: Array<{ delta?: { content?: string } }> }).choices?.[0];
                return choice?.delta?.content ?? null;
              },
              async (text) => options?.onEvent?.({ type: 'text-delta', text }),
              { signal: options?.signal }
            )
          ).trim();

          if (!content) {
            throw new Error('OpenRouter stream missing text content');
          }

          await options?.onEvent?.({ type: 'end' });
          return {
            content,
            provider: config.provider,
            model: config.model
          };
        }

        const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/chat/completions'), {
          method: 'POST',
          headers: openRouterHeaders(config),
          body: JSON.stringify({
            model: config.model,
            messages: request,
            stream: false
          }),
          signal: options?.signal
        });

        const json = await readJsonResponse<OpenRouterResp>(response, 'OpenRouter');
        const content = json.choices[0]?.message?.content?.trim();
        if (!content) {
          throw new Error(`OpenRouter response missing choices/content: ${JSON.stringify(json)}`);
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
