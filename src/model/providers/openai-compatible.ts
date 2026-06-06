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

type ChatCompletionsResp = {
  choices: Array<{
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
  }>;
};

type CompleteOptions = ModelCompleteOptions;

const AUTO_STREAM_FALLBACK_STATUSES = new Set([400, 404, 405, 415, 422]);

function headers(config: ResolvedModelConfig) {
  return {
    'content-type': 'application/json',
    ...(config.apiKey ? { authorization: `Bearer ${config.apiKey}` } : {})
  };
}

function shouldFallbackFromStreamingResponse(response: Response) {
  return AUTO_STREAM_FALLBACK_STATUSES.has(response.status);
}

async function streamHttpError(response: Response) {
  const body = (await response.text()).trim();
  const detail = body ? `: ${body}` : '';
  return new Error(
    `Model stream error ${response.status}${detail}. If this endpoint does not support streaming, retry with --streaming off.`
  );
}

async function emitStartEvent(config: ResolvedModelConfig, options: CompleteOptions | undefined, streaming: boolean) {
  await options?.onEvent?.({
    type: 'start',
    provider: config.provider,
    model: config.model,
    streaming
  });
}

function parseContent(json: ChatCompletionsResp, provider: string) {
  if (!Array.isArray(json.choices) || json.choices.length === 0) {
    throw new Error(`${provider} response missing choices/content: ${JSON.stringify(json)}`);
  }

  const content = json.choices[0]?.message?.content?.trim();
  if (!content) {
    throw new Error(`${provider} response missing choices/content: ${JSON.stringify(json)}`);
  }

  return content;
}

async function completeWithoutStreaming(config: ResolvedModelConfig, messages: ChatMessage[], options?: CompleteOptions) {
  await emitStartEvent(config, options, false);

  const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/chat/completions'), {
    method: 'POST',
    headers: headers(config),
    body: JSON.stringify({
      model: config.model,
      messages,
      stream: false
    }),
    signal: options?.signal
  });

  const json = await readJsonResponse<ChatCompletionsResp>(response, config.provider);
  const content = parseContent(json, config.provider);

  await options?.onEvent?.({ type: 'end' });
  return {
    content,
    provider: config.provider,
    model: config.model
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

async function completeTypedWithoutStreaming(config: ResolvedModelConfig, request: ModelPromptRequest, options?: CompleteOptions) {
  const mode = selectTypedRequestMode(request);
  await emitStartEvent(config, options, false);
  const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/chat/completions'), {
    method: 'POST',
    headers: headers(config),
    body: JSON.stringify(typedChatBody(request, mode, false)),
    signal: options?.signal
  });

  const json = await readJsonResponse<ChatCompletionsResp>(response, config.provider);
  const message = json.choices?.[0]?.message;
  if (!message) {
    throw new Error(`${config.provider} response missing choices/message: ${JSON.stringify(json)}`);
  }
  const toolCalls = parseOpenAIToolCalls(message);
  const content = message.content?.trim() ?? '';
  if (!content && toolCalls.length === 0) {
    throw new Error(`${config.provider} response missing choices/content: ${JSON.stringify(json)}`);
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

async function completeTypedWithStreaming(config: ResolvedModelConfig, request: ModelPromptRequest, options?: CompleteOptions) {
  const mode = selectTypedRequestMode(request);
  if (request.streaming.mode === 'on') {
    await emitStartEvent(config, options, true);
  }

  const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/chat/completions'), {
    method: 'POST',
    headers: headers(config),
    body: JSON.stringify(typedChatBody(request, mode, true)),
    signal: options?.signal
  });

  if (!response.ok) {
    if (request.streaming.mode === 'auto' && shouldFallbackFromStreamingResponse(response)) {
      await response.body?.cancel();
      return completeTypedWithoutStreaming(config, request, options);
    }

    throw await streamHttpError(response);
  }

  if (request.streaming.mode === 'auto') {
    await emitStartEvent(config, options, true);
  }

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
    throw new Error(`${config.provider} stream missing text/tool content`);
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

async function completeWithStreaming(config: ResolvedModelConfig, messages: ChatMessage[], options?: CompleteOptions) {
  if (config.streaming === 'on') {
    await emitStartEvent(config, options, true);
  }

  const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/chat/completions'), {
    method: 'POST',
    headers: headers(config),
    body: JSON.stringify({
      model: config.model,
      messages,
      stream: true
    }),
    signal: options?.signal
  });

  if (!response.ok) {
    if (config.streaming === 'auto' && shouldFallbackFromStreamingResponse(response)) {
      await response.body?.cancel();
      return completeWithoutStreaming(config, messages, options);
    }

    throw await streamHttpError(response);
  }

  if (config.streaming === 'auto') {
    await emitStartEvent(config, options, true);
  }

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
    throw new Error(`${config.provider} stream missing text content`);
  }

  await options?.onEvent?.({ type: 'end' });
  return {
    content,
    provider: config.provider,
    model: config.model
  };
}

export function createOpenAICompatibleClient(config: ResolvedModelConfig): ModelClient {
  return {
    async complete(request: ModelCompleteRequest, options?: CompleteOptions) {
      try {
        if (isModelPromptRequest(request)) {
          if (typedRequestShouldStream(request)) {
            return await completeTypedWithStreaming(config, request, options);
          }
          return await completeTypedWithoutStreaming(config, request, options);
        }

        if (config.streaming !== 'off') {
          return await completeWithStreaming(config, request, options);
        }

        return await completeWithoutStreaming(config, request, options);
      } catch (error) {
        await emitModelErrorEvent(options, error);
        throw error;
      }
    }
  };
}
