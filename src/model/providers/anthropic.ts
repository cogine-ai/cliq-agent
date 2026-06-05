import { fetchWithTimeout, joinUrl, readJsonResponse, readSseDeltas } from '../http.js';
import { emitModelErrorEvent } from '../events.js';
import { isModelPromptRequest } from '../prompt.js';
import type { ChatMessage, ModelClient, ModelCompleteOptions, ModelCompleteRequest, ModelPromptRequest, ResolvedModelConfig } from '../types.js';
import {
  effectiveTypedRequest,
  maybeParseStructuredOutput,
  selectTypedRequestMode,
  toolSpecsToAnthropicTools,
  typedPromptToAnthropicInput
} from './prompt-mapping.js';

type AnthropicResp = {
  content: Array<{ type: string; text?: string; id?: string; name?: string; input?: unknown }>;
};

type AnthropicToolCallPart = {
  id?: string;
  name?: string;
  inputJson: string;
};

function splitMessages(messages: ChatMessage[]) {
  const system = messages
    .filter((message) => message.role === 'system')
    .map((message) => message.content)
    .join('\n\n');
  const rest = messages
    .filter((message) => message.role !== 'system')
    .map((message) => ({ role: message.role, content: message.content }));
  return { system, messages: rest };
}

function messagesUrl(baseUrl: string) {
  return baseUrl.replace(/\/+$/, '').endsWith('/v1')
    ? joinUrl(baseUrl, '/messages')
    : joinUrl(baseUrl, '/v1/messages');
}

function typedRequestShouldStream(request: ModelPromptRequest) {
  return request.streaming.mode !== 'off' && request.providerCapabilities.streaming;
}

function typedBody(config: ResolvedModelConfig, request: ModelPromptRequest, stream: boolean) {
  const mode = selectTypedRequestMode(request);
  const body = typedPromptToAnthropicInput(request, mode);
  return {
    mode,
    body: {
      model: config.model,
      max_tokens: config.maxOutputTokens ?? 4096,
      ...(body.system ? { system: body.system } : {}),
      messages: body.messages,
      stream,
      ...(mode === 'native-tools' ? { tools: toolSpecsToAnthropicTools(request.toolSpecs) } : {})
    }
  };
}

function parseAnthropicToolInput(value: string) {
  if (!value.trim()) return {};
  const parsed = JSON.parse(value) as unknown;
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
}

function captureAnthropicStreamDeltas(json: unknown, toolParts: Map<number, AnthropicToolCallPart>) {
  const event = json as {
    type?: string;
    index?: number;
    content_block?: {
      type?: string;
      id?: string;
      name?: string;
      input?: unknown;
    };
    delta?: {
      type?: string;
      text?: string;
      partial_json?: string;
    };
  };
  if (event.type === 'content_block_start' && event.content_block?.type === 'tool_use') {
    const index = typeof event.index === 'number' ? event.index : toolParts.size;
    const input = event.content_block.input;
    toolParts.set(index, {
      id: event.content_block.id,
      name: event.content_block.name,
      inputJson:
        input && typeof input === 'object' && !Array.isArray(input) && Object.keys(input).length > 0
          ? JSON.stringify(input)
          : ''
    });
    return null;
  }

  if (event.type === 'content_block_delta' && event.delta?.type === 'input_json_delta') {
    const index = typeof event.index === 'number' ? event.index : toolParts.size;
    const existing = toolParts.get(index) ?? { inputJson: '' };
    toolParts.set(index, {
      ...existing,
      inputJson: existing.inputJson + (event.delta.partial_json ?? '')
    });
    return null;
  }

  if (event.type === 'content_block_delta' && event.delta?.type === 'text_delta') {
    return event.delta.text ?? null;
  }

  return null;
}

function anthropicToolCallsFromParts(toolParts: Map<number, AnthropicToolCallPart>) {
  return [...toolParts.entries()]
    .sort(([left], [right]) => left - right)
    .filter(([, part]) => typeof part.id === 'string' && typeof part.name === 'string')
    .map(([, part]) => ({
      id: part.id!,
      name: part.name!,
      arguments: parseAnthropicToolInput(part.inputJson)
    }));
}

async function completeTypedWithoutStreaming(config: ResolvedModelConfig, request: ModelPromptRequest, options?: ModelCompleteOptions) {
  const { mode, body } = typedBody(config, request, false);

  await options?.onEvent?.({
    type: 'start',
    provider: config.provider,
    model: config.model,
    streaming: false
  });

  const response = await fetchWithTimeout(messagesUrl(config.baseUrl), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': config.apiKey ?? '',
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify(body),
    signal: options?.signal
  });

  const json = await readJsonResponse<AnthropicResp>(response, 'Anthropic');
  if (!Array.isArray(json.content)) {
    throw new Error(`Anthropic response missing or invalid content array: ${JSON.stringify(json)}`);
  }
  const toolCalls = json.content
    .filter((block) => block.type === 'tool_use' && typeof block.id === 'string' && typeof block.name === 'string')
    .map((block) => ({
      id: block.id!,
      name: block.name!,
      arguments:
        block.input && typeof block.input === 'object' && !Array.isArray(block.input)
          ? (block.input as Record<string, unknown>)
          : {}
    }));
  const content =
    json.content
      .find((block) => block.type === 'text' && typeof block.text === 'string')
      ?.text?.trim() ?? '';
  if (!content && toolCalls.length === 0) {
    throw new Error(`Anthropic response missing text/tool content: ${JSON.stringify(json)}`);
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
  const { mode, body } = typedBody(config, request, true);
  await options?.onEvent?.({
    type: 'start',
    provider: config.provider,
    model: config.model,
    streaming: true
  });

  const response = await fetchWithTimeout(messagesUrl(config.baseUrl), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': config.apiKey ?? '',
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify(body),
    signal: options?.signal
  });

  const toolParts = new Map<number, AnthropicToolCallPart>();
  const content = (
    await readSseDeltas(
      response,
      (json) => captureAnthropicStreamDeltas(json, toolParts),
      async (text) => options?.onEvent?.({ type: 'text-delta', text }),
      { signal: options?.signal }
    )
  ).trim();
  const toolCalls = anthropicToolCallsFromParts(toolParts);
  if (!content && toolCalls.length === 0) {
    throw new Error('Anthropic stream missing text/tool content');
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

export function createAnthropicClient(config: ResolvedModelConfig): ModelClient {
  return {
    async complete(request: ModelCompleteRequest, options?: ModelCompleteOptions) {
      const body = Array.isArray(request) ? splitMessages(request) : null;

      try {
        if (!config.apiKey) {
          throw new Error('ANTHROPIC_API_KEY is required');
        }

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
          const response = await fetchWithTimeout(messagesUrl(config.baseUrl), {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'x-api-key': config.apiKey,
              'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
              model: config.model,
              max_tokens: config.maxOutputTokens ?? 4096,
              ...(body?.system ? { system: body.system } : {}),
              messages: body?.messages ?? [],
              stream: true
            }),
            signal: options?.signal
          });

          const content = (
            await readSseDeltas(
              response,
              (json) => {
                const event = json as { type?: string; delta?: { type?: string; text?: string } };
                return event.type === 'content_block_delta' && event.delta?.type === 'text_delta'
                  ? (event.delta.text ?? null)
                  : null;
              },
              async (text) => options?.onEvent?.({ type: 'text-delta', text }),
              { signal: options?.signal }
            )
          ).trim();

          if (!content) {
            throw new Error('Anthropic stream missing text content');
          }

          await options?.onEvent?.({ type: 'end' });
          return {
            content,
            provider: config.provider,
            model: config.model
          };
        }

        const response = await fetchWithTimeout(messagesUrl(config.baseUrl), {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-api-key': config.apiKey,
            'anthropic-version': '2023-06-01'
          },
          body: JSON.stringify({
            model: config.model,
            max_tokens: config.maxOutputTokens ?? 4096,
            ...(body?.system ? { system: body.system } : {}),
            messages: body?.messages ?? [],
            stream: false
          }),
          signal: options?.signal
        });

        const json = await readJsonResponse<AnthropicResp>(response, 'Anthropic');
        if (!Array.isArray(json.content)) {
          throw new Error(`Anthropic response missing or invalid content array: ${JSON.stringify(json)}`);
        }

        const content = json.content
          .find((block) => block.type === 'text' && typeof block.text === 'string')
          ?.text?.trim();
        if (!content) {
          throw new Error(`Anthropic response missing text content: ${JSON.stringify(json)}`);
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
