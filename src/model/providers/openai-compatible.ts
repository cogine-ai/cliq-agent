import { fetchWithTimeout, joinUrl, readJsonResponse, readSseDeltas } from '../http.js';
import type { ChatMessage, ModelClient, ModelStreamEvent, ResolvedModelConfig } from '../types.js';

type ChatCompletionsResp = {
  choices: Array<{
    message?: {
      content?: string;
    };
  }>;
};

type CompleteOptions = {
  onEvent?: (event: ModelStreamEvent) => void | Promise<void>;
};

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

async function emitErrorEvent(options: CompleteOptions | undefined, error: unknown) {
  try {
    await options?.onEvent?.({
      type: 'error',
      message: error instanceof Error ? error.message : String(error)
    });
  } catch {
    // Preserve the original provider failure even if the event sink fails.
  }
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
    })
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
    })
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
      async (text) => options?.onEvent?.({ type: 'text-delta', text })
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
    async complete(messages: ChatMessage[], options?: CompleteOptions) {
      try {
        if (config.streaming !== 'off') {
          return await completeWithStreaming(config, messages, options);
        }

        return await completeWithoutStreaming(config, messages, options);
      } catch (error) {
        await emitErrorEvent(options, error);
        throw error;
      }
    }
  };
}
