import { fetchWithTimeout, joinUrl, readJsonResponse, readSseDeltas } from '../http.js';
import type { ChatMessage, ModelClient, ModelStreamEvent, ResolvedModelConfig } from '../types.js';

type AnthropicResp = {
  content: Array<{ type: string; text?: string }>;
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

export function createAnthropicClient(config: ResolvedModelConfig): ModelClient {
  return {
    async complete(messages: ChatMessage[], options?: { onEvent?: (event: ModelStreamEvent) => void | Promise<void> }) {
      if (!config.apiKey) {
        throw new Error('ANTHROPIC_API_KEY is required');
      }

      const body = splitMessages(messages);
      await options?.onEvent?.({
        type: 'start',
        provider: config.provider,
        model: config.model,
        streaming: config.streaming !== 'off'
      });

      try {
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
              ...(body.system ? { system: body.system } : {}),
              messages: body.messages,
              stream: true
            })
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
              async (text) => options?.onEvent?.({ type: 'text-delta', text })
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
            ...(body.system ? { system: body.system } : {}),
            messages: body.messages,
            stream: false
          })
        });

        const json = await readJsonResponse<AnthropicResp>(response, 'Anthropic');
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
        await options?.onEvent?.({
          type: 'error',
          message: error instanceof Error ? error.message : String(error)
        });
        throw error;
      }
    }
  };
}
