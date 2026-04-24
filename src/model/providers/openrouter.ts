import { fetchWithTimeout, joinUrl, readJsonResponse, readSseDeltas } from '../http.js';
import type { ChatMessage, ModelClient, ModelStreamEvent, ResolvedModelConfig } from '../types.js';

type OpenRouterResp = {
  choices: Array<{
    message?: {
      role?: 'assistant';
      content?: string;
    };
  }>;
};

export function createOpenRouterClient(config: ResolvedModelConfig): ModelClient {
  return {
    async complete(messages: ChatMessage[], options?: { onEvent?: (event: ModelStreamEvent) => void | Promise<void> }) {
      if (!config.apiKey) {
        throw new Error('OPENROUTER_API_KEY is required');
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
            headers: {
              'content-type': 'application/json',
              authorization: `Bearer ${config.apiKey}`,
              'HTTP-Referer': 'https://local.cliq',
              'X-Title': 'cliq-agent'
            },
            body: JSON.stringify({
              model: config.model,
              messages,
              stream: true
            })
          });

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
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${config.apiKey}`,
            'HTTP-Referer': 'https://local.cliq',
            'X-Title': 'cliq-agent'
          },
          body: JSON.stringify({
            model: config.model,
            messages,
            stream: false
          })
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
        await options?.onEvent?.({
          type: 'error',
          message: error instanceof Error ? error.message : String(error)
        });
        throw error;
      }
    }
  };
}
