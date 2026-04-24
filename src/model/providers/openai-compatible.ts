import { fetchWithTimeout, joinUrl, readJsonResponse, readSseDeltas } from '../http.js';
import type { ChatMessage, ModelClient, ModelStreamEvent, ResolvedModelConfig } from '../types.js';

type ChatCompletionsResp = {
  choices: Array<{
    message?: {
      content?: string;
    };
  }>;
};

function headers(config: ResolvedModelConfig) {
  return {
    'content-type': 'application/json',
    ...(config.apiKey ? { authorization: `Bearer ${config.apiKey}` } : {})
  };
}

export function createOpenAICompatibleClient(config: ResolvedModelConfig): ModelClient {
  return {
    async complete(messages: ChatMessage[], options?: { onEvent?: (event: ModelStreamEvent) => void | Promise<void> }) {
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
            headers: headers(config),
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
            throw new Error(`${config.provider} stream missing text content`);
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
          headers: headers(config),
          body: JSON.stringify({
            model: config.model,
            messages,
            stream: false
          })
        });

        const json = await readJsonResponse<ChatCompletionsResp>(response, config.provider);
        if (!Array.isArray(json.choices) || json.choices.length === 0) {
          throw new Error(`${config.provider} response missing choices/content: ${JSON.stringify(json)}`);
        }

        const content = json.choices[0]?.message?.content?.trim();
        if (!content) {
          throw new Error(`${config.provider} response missing choices/content: ${JSON.stringify(json)}`);
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
