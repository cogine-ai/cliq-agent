import { fetchWithTimeout, joinUrl, readJsonResponse, readNdjsonDeltas } from '../http.js';
import { emitModelErrorEvent } from '../events.js';
import type { ChatMessage, ModelClient, ModelCompleteOptions, ResolvedModelConfig } from '../types.js';

type OllamaResp = {
  message?: {
    content?: string;
  };
};

export function createOllamaClient(config: ResolvedModelConfig): ModelClient {
  return {
    async complete(messages: ChatMessage[], options?: ModelCompleteOptions) {
      await options?.onEvent?.({
        type: 'start',
        provider: config.provider,
        model: config.model,
        streaming: config.streaming !== 'off'
      });

      try {
        if (config.streaming !== 'off') {
          const response = await fetchWithTimeout(joinUrl(config.baseUrl, '/api/chat'), {
            method: 'POST',
            headers: {
              'content-type': 'application/json'
            },
            body: JSON.stringify({
              model: config.model,
              messages,
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
              async (text) => options?.onEvent?.({ type: 'text-delta', text })
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
            messages,
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
