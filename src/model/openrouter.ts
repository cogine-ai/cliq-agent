import { MODEL, OPENROUTER_TIMEOUT_MS } from '../config.js';
import type { ChatMessage, ModelClient } from './types.js';

type OpenRouterResp = {
  choices: Array<{
    message: {
      role: 'assistant';
      content?: string;
    };
  }>;
};

export function createOpenRouterClient(): ModelClient {
  return {
    async complete(messages: ChatMessage[]) {
      const key = process.env.OPENROUTER_API_KEY;
      if (!key) {
        throw new Error('OPENROUTER_API_KEY is required');
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => {
        controller.abort();
      }, OPENROUTER_TIMEOUT_MS);

      let res: Response;
      try {
        res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${key}`,
            'HTTP-Referer': 'https://local.cliq',
            'X-Title': 'cliq-agent'
          },
          body: JSON.stringify({
            model: MODEL,
            messages
          }),
          signal: controller.signal
        });
      } catch (error) {
        if (error instanceof Error && error.name === 'AbortError') {
          throw new Error(`OpenRouter request timed out after ${OPENROUTER_TIMEOUT_MS}ms`);
        }

        throw error;
      } finally {
        clearTimeout(timeout);
      }

      if (!res.ok) {
        throw new Error(`OpenRouter error ${res.status}: ${await res.text()}`);
      }

      const json = (await res.json()) as OpenRouterResp;
      const content = json.choices[0]?.message?.content?.trim();
      if (!content) {
        throw new Error(`OpenRouter response missing choices/content: ${JSON.stringify(json)}`);
      }

      return content;
    }
  };
}
