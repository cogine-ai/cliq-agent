import { MODEL } from '../config.js';
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

      const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
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
        })
      });

      if (!res.ok) {
        throw new Error(`OpenRouter error ${res.status}: ${await res.text()}`);
      }

      const json = (await res.json()) as OpenRouterResp;
      return json.choices[0]?.message?.content?.trim() ?? '';
    }
  };
}
