import assert from 'node:assert/strict';
import test from 'node:test';

import { parseOllamaToolCalls, parseOpenAIToolCalls } from './prompt-mapping.js';

test('parseOpenAIToolCalls skips tool calls with non-object arguments', () => {
  assert.deepEqual(
    parseOpenAIToolCalls({
      tool_calls: [
        { id: 'call_array', function: { name: 'bash', arguments: '[]' } },
        { id: 'call_null', function: { name: 'bash', arguments: 'null' } },
        { id: 'call_object', function: { name: 'bash', arguments: '{"command":"pwd"}' } }
      ]
    }),
    [{ id: 'call_object', name: 'bash', arguments: { command: 'pwd' } }]
  );
});

test('parseOllamaToolCalls skips tool calls with non-object arguments', () => {
  assert.deepEqual(
    parseOllamaToolCalls({
      tool_calls: [
        { function: { name: 'bash', arguments: [] } },
        { function: { name: 'bash', arguments: null } },
        { function: { name: 'bash', arguments: { command: 'pwd' } } }
      ]
    }),
    [{ id: 'ollama_call_3', name: 'bash', arguments: { command: 'pwd' } }]
  );
});
