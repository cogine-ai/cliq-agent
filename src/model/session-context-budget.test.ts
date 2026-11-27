import test from 'node:test';
import assert from 'node:assert/strict';
import { buildModelRequestWire, projectModelVisiblePrompt, sessionContextUserWireByteLowerBound,
  MODEL_REQUEST_BODY_LIMIT_BYTES, type NormalPromptMessageV1 } from './request.js';
import type { ProviderName } from '../kernel/types.js';

// Pure serialization only; no provider request, credential, StateOwner or Run.
const providers: readonly ProviderName[] = ['openai', 'anthropic', 'ollama', 'openai-compatible'];
function messages(contents: readonly string[]): NormalPromptMessageV1[] {
  return [{ index: 0, role: 'system', sourceKind: 'assembly_instructions', sourceId: 'assembly', contentUtf8: 'system' },
    ...contents.map((contentUtf8, index) => ({ index: index + 1, role: 'user' as const, sourceKind: 'session_summary' as const,
      sourceId: `summary-${index}`, contentUtf8 }))];
}
test('selected adapter additive lower bound survives adjacent-user and Anthropic block merging', () => {
  for (const provider of providers) for (const mode of ['native-tools', 'text-only'] as const) {
    for (const contents of [Array.from({ length: 2_000 }, () => ''), ['first', 'second', 'third'],
      ['quoted " and slash \\', '\n\t\r', '汉字 / 🔥 / e\u0301', '']]) {
      const prompt = projectModelVisiblePrompt({ messages: messages(contents), tools: [] }, mode);
      const actual = buildModelRequestWire({ provider, model: 'fixed-model', streaming: true, contextLimitTokens: 65_536 }, prompt, 256, mode);
      const lower = contents.reduce((sum, content) => sum + sessionContextUserWireByteLowerBound(provider, 'fixed-model', content), 0);
      assert(actual.bodyBytes.length >= lower, `${provider}/${mode} must retain every complete user representation`);
    }
  }
});
test('UTF8 and JSON escaping use actual wire bytes instead of character counts', () => {
  for (const provider of providers) {
    const plain = sessionContextUserWireByteLowerBound(provider, 'fixed-model', 'a');
    assert.equal(sessionContextUserWireByteLowerBound(provider, 'fixed-model', '🔥') - plain, 3);
    assert.equal(sessionContextUserWireByteLowerBound(provider, 'fixed-model', '\n') - plain, 1);
    assert.equal(sessionContextUserWireByteLowerBound(provider, 'fixed-model', '"') - plain, 1);
  }
});
test('rejection-only bound cannot authorize a request that the exact adapter rejects', () => {
  for (const provider of providers) {
    const content = 'x'.repeat(MODEL_REQUEST_BODY_LIMIT_BYTES);
    const lower = sessionContextUserWireByteLowerBound(provider, 'fixed-model', content);
    assert(lower > MODEL_REQUEST_BODY_LIMIT_BYTES);
    const prompt = projectModelVisiblePrompt({ messages: messages([content]), tools: [] }, 'native-tools');
    assert(buildModelRequestWire({ provider, model: 'fixed-model', streaming: false, contextLimitTokens: 65_536 }, prompt, 256,
      'native-tools').bodyBytes.length >= lower);
    // A tiny lower bound supplies no acceptance: unchanged exact serialization
    // can still exceed the ceiling through the remaining legitimate body.
    const small = projectModelVisiblePrompt({ messages: messages(['small']), tools: [] }, 'native-tools');
    const body = buildModelRequestWire({ provider, model: 'm'.repeat(MODEL_REQUEST_BODY_LIMIT_BYTES), streaming: false,
      contextLimitTokens: 65_536 }, small, 256, 'native-tools');
    assert(sessionContextUserWireByteLowerBound(provider, 'fixed-model', 'small') < MODEL_REQUEST_BODY_LIMIT_BYTES);
    assert(body.bodyBytes.length > MODEL_REQUEST_BODY_LIMIT_BYTES);
  }
});
