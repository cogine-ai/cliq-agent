import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { decodeSkillResourceInput } from '../../../src/kernel/skill.js';
import { buildBundledSkillPackageData } from './installed-skill-package.js';
import { installedToolsCalls } from './installed-tools-result.js';
import { assertInstalledSkillPrompt, installedBundledSkill, installedSkillIds, installedToolsAndSkillsCalls } from './installed-skills.js';

test('skills extend the one original tool batch while preserving every original call and bounded resource protocol', () => {
  const original = installedToolsCalls('before', 'after'), combined = installedToolsAndSkillsCalls('before', 'after');
  assert.deepEqual(combined.slice(0, 19), original); assert.equal(combined.length, 22);
  assert.deepEqual(combined.slice(19).map(call => call.name), ['skill_resource', 'skill_resource', 'skill_resource']);
  assert.deepEqual(combined.slice(19).map(call => decodeSkillResourceInput(call.input).skillId), installedSkillIds());
  assert(new Set(combined.map(call => call.callId)).size === combined.length);
  const bundle = buildBundledSkillPackageData(installedBundledSkill());
  assert.equal(bundle.roots.length, 1); assert(bundle.contents.every(entry => !entry.executable));
});

test('actual prompt guard requires exactly ordered scope blocks and original binary-safe resource replies', () => {
  const descriptions = [
    ['owned-user-skill', 'user', 'Use the frozen [user bytes](assets/data.txt).', 'original user skill resource\n'],
    ['owned-bundled-skill', 'bundled', 'Read the frozen [script as data](scripts/inspect.py).', 'raise SystemExit("SKILL_BYTES_MUST_NOT_EXECUTE")\n'],
    ['owned-workspace-skill', 'workspace', 'Use the frozen [workspace bytes](assets/data.txt).', 'original workspace skill resource\n']
  ];
  const blocks = descriptions.map(([skillId, sourceScope, instructionUtf8]) => canonicalJsonBytes({ format: 'cliq-skill-instruction-prompt-v1', skillId, sourceScope, instructionUtf8 }).toString());
  const replies = descriptions.map(([, , , bytes], index) => ({ role: 'tool', tool_call_id: `owned-installed-skill-${index}`,
    content: canonicalJsonBytes({ kind: 'range', output: { bytesBase64: Buffer.from(bytes!).toString('base64') } }).toString() }));
  const body = { messages: [{ role: 'system', content: 'base\n\n' + blocks.join('\n\n') }, ...replies] };
  assertInstalledSkillPrompt(body, true);
  assert.throws(() => assertInstalledSkillPrompt({ messages: [{ role: 'system', content: [...blocks].reverse().join('\n\n') }] }, false));
  assert.throws(() => assertInstalledSkillPrompt({ messages: [{ role: 'system', content: blocks.join('\n\n') + blocks[0] }] }, false));
  assert.throws(() => assertInstalledSkillPrompt({ messages: body.messages.slice(0, -1) }, true));
  assert.throws(() => assertInstalledSkillPrompt({ messages: [body.messages[0], ...replies.map(reply => ({ ...reply, content: '{"kind":"range","output":{"bytesBase64":"ZXhlY3V0ZWQ="}}' }))] }, true));
});
