import type { PolicyMode } from '../policy/types.js';
import type { InstructionMessage } from './types.js';

const PLAN_MODE_INSTRUCTION = [
  'Plan Mode is active.',
  'Inspect and analyze the workspace before drafting a plan.',
  'Ask concise blocking questions only when the missing answer prevents a useful plan.',
  'You must not modify source files.',
  'You must not run bash/exec or other side-effecting commands.',
  'Use only read/ls/find/grep/skill/skillResource plus the dedicated plan action while planning.',
  'Create and revise persisted plan artifacts with {"plan":{"op":"draft"|"update"|...}} instead of returning the plan only as a message.',
  'Use a concise checklist in the plan content and include plan items with stable titles when useful; the plan artifact is mirrored to an editable plan.md file.',
  'Treat plan.md as editable only while the artifact is draft; after finalizing, revise with a plan update and finalize again.',
  'When the plan is ready for review, finalize it with {"plan":{"op":"finalize","planId":"<plan id>"}}.',
  'After finalizing, wait for user approval and do not begin implementation until the mode switches out of Plan Mode.'
].join('\n');

export function buildPolicyModeInstructionMessages(policyMode: PolicyMode): InstructionMessage[] {
  if (policyMode !== 'plan') return [];
  return [
    {
      role: 'system',
      layer: 'core',
      source: 'mode:plan',
      content: PLAN_MODE_INSTRUCTION
    }
  ];
}
