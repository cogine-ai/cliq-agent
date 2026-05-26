import type { PolicyMode } from '../policy/types.js';
import type { InstructionMessage } from './types.js';

const PLAN_MODE_INSTRUCTION = [
  'Plan Mode is active.',
  'Inspect and analyze the workspace, then produce a concrete plan before implementation.',
  'You must not modify source files.',
  'You must not run bash/exec or other side-effecting commands.',
  'If the user asks you to implement, provide the plan and explain that execution requires switching out of Plan Mode.'
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
