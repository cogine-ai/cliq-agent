import type { CliqExtension } from '../types.js';

export const policyInstructionsExtension: CliqExtension = {
  name: 'policy-instructions',
  instructionSources: [
    async ({ policyMode }) => {
      if (policyMode === 'auto') {
        return [];
      }

      return [
        {
          role: 'system',
          layer: 'extension',
          source: 'policy-instructions',
          content: `Current policy mode is ${policyMode}. Plan actions that can succeed under this mode and explain when a write or exec step would be blocked.`
        }
      ];
    }
  ],
  hooks: []
};
