import type { InstructionMessage } from '../instructions/types.js';
import type { PolicyMode } from '../policy/types.js';
import type { RuntimeHook } from '../runtime/hooks.js';
import type { Session } from '../session/types.js';

export type ExtensionInstructionSource = (context: {
  cwd: string;
  session: Session;
  policyMode: PolicyMode;
}) => Promise<InstructionMessage[]> | InstructionMessage[];

export type CliqExtension = {
  name: string;
  instructionSources?: ExtensionInstructionSource[];
  hooks?: RuntimeHook[];
};
