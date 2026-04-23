import type { ChatMessage } from '../model/types.js';
import type { Session } from '../session/types.js';

export type InstructionLayer = 'core' | 'workspace' | 'skill' | 'extension';

export type InstructionMessage = ChatMessage & {
  role: 'system';
  layer: InstructionLayer;
  source: string;
};

export type LoadedSkillPrompt = {
  name: string;
  prompt: string;
};

export type BuildInstructionMessagesOptions = {
  cwd: string;
  basePrompt: string;
  workspaceInstructions: string[];
  skills: LoadedSkillPrompt[];
  extensionMessages: InstructionMessage[];
  session?: Session;
};
