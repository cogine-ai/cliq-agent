import { promises as fs } from 'node:fs';

import { resolveWorkspacePath } from '../tools/path.js';
import type { BuildInstructionMessagesOptions, InstructionMessage } from './types.js';

export async function loadWorkspaceInstructionFiles(cwd: string, files: string[]) {
  const loaded: string[] = [];

  for (const file of files) {
    const { targetRealPath } = await resolveWorkspacePath(cwd, file);
    loaded.push((await fs.readFile(targetRealPath, 'utf8')).trim());
  }

  return loaded.filter(Boolean);
}

export async function buildInstructionMessages(options: BuildInstructionMessagesOptions): Promise<InstructionMessage[]> {
  const messages: InstructionMessage[] = [
    { role: 'system', layer: 'core', source: 'base', content: options.basePrompt }
  ];

  for (const instruction of options.workspaceInstructions) {
    messages.push({
      role: 'system',
      layer: 'workspace',
      source: 'workspace',
      content: instruction
    });
  }

  for (const skill of options.skills) {
    messages.push({
      role: 'system',
      layer: 'skill',
      source: `skill:${skill.name}`,
      content: skill.prompt
    });
  }

  messages.push(...options.extensionMessages);
  return messages;
}
