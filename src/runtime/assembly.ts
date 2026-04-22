import { loadExtensions } from '../extensions/loader.js';
import { buildInstructionMessages, loadWorkspaceInstructionFiles } from '../instructions/builder.js';
import { BASE_SYSTEM_PROMPT } from '../prompt/system.js';
import type { PolicyMode } from '../policy/types.js';
import type { Session } from '../session/types.js';
import { loadSkills, mergeSkillNames } from '../skills/loader.js';
import { loadWorkspaceConfig } from '../workspace/config.js';

export async function createRuntimeAssembly({
  cwd,
  session,
  policyMode,
  cliSkillNames
}: {
  cwd: string;
  session: Session;
  policyMode: PolicyMode;
  cliSkillNames: string[];
}) {
  const workspaceConfig = await loadWorkspaceConfig(cwd);
  const skillNames = mergeSkillNames(workspaceConfig.defaultSkills, cliSkillNames);
  const extensions = await loadExtensions(cwd, workspaceConfig.extensions);
  const skills = await loadSkills(cwd, skillNames);
  const workspaceInstructions = await loadWorkspaceInstructionFiles(cwd, workspaceConfig.instructionFiles);

  return {
    skillNames,
    extensionNames: extensions.map((extension) => extension.name),
    hooks: extensions.flatMap((extension) => extension.hooks ?? []),
    session,
    async instructions(currentSession: Session) {
      const extensionMessages = (
        await Promise.all(
          extensions.flatMap((extension) =>
            (extension.instructionSources ?? []).map(async (source) => {
              try {
                return await source({ cwd, session: currentSession, policyMode });
              } catch (error) {
                throw new Error(
                  `Extension ${extension.name} instruction source failed: ${
                    error instanceof Error ? error.message : String(error)
                  }`
                );
              }
            })
          )
        )
      ).flat();

      return buildInstructionMessages({
        cwd,
        basePrompt: BASE_SYSTEM_PROMPT,
        workspaceInstructions,
        skills: skills.map((skill) => ({ name: skill.name, prompt: skill.prompt })),
        extensionMessages
      });
    }
  };
}
