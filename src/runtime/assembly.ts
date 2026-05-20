import { loadExtensions } from '../extensions/loader.js';
import { buildInstructionMessages, loadWorkspaceInstructionFiles } from '../instructions/builder.js';
import { BASE_SYSTEM_PROMPT } from '../prompt/system.js';
import type { PolicyMode } from '../policy/types.js';
import type { Session } from '../session/types.js';
import { activateSkill, discoverSkillCatalog, mergeSkillNames } from '../skills/loader.js';
import { loadWorkspaceConfig } from '../workspace/config.js';
import type { InstructionLayer, InstructionMessage } from '../instructions/types.js';
import type { SkillDiagnostic } from '../skills/types.js';

const INSTRUCTION_LAYERS = new Set<InstructionLayer>(['core', 'workspace', 'skill', 'extension']);

function validateExtensionMessages(extensionName: string, value: unknown): InstructionMessage[] {
  if (!Array.isArray(value)) {
    throw new Error(`Extension ${extensionName} instruction source returned invalid value, expected array`);
  }

  value.forEach((message, index) => {
    if (
      !message ||
      typeof message !== 'object' ||
      (message as Record<string, unknown>).role !== 'system' ||
      typeof (message as Record<string, unknown>).content !== 'string' ||
      typeof (message as Record<string, unknown>).source !== 'string' ||
      !INSTRUCTION_LAYERS.has((message as Record<string, unknown>).layer as InstructionLayer)
    ) {
      throw new Error(`Extension ${extensionName} instruction source returned invalid message at index ${index}`);
    }
  });

  return value as InstructionMessage[];
}

export async function createRuntimeAssembly({
  cwd,
  session,
  policyMode,
  cliSkillNames,
  explicitSkillActivationSource = 'cli'
}: {
  cwd: string;
  session: Session;
  policyMode: PolicyMode;
  cliSkillNames: string[];
  explicitSkillActivationSource?: 'cli' | 'headless';
}) {
  const workspaceConfig = await loadWorkspaceConfig(cwd);
  const skillCatalog = await discoverSkillCatalog(cwd);
  const skillDiagnostics: SkillDiagnostic[] = [];
  const skillNames = mergeSkillNames(workspaceConfig.defaultSkills, cliSkillNames);
  const extensions = await loadExtensions(cwd, workspaceConfig.extensions);
  for (const name of workspaceConfig.defaultSkills) {
    try {
      await activateSkill(cwd, session, name, {
        catalog: skillCatalog,
        projectOnly: true,
        activatedBy: 'workspace-default'
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (/not project-owned/i.test(message)) {
        skillDiagnostics.push({
          level: 'warning',
          code: 'workspace-default-not-project-owned',
          message: `Workspace default skill ${name} is not project-owned and was not activated`
        });
        continue;
      }
      throw error;
    }
  }
  for (const name of cliSkillNames) {
    await activateSkill(cwd, session, name, {
      catalog: skillCatalog,
      activatedBy: explicitSkillActivationSource
    });
  }
  const workspaceInstructions = await loadWorkspaceInstructionFiles(cwd, workspaceConfig.instructionFiles);

  return {
    workspaceConfig,
    skillCatalog,
    skillDiagnostics,
    skillNames,
    extensionNames: extensions.map((extension) => extension.name),
    hooks: extensions.flatMap((extension) => extension.hooks ?? []),
    commandHooks: workspaceConfig.hooks ?? {},
    session,
    async instructions(currentSession: Session) {
      const extensionMessages = (
        await Promise.all(
          extensions.flatMap((extension) =>
            (extension.instructionSources ?? []).map(async (source) => {
              try {
                const messages = await source({ cwd, session: currentSession, policyMode });
                return validateExtensionMessages(extension.name, messages);
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
        skills: (currentSession.activeSkills ?? []).map((skill) => ({ name: skill.name, prompt: skill.prompt })),
        extensionMessages
      });
    }
  };
}
