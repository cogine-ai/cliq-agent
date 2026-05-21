export type LoadedSkillFrontmatter = {
  license?: string;
  compatibility?: string;
  metadata?: Record<string, string>;
  allowedTools?: string | string[];
};

export type LoadedSkill = {
  name: string;
  description: string;
  prompt: string;
  frontmatter?: LoadedSkillFrontmatter;
};
