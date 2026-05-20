export type SkillDiagnostic = {
  level: 'info' | 'warning' | 'error';
  code: string;
  message: string;
  source?: string;
};

export type SkillManifest = {
  name: string;
  description: string;
  license?: string;
  compatibility?: string;
  metadata?: Record<string, string>;
  allowedTools?: string[];
};

export type ParsedSkillMarkdown = {
  manifest: SkillManifest;
  prompt: string;
  diagnostics: SkillDiagnostic[];
};

export type SkillScope = 'project' | 'user';

export type SkillSourceKind = 'project-cliq' | 'project-agents' | 'user-cliq' | 'user-agents';

export type SkillStatus = 'available' | 'invalid' | 'shadowed';

export type SkillCatalogEntry = {
  id: string;
  name: string;
  description: string | null;
  scope: SkillScope;
  sourceKind: SkillSourceKind;
  sourceRoot: string;
  skillDir: string;
  skillFile: string;
  status: SkillStatus;
  diagnostics: SkillDiagnostic[];
  shadowedBy?: string;
  rank: number;
};

export type SkillCatalog = {
  entries: SkillCatalogEntry[];
  diagnostics: SkillDiagnostic[];
};

export type SkillActivationSource = 'workspace-default' | 'cli' | 'headless' | 'model' | 'tui';

export type LoadedSkill = {
  name: string;
  description: string | null;
  prompt: string;
  manifest: SkillManifest;
  scope: SkillScope;
  sourceKind: SkillSourceKind;
  sourceRoot: string;
  skillDir: string;
  skillFile: string;
  diagnostics: SkillDiagnostic[];
};

export type ActiveSkill = LoadedSkill & {
  activatedBy: SkillActivationSource;
  activatedAt: string;
};
