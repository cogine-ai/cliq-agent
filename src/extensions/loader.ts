import { pathToFileURL } from 'node:url';

import { resolveWorkspacePath } from '../tools/path.js';
import { policyInstructionsExtension } from './builtin/policy-instructions.js';
import type { CliqExtension } from './types.js';

const BUILTIN_EXTENSIONS: Record<string, CliqExtension> = {
  'policy-instructions': policyInstructionsExtension
};

async function importExtension(specifier: string, cwd: string): Promise<CliqExtension> {
  if (specifier.startsWith('builtin:')) {
    const builtin = BUILTIN_EXTENSIONS[specifier.slice('builtin:'.length)];
    if (!builtin) {
      throw new Error(`Unknown built-in extension: ${specifier}`);
    }

    return builtin;
  }

  if (specifier.startsWith('.')) {
    const { targetRealPath } = await resolveWorkspacePath(cwd, specifier);

    try {
      const mod = await import(pathToFileURL(targetRealPath).href);
      return (mod.default ?? mod.extension) as CliqExtension;
    } catch (error) {
      throw new Error(`Failed to load extension ${specifier}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  throw new Error(`Unsupported extension specifier in Phase 2: ${specifier}`);
}

export async function loadExtensions(cwd: string, specifiers: string[]) {
  const loaded: CliqExtension[] = [];
  const names = new Set<string>();

  for (const specifier of specifiers) {
    const extension = await importExtension(specifier, cwd);
    if (!extension || typeof extension.name !== 'string') {
      throw new Error(`Extension ${specifier} must export a named CliqExtension`);
    }

    if (extension.instructionSources !== undefined && !Array.isArray(extension.instructionSources)) {
      throw new Error(`Extension ${specifier} has invalid instructionSources, expected array`);
    }

    if ((extension.instructionSources ?? []).some((source) => typeof source !== 'function')) {
      throw new Error(`Extension ${specifier} has invalid instructionSource item, expected function`);
    }

    if (extension.hooks !== undefined && !Array.isArray(extension.hooks)) {
      throw new Error(`Extension ${specifier} has invalid hooks, expected array`);
    }

    if ((extension.hooks ?? []).some((hook) => !hook || typeof hook !== 'object' || Array.isArray(hook))) {
      throw new Error(`Extension ${specifier} has invalid hook item, expected object`);
    }

    if (names.has(extension.name)) {
      throw new Error(`duplicate extension name: ${extension.name}`);
    }

    names.add(extension.name);
    loaded.push({
      name: extension.name,
      instructionSources: extension.instructionSources ?? [],
      hooks: extension.hooks ?? []
    });
  }

  return loaded;
}
