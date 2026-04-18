import type { PolicyAuthorization, PolicyConfirm, PolicyMode, ToolAccess } from './types.js';

type PolicyEngineOptions = {
  mode: PolicyMode;
  confirm?: PolicyConfirm;
};

type ToolShape = {
  name: string;
  access: ToolAccess;
};

export function createPolicyEngine({ mode, confirm }: PolicyEngineOptions) {
  async function authorize(definition: ToolShape): Promise<PolicyAuthorization> {
    if (mode === 'auto') {
      return { allowed: true };
    }

    if (mode === 'read-only' && definition.access !== 'read') {
      return {
        allowed: false,
        reason: `policy mode read-only blocks ${definition.access} tools`
      };
    }

    const requiresConfirmation =
      mode === 'confirm-all' ||
      (mode === 'confirm-write' && definition.access === 'write') ||
      (mode === 'confirm-bash' && definition.name === 'bash');

    if (!requiresConfirmation) {
      return { allowed: true };
    }

    if (!confirm) {
      return {
        allowed: false,
        reason: 'confirmation required but no confirmer is available'
      };
    }

    const approved = await confirm(`Allow ${definition.name} (${definition.access})?`);
    return approved ? { allowed: true } : { allowed: false, reason: 'user declined confirmation' };
  }

  return { mode, authorize };
}
