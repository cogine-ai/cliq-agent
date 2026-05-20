import { type PermissionTable } from '../policy/decision-table.js';
import { createPolicyEngine } from '../policy/engine.js';
import type { ApprovalSubject, PolicyMode } from '../policy/types.js';
import type { ExtendApprovalScopeResult } from './extend-approval-scope.js';

export function createTuiLivePolicyEngine(
  initialMode: PolicyMode,
  requestApproval: (
    subject: ApprovalSubject
  ) => Promise<'allow' | 'deny' | 'allow-turn' | 'allow-session' | 'allow-workspace'>,
  table: PermissionTable,
  extendAllow: (
    subject: ApprovalSubject,
    scope: 'session' | 'workspace'
  ) => Promise<ExtendApprovalScopeResult>,
  onExtendedAllow?: () => void
) {
  let inner = createPolicyEngine({ mode: initialMode, table });
  let allowTurn = false;

  const engine = {
    get mode() {
      return inner.mode;
    },
    decide: async (subject: ApprovalSubject) => {
      const decision = await inner.decide(subject);
      if (decision.behavior !== 'ask') return decision;
      if (allowTurn) {
        return { behavior: 'allow', decidedBy: 'user' as const };
      }
      const userChoice = await requestApproval(subject);
      if (userChoice === 'allow') {
        return { behavior: 'allow', decidedBy: 'user' as const };
      }
      if (userChoice === 'allow-turn') {
        allowTurn = true;
        return { behavior: 'allow', decidedBy: 'user' as const };
      }
      if (userChoice === 'allow-session' || userChoice === 'allow-workspace') {
        const scope = userChoice === 'allow-session' ? 'session' : 'workspace';
        const result = await extendAllow(subject, scope);
        if (!result.ok) {
          process.stderr.write(
            `cliq: could not extend approval to ${scope}: ${result.reason}\n`
          );
        } else {
          onExtendedAllow?.();
        }
        return { behavior: 'allow', decidedBy: 'user' as const };
      }
      return {
        behavior: 'deny' as const,
        reason: 'user denied via TUI approval modal',
        decidedBy: 'user' as const
      };
    }
  };

  return {
    engine: engine as ReturnType<typeof createPolicyEngine>,
    setMode(mode: PolicyMode) {
      inner = createPolicyEngine({ mode, table });
    },
    resetTurn() {
      allowTurn = false;
    },
    rebuildForExtendedAllow() {
      inner = createPolicyEngine({ mode: inner.mode, table });
    }
  };
}
