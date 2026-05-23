import { type PermissionTable } from './decision-table.js';
import { createPolicyEngine } from './engine.js';
import type { ApprovalSubject, PolicyMode } from './types.js';
import type { ApprovalScope, ExtendApprovalScopeResult } from './approval-scope.js';

export type InteractiveApprovalChoice =
  | 'allow'
  | 'deny'
  | 'allow-turn'
  | 'allow-session'
  | 'allow-workspace';

export type ExtendAllowFailure = {
  scope: ApprovalScope;
  reason: string;
};

export type InteractivePolicyEngineOptions = {
  initialMode: PolicyMode;
  requestApproval: (subject: ApprovalSubject) => Promise<InteractiveApprovalChoice>;
  table: PermissionTable;
  extendAllow: (
    subject: ApprovalSubject,
    scope: ApprovalScope
  ) => Promise<ExtendApprovalScopeResult>;
  onExtendAllowFailure?: (failure: ExtendAllowFailure) => void;
};

export function createInteractivePolicyEngine({
  initialMode,
  requestApproval,
  table,
  extendAllow,
  onExtendAllowFailure
}: InteractivePolicyEngineOptions) {
  let inner = createPolicyEngine({ mode: initialMode, table });
  let allowTurn = false;

  function rebuildForExtendedAllow() {
    inner = createPolicyEngine({ mode: inner.mode, table });
  }

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
          onExtendAllowFailure?.({ scope, reason: result.reason });
        } else {
          rebuildForExtendedAllow();
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
    rebuildForExtendedAllow
  };
}
