import type { ApprovalSubject } from '../policy/types.js';
import type { PendingApproval, UiApprovalDecision, UiStore } from './store.js';

// Cliq's policy.decide() awaits a UI decision through this bridge whenever
// inner.decide() returns `ask`. Promises do not observe AbortSignal, so the
// bridge also exposes a cancelPending() entry point that the Ctrl+C handler
// uses to force-deny an in-flight approval; without it, an abort would leave
// the runner blocked forever inside decide().
export type ApprovalBridge = {
  requestApproval(subject: ApprovalSubject): Promise<UiApprovalDecision>;
  cancelPending(): void;
};

export function createApprovalBridge(store: UiStore): ApprovalBridge {
  let counter = 0;
  let current: { id: string; resolve: (d: UiApprovalDecision) => void } | null = null;

  function requestApproval(subject: ApprovalSubject): Promise<UiApprovalDecision> {
    return new Promise((resolve) => {
      // If a previous request is still in flight (caller bypassed normal
      // turn serialization, e.g. mid-flight reentry), force-deny it so its
      // Promise resolves before we install a new pending. Without this the
      // old caller awaits forever.
      if (current) {
        const stale = current;
        current = null;
        stale.resolve('deny');
        store.dispatch({ type: 'approval-resolve', id: stale.id });
      }

      counter += 1;
      const id = `pa_${counter}`;
      const wrappedResolve = (decision: UiApprovalDecision) => {
        if (current?.id === id) current = null;
        resolve(decision);
      };
      current = { id, resolve: wrappedResolve };
      const pending: PendingApproval = { id, subject, resolve: wrappedResolve };
      store.dispatch({ type: 'approval-request', pending });
    });
  }

  function cancelPending(): void {
    if (!current) return;
    const stale = current;
    current = null;
    stale.resolve('deny');
    store.dispatch({ type: 'approval-resolve', id: stale.id });
  }

  return { requestApproval, cancelPending };
}
