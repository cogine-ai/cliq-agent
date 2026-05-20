import { accessChannelPrimaryKey, type PermissionRule, type PermissionTable } from '../policy/decision-table.js';
import type { ApprovalSubject } from '../policy/types.js';
import { appendPersistedWorkspacePermission } from '../session/permissions.js';
import type { WorkspaceTrustContext } from '../session/trust.js';

/**
 * Derive the PermissionRule that an "allow this {session,workspace}" modal
 * decision would persist. Returns null when the subject doesn't carry an
 * identifiable channel key (e.g. bash with no parseable command head, or a
 * non-tool subject) — the caller surfaces a soft error so the user picks a
 * different scope or modifies the action.
 */
export function approvalSubjectToPermissionRule(
  subject: ApprovalSubject,
  source: PermissionRule['source']
): PermissionRule | null {
  if (subject.kind !== 'tool') return null;
  const key = accessChannelPrimaryKey(subject.channel);
  if (!key) return null;
  return { channel: subject.channel.kind, pattern: key, source };
}

export type ExtendApprovalScopeResult = { ok: true } | { ok: false; reason: string };

/**
 * Apply a session- or workspace-scoped allow from the TUI approval modal.
 *
 * Workspace scope persists to disk BEFORE mutating the in-memory table so a
 * failed write cannot leave a session-lived allow behind (PR #91 regression).
 */
export type ExtendApprovalScopeDeps = {
  appendPersisted?: typeof appendPersistedWorkspacePermission;
};

export async function extendApprovalScope(
  trustContext: WorkspaceTrustContext,
  permissionTable: PermissionTable,
  subject: ApprovalSubject,
  scope: 'session' | 'workspace',
  deps: ExtendApprovalScopeDeps = {}
): Promise<ExtendApprovalScopeResult> {
  const appendPersisted = deps.appendPersisted ?? appendPersistedWorkspacePermission;
  const rule = approvalSubjectToPermissionRule(
    subject,
    scope === 'session' ? 'session' : 'persisted'
  );
  if (!rule) {
    return {
      ok: false,
      reason: `cannot derive a permission rule from ${subject.kind} subject`
    };
  }
  if (scope === 'workspace') {
    try {
      await appendPersisted(trustContext, 'allow', {
        channel: rule.channel,
        pattern: rule.pattern
      });
    } catch (err) {
      return {
        ok: false,
        reason: err instanceof Error ? err.message : String(err)
      };
    }
  }
  permissionTable.allow.push(rule);
  return { ok: true };
}
