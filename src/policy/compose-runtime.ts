import {
  composePermissionTable,
  type PermissionRule,
  type PermissionTable
} from './decision-table.js';
import {
  readPersistedWorkspacePermissions,
  type PersistedPermissionRule,
  type WorkspacePermissionsRecord
} from '../session/permissions.js';
import type { WorkspaceTrustContext } from '../session/trust.js';
import type { WorkspacePermissionsConfig } from '../workspace/config.js';

/**
 * Assemble the runtime {@link PermissionTable} for a single Cliq invocation
 * by stacking layers in trust-aware order. Higher layers in this list are
 * evaluated LATER by the matcher; deny rules from any layer always win
 * because {@link composePermissionTable} concatenates deny first.
 *
 * Layer order (lowest → highest priority for allow/ask; deny is always
 * sticky regardless of layer):
 *
 *   1. builtin                — seeded by composePermissionTable
 *   2. workspace config        — `.cliq/config` permissions section
 *   3. persisted per-workspace — ~/.cliq/workspaces/<id>/permissions.json
 *   4. CLI flags               — --allow/--deny/--ask
 *   5. session memory          — TUI "Allow this session" picks (B5 wires;
 *                                B4 just leaves a hook in the caller)
 *
 * The user-global allow/deny store (~/.cliq/permissions.global.json) is
 * intentionally absent — see TODO(no-issue: user-global-permissions) in
 * src/session/permissions.ts for why we ship without it in v0.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * SECURITY — load-order invariant.
 * ─────────────────────────────────────────────────────────────────────────
 * Callers MUST have already satisfied the Workspace Trust gate
 * (src/session/trust.ts) BEFORE invoking this function. Both
 * `workspaceConfigPermissions` (parsed from `.cliq/config`, which is
 * repo-controlled) and the persisted permissions.json (which a hostile
 * checkout could in theory pre-seed under a fresh CLIQ_HOME) MUST NOT
 * influence the PolicyEngine before the user has approved trust on the
 * canonical workspace path. This is the same load-order class of
 * vulnerability documented in #48 and reinforced in #61. The store reader
 * itself is intentionally agnostic; this composer is the one place the
 * order is enforced.
 */
export async function composeRuntimePermissionTable(opts: {
  trustContext: WorkspaceTrustContext;
  workspaceConfigPermissions?: WorkspacePermissionsConfig | undefined;
  cliPermissions?:
    | {
        allow: PermissionRule[];
        deny: PermissionRule[];
        ask: PermissionRule[];
      }
    | undefined;
}): Promise<PermissionTable> {
  const layers: Partial<PermissionTable>[] = [];

  if (opts.workspaceConfigPermissions) {
    layers.push({
      allow: opts.workspaceConfigPermissions.allow ?? [],
      deny: opts.workspaceConfigPermissions.deny ?? [],
      ask: opts.workspaceConfigPermissions.ask ?? []
    });
  }

  const persisted = await readPersistedWorkspacePermissions(opts.trustContext);
  if (persisted) {
    layers.push(permissionLayerFromPersisted(persisted));
  }

  if (opts.cliPermissions) {
    layers.push(opts.cliPermissions);
  }

  return composePermissionTable(...layers);
}

function permissionLayerFromPersisted(record: WorkspacePermissionsRecord): Partial<PermissionTable> {
  return {
    allow: record.allow.map(toPersistedRule),
    deny: record.deny.map(toPersistedRule),
    ask: []
  };
}

function toPersistedRule(rule: PersistedPermissionRule): PermissionRule {
  // The persisted store only carries the matcher fields; the source label is
  // applied at compose time so PolicyEngine diagnostics can identify which
  // layer a decision came from ("persisted rule fs-write: docs/*").
  return { channel: rule.channel, pattern: rule.pattern, source: 'persisted' };
}
