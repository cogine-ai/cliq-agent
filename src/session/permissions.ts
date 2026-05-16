import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { AccessChannelKind } from '../policy/types.js';
import type { WorkspaceTrustContext } from './trust.js';

/**
 * SECURITY — load-order invariant.
 *
 * `permissions.json` lives in the same workspace-keyed directory as `trust.json`
 * and the persisted file describes "always allow" / "always deny" rules that the
 * PolicyEngine decision table consumes (see src/policy/decision-table.ts).
 *
 * Callers MUST satisfy the Workspace Trust gate (see src/session/trust.ts)
 * BEFORE reading permissions.json. A hostile checkout that pre-seeded an allow
 * rule must never be honored just because the user happens to land in that
 * directory. This is the same load-order class of bug #48 guarded against for
 * `.cliq/config`.
 *
 * The store API itself is intentionally agnostic — it neither knows nor cares
 * whether trust has been resolved. Enforcing the load order is the
 * responsibility of the call site in src/cli.ts / src/runtime/assembly.ts
 * (wired in step B4 of #62-B).
 */

export const WORKSPACE_PERMISSIONS_RECORD_VERSION = 1 as const;

export type PersistedPermissionRule = {
  channel: AccessChannelKind;
  pattern: string;
};

export type WorkspacePermissionsRecord = {
  version: typeof WORKSPACE_PERMISSIONS_RECORD_VERSION;
  workspaceId: string;
  workspaceRealPath: string;
  decidedAt: string;
  allow: PersistedPermissionRule[];
  deny: PersistedPermissionRule[];
};

export function workspacePermissionsRecordPath(ctx: WorkspaceTrustContext) {
  return path.join(ctx.cliqHome, 'workspaces', ctx.workspaceId, 'permissions.json');
}

/**
 * Read the persisted permissions record. Returns `undefined` for ENOENT, JSON
 * parse failure, schema-version mismatch, or workspaceId mismatch. This is the
 * same fail-closed "corrupted file is treated as absent" stance the trust
 * record uses (see #61 review), so a tampered or unreadable file can never
 * elevate the user above what the live PolicyEngine preset would grant.
 */
export async function readPersistedWorkspacePermissions(
  ctx: WorkspaceTrustContext
): Promise<WorkspacePermissionsRecord | undefined> {
  const target = workspacePermissionsRecordPath(ctx);
  let raw: string;
  try {
    raw = await fs.readFile(target, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') {
      return undefined;
    }
    throw error;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== 'object') {
    return undefined;
  }

  const rec = parsed as Partial<WorkspacePermissionsRecord>;
  if (
    rec.version !== WORKSPACE_PERMISSIONS_RECORD_VERSION ||
    typeof rec.workspaceId !== 'string' ||
    typeof rec.workspaceRealPath !== 'string' ||
    typeof rec.decidedAt !== 'string'
  ) {
    return undefined;
  }
  if (rec.workspaceId !== ctx.workspaceId) {
    // Workspace ID mismatch: the file lives under <cliqHome>/workspaces/<id>/
    // but its own self-reported id is something else. Treat as corrupt rather
    // than risk applying rules across workspaces.
    return undefined;
  }

  const allow = sanitizeRules(rec.allow);
  const deny = sanitizeRules(rec.deny);
  if (allow === null || deny === null) {
    return undefined;
  }

  return {
    version: WORKSPACE_PERMISSIONS_RECORD_VERSION,
    workspaceId: rec.workspaceId,
    workspaceRealPath: rec.workspaceRealPath,
    decidedAt: rec.decidedAt,
    allow,
    deny
  };
}

/**
 * Write the persisted permissions record atomically (tmp + rename). Mirrors
 * trust.ts so concurrent cliq processes can't observe a half-written file.
 */
export async function writePersistedWorkspacePermissions(
  ctx: WorkspaceTrustContext,
  record: Omit<WorkspacePermissionsRecord, 'version' | 'workspaceId' | 'workspaceRealPath' | 'decidedAt'> &
    Partial<Pick<WorkspacePermissionsRecord, 'decidedAt'>>
): Promise<WorkspacePermissionsRecord> {
  const value: WorkspacePermissionsRecord = {
    version: WORKSPACE_PERMISSIONS_RECORD_VERSION,
    workspaceId: ctx.workspaceId,
    workspaceRealPath: ctx.workspaceRealPath,
    decidedAt: record.decidedAt ?? new Date().toISOString(),
    allow: record.allow,
    deny: record.deny
  };
  await atomicWritePermissionsRecord(workspacePermissionsRecordPath(ctx), value);
  return value;
}

/**
 * Append a rule to the persisted record. Reads the current record (or starts
 * fresh if absent), de-duplicates exact (channel, pattern) matches, and writes
 * atomically. Returns the resulting record so the caller can update any
 * in-process layered table without re-reading from disk.
 *
 * Used by the TUI "Always allow in this workspace" / "Always deny" decisions.
 */
export async function appendPersistedWorkspacePermission(
  ctx: WorkspaceTrustContext,
  kind: 'allow' | 'deny',
  rule: PersistedPermissionRule
): Promise<WorkspacePermissionsRecord> {
  const current = await readPersistedWorkspacePermissions(ctx);
  const allow = [...(current?.allow ?? [])];
  const deny = [...(current?.deny ?? [])];
  const target = kind === 'allow' ? allow : deny;
  const already = target.some((r) => r.channel === rule.channel && r.pattern === rule.pattern);
  if (!already) {
    target.push({ channel: rule.channel, pattern: rule.pattern });
  }
  return await writePersistedWorkspacePermissions(ctx, { allow, deny });
}

const VALID_CHANNELS = new Set<AccessChannelKind>([
  'fs-read',
  'fs-write',
  'bash',
  'mcp',
  'network'
]);

function sanitizeRules(value: unknown): PersistedPermissionRule[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return null;
  const out: PersistedPermissionRule[] = [];
  for (const item of value) {
    if (!item || typeof item !== 'object') continue;
    const rec = item as Partial<PersistedPermissionRule>;
    if (typeof rec.channel !== 'string' || typeof rec.pattern !== 'string') continue;
    if (!VALID_CHANNELS.has(rec.channel as AccessChannelKind)) continue;
    out.push({ channel: rec.channel as AccessChannelKind, pattern: rec.pattern });
  }
  return out;
}

async function atomicWritePermissionsRecord(target: string, value: WorkspacePermissionsRecord) {
  await fs.mkdir(path.dirname(target), { recursive: true });
  const temp = path.join(
    path.dirname(target),
    `.${path.basename(target)}.${process.pid}.${crypto.randomUUID()}.tmp`
  );
  try {
    await fs.writeFile(temp, JSON.stringify(value, null, 2));
    await fs.rename(temp, target);
  } catch (error) {
    await fs.rm(temp, { force: true });
    throw error;
  }
}

// TODO(no-issue: user-global-permissions): v0 deliberately ships per-workspace
// only. A user-global allow/deny store at ~/.cliq/permissions.global.json was
// considered and skipped because a cross-workspace allow conflicts with the
// Layer 1 workspace trust model (a globally-trusted "bash: rm" rule would
// apply to a workspace the user has never even seen). If we add it later it
// MUST live behind a separate explicit opt-in and be load-order isolated from
// trust.json so a hostile checkout can't read it.
