import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { resolveCliqHome, workspaceIdFromRealPath } from './store.js';

export const WORKSPACE_TRUST_RECORD_VERSION = 1 as const;

export type PersistedWorkspaceTrustDecision = 'trusted' | 'denied';

export type WorkspaceTrustRecord = {
  version: typeof WORKSPACE_TRUST_RECORD_VERSION;
  workspaceId: string;
  workspaceRealPath: string;
  decision: PersistedWorkspaceTrustDecision;
  decidedAt: string;
};

export type WorkspaceTrustContext = {
  workspaceRealPath: string;
  workspaceId: string;
  cliqHome: string;
};

export class WorkspaceTrustError extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode: number) {
    super(message);
    this.name = 'WorkspaceTrustError';
    this.exitCode = exitCode;
  }
}

/**
 * Mirrors Codex CLI `trust_level`-style ergonomics (`trusted`/`untrusted`) while
 * keeping CI-friendly short tokens (`trust`/`deny`).
 */
export function parseCliqTrustWorkspaceEnv(
  env: Record<string, string | undefined> = process.env
): 'trust' | 'deny' | undefined {
  const raw = env.CLIQ_TRUST_WORKSPACE?.trim();
  if (!raw) {
    return undefined;
  }
  const norm = raw.toLowerCase();
  if (norm === 'trust' || norm === 'trusted' || norm === '1' || norm === 'yes') {
    return 'trust';
  }
  if (norm === 'deny' || norm === 'untrusted' || norm === '0' || norm === 'no') {
    return 'deny';
  }
  throw new WorkspaceTrustError(
    `invalid CLIQ_TRUST_WORKSPACE="${raw}" — use trust, deny, trusted, or untrusted`,
    2
  );
}

export function workspaceTrustRecordPath(ctx: WorkspaceTrustContext) {
  return path.join(ctx.cliqHome, 'workspaces', ctx.workspaceId, 'trust.json');
}

async function atomicWriteTrustRecord(target: string, value: WorkspaceTrustRecord) {
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

export function formatTrustResetHint(trustJsonPath: string) {
  return `To reset a prior decision, delete the trust record at ${trustJsonPath} and rerun cliq interactively once.`;
}

export async function createWorkspaceTrustContext(
  cwd: string,
  cliqHome = resolveCliqHome()
): Promise<WorkspaceTrustContext> {
  try {
    const stat = await fs.stat(cwd);
    if (!stat.isDirectory()) {
      throw new WorkspaceTrustError(`workspace path is not a directory: ${cwd}`, 2);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') {
      throw new WorkspaceTrustError(`workspace path does not exist: ${cwd}`, 2);
    }
    throw error;
  }

  let workspaceRealPath = cwd;
  try {
    workspaceRealPath = await fs.realpath(cwd);
  } catch {
    // fall through with cwd verbatim
  }

  return {
    workspaceRealPath,
    workspaceId: workspaceIdFromRealPath(workspaceRealPath),
    cliqHome
  };
}

function isPersistedDecision(value: unknown): value is PersistedWorkspaceTrustDecision {
  return value === 'trusted' || value === 'denied';
}

export async function readPersistedWorkspaceTrust(
  ctx: WorkspaceTrustContext
): Promise<PersistedWorkspaceTrustDecision | undefined> {
  const target = workspaceTrustRecordPath(ctx);
  try {
    const parsed = JSON.parse(await fs.readFile(target, 'utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      return undefined;
    }
    const rec = parsed as Partial<WorkspaceTrustRecord>;
    if (
      rec.version !== WORKSPACE_TRUST_RECORD_VERSION ||
      typeof rec.workspaceId !== 'string' ||
      typeof rec.workspaceRealPath !== 'string' ||
      !isPersistedDecision(rec.decision) ||
      typeof rec.decidedAt !== 'string'
    ) {
      return undefined;
    }
    if (rec.workspaceId !== ctx.workspaceId) {
      return undefined;
    }
    return rec.decision;
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') {
      return undefined;
    }
    throw error;
  }
}

export async function writePersistedWorkspaceTrust(ctx: WorkspaceTrustContext, decision: PersistedWorkspaceTrustDecision) {
  const record: WorkspaceTrustRecord = {
    version: WORKSPACE_TRUST_RECORD_VERSION,
    workspaceId: ctx.workspaceId,
    workspaceRealPath: ctx.workspaceRealPath,
    decision,
    decidedAt: new Date().toISOString()
  };
  await atomicWriteTrustRecord(workspaceTrustRecordPath(ctx), record);
}

export type WorkspaceTrustDecisionSource = 'env' | 'persisted';

export async function evaluateWorkspaceTrustForNonInteractive(
  ctx: WorkspaceTrustContext,
  env: Record<string, string | undefined> = process.env
): Promise<{ ok: true; source: WorkspaceTrustDecisionSource } | { ok: false; message: string }> {
  let envTrust: ReturnType<typeof parseCliqTrustWorkspaceEnv>;
  try {
    envTrust = parseCliqTrustWorkspaceEnv(env);
  } catch (error) {
    if (error instanceof WorkspaceTrustError) {
      return { ok: false, message: error.message };
    }
    throw error;
  }
  if (envTrust === 'deny') {
    return {
      ok: false,
      message:
        `CLIQ_TRUST_WORKSPACE=deny forbids workspace runtime for "${ctx.workspaceRealPath}". ` +
        `Remove CLIQ_TRUST_WORKSPACE after reviewing the checkout.`
    };
  }
  if (envTrust === 'trust') {
    return { ok: true, source: 'env' };
  }

  const persisted = await readPersistedWorkspaceTrust(ctx);
  if (persisted === 'trusted') {
    return { ok: true, source: 'persisted' };
  }
  if (persisted === 'denied') {
    return {
      ok: false,
      message:
        `This workspace (${ctx.workspaceRealPath}) was previously declined for Cliq trusted access. ${formatTrustResetHint(
          workspaceTrustRecordPath(ctx)
        )}`
    };
  }

  return {
    ok: false,
    message:
      `Cliq refuses to enter an untrusted workspace at "${ctx.workspaceRealPath}" in non-interactive mode. ` +
      `Approve once from a terminal (stdin+stdout both TTY), ` +
      `or set CLIQ_TRUST_WORKSPACE=trust explicitly for CI/headless.`
  };
}
