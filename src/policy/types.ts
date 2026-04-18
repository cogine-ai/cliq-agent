export type PolicyMode = 'auto' | 'confirm-write' | 'read-only' | 'confirm-bash' | 'confirm-all';

export type ToolAccess = 'read' | 'write' | 'exec';

export type PolicyAuthorization = { allowed: true } | { allowed: false; reason: string };

export type PolicyConfirm = (prompt: string) => Promise<boolean>;
