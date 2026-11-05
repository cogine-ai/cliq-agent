// Passive fixed MCP Admin boundaries. These observations cannot establish a
// claim, successful protocol, process death, FD join or permission to retry.
import { types } from 'node:util';
import { classifyInstalledRequestError, INSTALLED_REQUEST_FAILURE_KINDS, INSTALLED_REQUEST_FAILURE_CODES } from './installed-request-diagnostics.js';
export const MCP_ADMIN_LIFECYCLE_PHASES = Object.freeze(['launcher_open', 'controller_start', 'native_prepare', 'plan_publish',
  'prepared_write', 'input_create', 'scope_reserve', 'scope_ready', 'claim_write', 'protocol', 'discovery_publish',
  'native_close', 'scope_close', 'controller_close', 'launcher_close', 'retained_cleanup'] as const);
export type McpAdminLifecyclePhase = typeof MCP_ADMIN_LIFECYCLE_PHASES[number];
export type McpAdminLifecycleObservation = Readonly<{ transport: 'http' | 'stdio'; phase: McpAdminLifecyclePhase;
  event: 'entered' | 'settled' | 'failed'; errorClass: typeof INSTALLED_REQUEST_FAILURE_KINDS[number] | null;
  code: typeof INSTALLED_REQUEST_FAILURE_CODES[number] | null }>;
const observers = new Set<(observation: McpAdminLifecycleObservation) => void>();
export function observeMcpAdminLifecycle(observer: (observation: McpAdminLifecycleObservation) => void): () => void {
  if (typeof observer !== 'function' || types.isProxy(observer)) throw new TypeError('MCP Admin observer must be a fixed function');
  observers.add(observer); return () => { observers.delete(observer); };
}
export function decodeMcpAdminLifecycleObservation(value: unknown): McpAdminLifecycleObservation {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('invalid fixed MCP Admin observation');
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = ['transport', 'phase', 'event', 'errorClass', 'code'];
  if (Reflect.ownKeys(descriptors).length !== keys.length || keys.some(key => !descriptors[key] ||
      !Object.hasOwn(descriptors[key]!, 'value') || !descriptors[key]!.enumerable)) throw new TypeError('invalid fixed MCP Admin observation fields');
  const row = Object.fromEntries(keys.map(key => [key, descriptors[key]!.value]));
  if (!['http', 'stdio'].includes(row.transport) || !MCP_ADMIN_LIFECYCLE_PHASES.includes(row.phase) ||
      !['entered', 'settled', 'failed'].includes(row.event) ||
      (row.event === 'failed' ? !INSTALLED_REQUEST_FAILURE_KINDS.includes(row.errorClass) ||
        (row.errorClass === 'kernel_storage' ? !INSTALLED_REQUEST_FAILURE_CODES.includes(row.code) : row.code !== null)
        : row.errorClass !== null || row.code !== null)) throw new TypeError('invalid fixed MCP Admin observation values');
  return Object.freeze(row) as McpAdminLifecycleObservation;
}
export function noteMcpAdminLifecycle(transport: 'http' | 'stdio', phase: McpAdminLifecyclePhase,
  event: 'entered' | 'settled' | 'failed', error?: unknown): void {
  if (!observers.size) return;
  try {
    const failure = event === 'failed' ? classifyInstalledRequestError(error) : undefined;
    const observation = decodeMcpAdminLifecycleObservation({ transport, phase, event, errorClass: failure?.kind ?? null, code: failure?.code ?? null });
    for (const observer of [...observers]) try { observer(observation); } catch { /* Measurement cannot replace the producer or its join. */ }
  } catch { /* Unavailable diagnosis never changes the original operation. */ }
}
/** Enter the original operation synchronously. With no observer the exact
 * original Promise or synchronous throw is returned, without another await.
 * Call outside the fresh SQL gate -> native release critical section. */
export function observeMcpAdminWork<T>(transport: 'http' | 'stdio', phase: McpAdminLifecyclePhase, operation: () => Promise<T>): Promise<T> {
  if (!observers.size) return operation();
  noteMcpAdminLifecycle(transport, phase, 'entered');
  let task: Promise<T>;
  try { task = operation(); } catch (error) { noteMcpAdminLifecycle(transport, phase, 'failed', error); throw error; }
  return task.then(value => { noteMcpAdminLifecycle(transport, phase, 'settled'); return value; },
    error => { noteMcpAdminLifecycle(transport, phase, 'failed', error); throw error; });
}
