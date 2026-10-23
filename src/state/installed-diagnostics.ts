import { channel } from 'node:diagnostics_channel';

export const INSTALLED_CREDENTIAL_PHASE_CHANNEL = 'cliq.installed.credential.phase.v1';
export const INSTALLED_CREDENTIAL_PHASES = Object.freeze(['open_selected', 'history', 'first_supervisor', 'secret_input',
  'second_supervisor', 'platform_store', 'finalize', 'retire'] as const);
export type InstalledCredentialPhase = typeof INSTALLED_CREDENTIAL_PHASES[number];

const phases: ReadonlySet<string> = new Set(INSTALLED_CREDENTIAL_PHASES);
const credential = channel(INSTALLED_CREDENTIAL_PHASE_CHANNEL);

/** Inert phase data only. Subscribers belong to trusted image composition and
 * must catch their own errors: Node reports subscriber throws independently of
 * publish(). No diagnostic result participates in credential decisions. */
export function noteInstalledCredentialPhase(phase: InstalledCredentialPhase): void {
  if (!credential.hasSubscribers || typeof phase !== 'string' || !phases.has(phase)) return;
  try { credential.publish(phase); } catch { /* A diagnostic never decides an operation. */ }
}

export const INSTALLED_CLIENT_PHASE_CHANNEL = 'cliq.installed.client.authentication.v1';
export const INSTALLED_CLIENT_PHASES = Object.freeze(['manager_observer_loaded', 'initial_current_observed', 'native_connected',
  'pre_hello_current_verified', 'hello_exchange_started', 'hello_received', 'final_current_verified'] as const);
export type InstalledClientPhase = typeof INSTALLED_CLIENT_PHASES[number];
const clientPhases: ReadonlySet<string> = new Set(INSTALLED_CLIENT_PHASES);
const client = channel(INSTALLED_CLIENT_PHASE_CHANNEL);

/** Fixed diagnostic boundaries only, not authentication or delivery evidence.
 * Trusted subscribers must catch their own errors, as for credential phases. */
export function noteInstalledClientPhase(phase: InstalledClientPhase): void {
  if (!client.hasSubscribers || typeof phase !== 'string' || !clientPhases.has(phase)) return;
  try { client.publish(phase); } catch { /* A diagnostic never decides an operation. */ }
}

export const INSTALLED_SERVER_AUTHENTICATION_CHANNEL = 'cliq.installed.server.authentication.v1';
export const INSTALLED_SERVER_AUTHENTICATION_PHASES = Object.freeze(['image_hash', 'process_cas', 'principal_cas', 'peer_cas', 'channel_cas'] as const);
type ServerAuthenticationPhase = typeof INSTALLED_SERVER_AUTHENTICATION_PHASES[number];
const serverPhases: ReadonlySet<string> = new Set(INSTALLED_SERVER_AUTHENTICATION_PHASES);
const server = channel(INSTALLED_SERVER_AUTHENTICATION_CHANNEL);
let serverOrdinal = 0;

/** Fixed trusted-composition observation only. These are complete JS await
 * spans, never native fsync intervals, authentication or deadline authority.
 * An ordinary image has no subscriber: no clock, ordinal, tuple or task. */
export function beginInstalledServerAuthentication(): (<T>(phase: ServerAuthenticationPhase, operation: () => Promise<T>) => Promise<T>) | undefined {
  if (!server.hasSubscribers || serverOrdinal >= Number.MAX_SAFE_INTEGER) return;
  const ordinal = ++serverOrdinal;
  const emit = (phase: string, elapsedNs: number) => {
    try { server.publish(Object.freeze({ ordinal, phase, elapsedNs })); } catch { /* Diagnostic only. */ }
  };
  emit('publish_started', 0);
  return async <T>(phase: ServerAuthenticationPhase, operation: () => Promise<T>): Promise<T> => {
    if (typeof phase !== 'string' || !serverPhases.has(phase)) return operation();
    let started: bigint | undefined;
    try { started = process.hrtime.bigint(); } catch { /* Missing clocks never replace an operation. */ }
    const completed = (outcome: 'completed' | 'failed') => {
      try {
        if (started === undefined) return;
        const elapsed = process.hrtime.bigint() - started;
        if (elapsed >= 0n && elapsed <= BigInt(Number.MAX_SAFE_INTEGER)) emit(phase + '_' + outcome, Number(elapsed));
      } catch { /* Never turn missing diagnostic data into an operation failure. */ }
    };
    try { const value = await operation(); completed('completed'); return value; }
    catch (error) { completed('failed'); throw error; }
  };
}
