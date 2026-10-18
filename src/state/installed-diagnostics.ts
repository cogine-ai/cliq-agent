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
