// Inert fixed observations only. Never a retirement proof or a clock authority.
import { channel } from 'node:diagnostics_channel';
import { canonicalSha256 } from '../kernel/canonical.js';

export const PUBLICATION_RETIREMENT_CHANNEL = 'cliq.installed.publication.retirement.v1';
export type PublicationRetirementDiagnostic = Readonly<{ version: 1; key: string; kind: 'original' | 'namespace'; joined: true;
  slots: PublicationRetirementSpans }>;
type Span = readonly [calls: number, attempts: number, outcome: 'unavailable'] |
  readonly [calls: number, attempts: number, firstOutcome: 'ok' | 'interrupted' | 'error',
    monotonicEnterNs: string, realtimeEnterNs: string, monotonicReturnNs: string, realtimeReturnNs: string];
/** Fixed positions: arena, arena parent, workspace parent. A null arena means
 * no arena fsync was attempted, not that any missing physical proof is valid. */
export type PublicationRetirementSpans = readonly [Span | null, Span, Span];
function invalid(): never { throw new TypeError('invalid fixed publication retirement diagnostic'); }
function tuple(value: unknown, lengths: readonly number[]): unknown[] {
  if (!Array.isArray(value)) return invalid();
  const fields = Object.getOwnPropertyDescriptors(value) as unknown as Record<string, PropertyDescriptor>, size = fields.length?.value;
  if (!Number.isSafeInteger(size) || !lengths.includes(size) || Reflect.ownKeys(fields).length !== size + 1) return invalid();
  const result: unknown[] = [];
  for (let index = 0; index < size; index++) {
    const field = fields[String(index)];
    if (!field || !Object.hasOwn(field, 'value') || !field.enumerable) return invalid();
    result.push(field.value);
  }
  return result;
}
function span(value: unknown): Span {
  const row = tuple(value, [3, 7]), [calls, attempts, outcome] = row;
  if (!Number.isSafeInteger(calls) || (calls as number) < 1 || (calls as number) > 0xffffffff ||
      !Number.isSafeInteger(attempts) || (attempts as number) < (calls as number) || (attempts as number) > 0xffffffff) return invalid();
  if (outcome === 'unavailable') { if (row.length !== 3) return invalid(); }
  else {
    if (row.length !== 7 || outcome !== 'ok' && outcome !== 'interrupted' && outcome !== 'error') return invalid();
    for (const stamp of row.slice(3))
      if (typeof stamp !== 'string' || !/^(0|[1-9][0-9]{0,19})$/u.test(stamp) || BigInt(stamp) > 18446744073709551615n) return invalid();
    if (BigInt(row[5] as string) < BigInt(row[3] as string) || BigInt(row[6] as string) < BigInt(row[4] as string)) return invalid();
  }
  return Object.freeze(row) as Span;
}
/** Pure closed decoder. It copies data properties without invoking getters;
 * counts >1 explicitly cannot describe a single uninterrupted fsync. */
export function decodePublicationRetirementSpans(value: unknown): PublicationRetirementSpans {
  const rows = tuple(value, [3]);
  return Object.freeze([rows[0] === null ? null : span(rows[0]), span(rows[1]), span(rows[2])]);
}

export function publicationRetirementDiagnosticKey(value: Readonly<{ runId: string; planRef: string; opId: string;
  attempt: number; dispatchId: string; probeNonceDigest: string }>): string {
  return canonicalSha256(['cliq-publication-retirement-diagnostic-v1', value.runId, value.planRef, value.opId,
    value.attempt, value.dispatchId, value.probeNonceDigest]);
}
export type PublicationRetirementDispatch = Readonly<{ runId: string; planRef: string; opId: string; attempt: number; dispatchId: string }>;
/** Initial execution has no probe nonce. Its dispatch-only domain must never
 * be used as attribution or a completion proof for a later reconciliation. */
export function publicationClaimRetirementDiagnosticKey(value: PublicationRetirementDispatch): string {
  return canonicalSha256(['cliq-publication-claim-retirement-diagnostic-v1', value.runId, value.planRef, value.opId,
    value.attempt, value.dispatchId]);
}
export function decodePublicationRetirementDiagnostic(value: unknown): PublicationRetirementDiagnostic {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const fields = Object.getOwnPropertyDescriptors(value), keys = ['version', 'key', 'kind', 'joined', 'slots'];
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !fields[key] || !fields[key]!.enumerable ||
      !Object.hasOwn(fields[key]!, 'value'))) return invalid();
  const version = fields.version!.value, key = fields.key!.value, kind = fields.kind!.value, joined = fields.joined!.value;
  if (version !== 1 || typeof key !== 'string' || !/^[0-9a-f]{64}$/u.test(key) || kind !== 'original' && kind !== 'namespace' || joined !== true) return invalid();
  return Object.freeze({ version, key, kind, joined, slots: decodePublicationRetirementSpans(fields.slots!.value) });
}
const diagnostic = channel(PUBLICATION_RETIREMENT_CHANNEL);
/** Trusted image subscribers must catch their own exceptions: Node reports
 * subscriber throws independently of publish(). Reading and publishing are
 * guarded, and no subscriber means no native read or diagnostic output. */
export function noteJoinedPublicationRetirement(read: () => PublicationRetirementDiagnostic): void {
  if (!diagnostic.hasSubscribers) return;
  try { diagnostic.publish(decodePublicationRetirementDiagnostic(read())); } catch { /* Never an execution or retirement decision. */ }
}
