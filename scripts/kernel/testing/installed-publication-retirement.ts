// Fixed retained data only. These messages and clock comparisons are not a
// process observation, publication permission or native retirement proof.
import { decodePublicationRetirementDiagnostic,
  type PublicationRetirementDiagnostic } from '../../../src/state/publication-retirement-diagnostics.js';

const PREFIX = 'CLIQ_PUBLICATION_RETIRE_V1:';
const MAX_FRAMES = 129, MAX_MESSAGE_BYTES = 255;
const invalid = (): never => { throw new TypeError('invalid installed publication retirement messages'); };

function messages(value: unknown): string[] {
  if (!Array.isArray(value)) return invalid();
  const fields = Object.getOwnPropertyDescriptors(value) as unknown as Record<string, PropertyDescriptor>;
  const length = fields.length?.value;
  if (!Number.isSafeInteger(length) || length < 4 || length > MAX_FRAMES || length % 4 !== 0 ||
      Reflect.ownKeys(fields).length !== length + 1) return invalid();
  const result: string[] = [];
  for (let index = 0; index < length; index++) {
    const field = fields[String(index)];
    if (!field || !field.enumerable || !Object.hasOwn(field, 'value') || typeof field.value !== 'string' ||
        field.value.length > MAX_MESSAGE_BYTES || !/^[\x20-\x7e]+$/u.test(field.value) || !field.value.startsWith(PREFIX)) return invalid();
    result.push(field.value);
  }
  return result;
}

/** One journal MESSAGE is one LF-free ASCII frame. There is no permissive
 * text filtering: missing/truncated/interleaved/duplicate groups are a miss. */
export function decodeInstalledPublicationRetirements(value: unknown): readonly PublicationRetirementDiagnostic[] {
  const input = messages(value), seen = new Set<string>(), result: PublicationRetirementDiagnostic[] = [];
  for (let offset = 0; offset < input.length; offset += 4) {
    const slots: unknown[] = []; let key: string | undefined, kind: string | undefined;
    for (let index = 0; index < 4; index++) {
      const frame = input[offset + index]!.slice(PREFIX.length).split(':');
      const [frameKey, frameKind, slot, ...row] = frame;
      if (!frameKey || !/^[0-9a-f]{64}$/u.test(frameKey) || frameKind !== 'original' && frameKind !== 'namespace' ||
          slot !== (index === 3 ? 'joined' : String(index))) return invalid();
      if (index === 0) { key = frameKey; kind = frameKind; }
      if (frameKey !== key || frameKind !== kind) return invalid();
      if (index === 3) { if (row.length !== 0) return invalid(); continue; }
      if (row.length === 1 && row[0] === 'none' && index === 0) { slots.push(null); continue; }
      if (row.length !== 3 && row.length !== 7 || !/^[1-9][0-9]{0,9}$/u.test(row[0]!) || !/^[1-9][0-9]{0,9}$/u.test(row[1]!)) return invalid();
      slots.push([Number(row[0]), Number(row[1]), ...row.slice(2)]);
    }
    const identity = `${key}:${kind}`;
    if (seen.has(identity)) return invalid();
    seen.add(identity);
    result.push(decodePublicationRetirementDiagnostic({ version: 1, key, kind, joined: true, slots }));
  }
  return Object.freeze(result);
}

function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !fields[key]?.enumerable || !Object.hasOwn(fields[key]!, 'value'))) return invalid();
  return Object.fromEntries(keys.map(key => [key, fields[key]!.value]));
}
function nanoseconds(value: unknown): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/u.test(value) || BigInt(value) > 18446744073709551615n) return invalid();
  return BigInt(value);
}

/** Necessary fixed-data overlap only. The caller independently binds key to
 * the original CAS claim/probe and obtains actual native/actor observations.
 * Arena slot zero, aggregate counts and adjacent intervals cannot qualify. */
export function isOriginalPublicationRetirementSignalBracket(packetInput: unknown, expectedKey: unknown, signalInput: unknown): boolean {
  const packet = decodePublicationRetirementDiagnostic(packetInput);
  if (typeof expectedKey !== 'string' || !/^[0-9a-f]{64}$/u.test(expectedKey)) return invalid();
  const signal = record(signalInput, ['monotonicEnterNs', 'realtimeEnterNs', 'monotonicReturnNs', 'realtimeReturnNs']);
  const enter = nanoseconds(signal.monotonicEnterNs), realEnter = nanoseconds(signal.realtimeEnterNs),
    returned = nanoseconds(signal.monotonicReturnNs), realReturned = nanoseconds(signal.realtimeReturnNs);
  if (returned < enter || realReturned < realEnter) return invalid();
  if (packet.kind !== 'original' || packet.key !== expectedKey) return false;
  return [packet.slots[1], packet.slots[2]].some(span => span.length === 7 && span[0] === 1 && span[1] === 1 && span[2] === 'ok' &&
    BigInt(span[3]) < enter && returned < BigInt(span[5]) && BigInt(span[4]) < realEnter && realReturned < BigInt(span[6]));
}

/** Independent unchanged stop bound, measured from original signal entry;
 * containment in fsync never implies this actual actor join was timely. */
export function isPublicationSignalActorJoinedWithinStop(input: unknown): boolean {
  const value = record(input, ['monotonicSignalEnterNs', 'monotonicJoinedNs']);
  const started = nanoseconds(value.monotonicSignalEnterNs), joined = nanoseconds(value.monotonicJoinedNs);
  if (joined < started) return invalid();
  return joined - started <= 2_000_000_000n;
}
