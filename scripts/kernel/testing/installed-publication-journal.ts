// Fixed-data journald observation only, not publication or clock authority.
import assert from 'node:assert/strict';
import { types } from 'node:util';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { PublicationRetirementDiagnostic } from '../../../src/state/publication-retirement-diagnostics.js';
import { decodeInstalledPublicationRetirements } from './installed-publication-retirement.js';

type Sender = Readonly<{
  uid: number; pid: number; invocationId: string; key: string;
}>;
function readRetirementPackets(text: string, expected: Sender, kind: 'original' | 'namespace'): readonly PublicationRetirementDiagnostic[] | undefined {
  assert(Number.isSafeInteger(expected.uid) && expected.uid > 0);
  assert(Number.isSafeInteger(expected.pid) && expected.pid > 0);
  assert.match(expected.invocationId, /^[0-9a-f]{32}$/u); assert.match(expected.key, /^[0-9a-f]{64}$/u);
  assert(Buffer.byteLength(text, 'utf8') <= 256 * 1024);
  const lines = text.trim().split('\n').filter(Boolean); assert(lines.length <= 80);
  const messages: string[] = [];
  for (const line of lines) {
    const record = parseJsonStrict(line) as Record<string, unknown>;
    assert(record && typeof record === 'object' && !Array.isArray(record));
    assert.equal(record._UID, String(expected.uid)); assert.equal(record._PID, String(expected.pid));
    assert.equal(record._TRANSPORT, 'stdout');
    // User-manager journald enrichment is not universal. Trusted sender
    // metadata plus independent caller-held start/image and lifecycle
    // observations stay mandatory. Retained text cannot establish death.
    if (kind === 'original' || record._SYSTEMD_INVOCATION_ID !== undefined)
      assert.equal(record._SYSTEMD_INVOCATION_ID, expected.invocationId);
    if (typeof record.MESSAGE === 'string' && record.MESSAGE.startsWith('CLIQ_PUBLICATION_RETIRE_V1:')) messages.push(record.MESSAGE);
  }
  if (messages.length === 0) return undefined;
  return decodeInstalledPublicationRetirements(messages);
}

function readRetirementJournal(text: string, expected: Sender, kind: 'original' | 'namespace'): PublicationRetirementDiagnostic | undefined {
  const packets = readRetirementPackets(text, expected, kind);
  if (!packets) return undefined;
  assert.equal(packets.length, 1, kind === 'namespace' ? 'the current Supervisor must emit exactly one namespace retirement group' :
    'the captured Supervisor must emit exactly one original retirement group');
  const packet = packets[0]!;
  assert.equal(packet.kind, kind); assert.equal(packet.key, expected.key);
  return packet;
}

export function readInstalledNamespaceRetirementJournal(text: string, expected: Sender): PublicationRetirementDiagnostic | undefined {
  return readRetirementJournal(text, expected, 'namespace');
}

/** One unfiltered journal window from the same independently live-bracketed
 * current Supervisor. Both distinct keys must come from its complete retained
 * probe graphs. Data matching alone establishes neither those origins nor a
 * process lifetime, deadline crossing, native join or physical late result. */
export function readInstalledLatePublicationRetirementJournal(text: string,
  expected: Omit<Sender, 'key'> & Readonly<{ expiredProbeKey: string; freshProbeKey: string }>):
  readonly [PublicationRetirementDiagnostic, PublicationRetirementDiagnostic] | undefined {
  assert.match(expected.freshProbeKey, /^[0-9a-f]{64}$/u);
  assert.notEqual(expected.expiredProbeKey, expected.freshProbeKey);
  const packets = readRetirementPackets(text, { uid: expected.uid, pid: expected.pid, invocationId: expected.invocationId,
    key: expected.expiredProbeKey }, 'namespace');
  if (!packets) return undefined;
  assert.equal(packets.length, 2, 'the current Supervisor must emit exactly the expired-then-fresh namespace retirement groups');
  const [expired, fresh] = packets;
  assert.equal(expired!.kind, 'namespace'); assert.equal(expired!.key, expected.expiredProbeKey);
  assert.equal(fresh!.kind, 'namespace'); assert.equal(fresh!.key, expected.freshProbeKey);
  return Object.freeze([expired!, fresh!] as const);
}

/** Original dispatch only, never a probe-nonce or process-death assertion. */
export function readInstalledOriginalRetirementJournal(text: string, expected: Sender): PublicationRetirementDiagnostic | undefined {
  return readRetirementJournal(text, expected, 'original');
}

const SERVER_AUTH_STAGES = ['image_hash', 'process_cas', 'principal_cas', 'peer_cas', 'channel_cas'] as const;
type ServerAuthenticationPhase = 'publish_started' | `${typeof SERVER_AUTH_STAGES[number]}_${'completed' | 'failed'}`;
export type InstalledServerAuthenticationObservation = Readonly<{
  ordinal: number; phase: ServerAuthenticationPhase; elapsedNs: number;
}>;

/** One complete, unfiltered journal window from an independently identified
 * original server. Prefixes and independent JS-await spans are diagnosis only,
 * never authentication success, native timing, process death or authority. */
export function readInstalledServerAuthenticationJournal(text: string,
  expected: Readonly<{ uid: number; pid: number; invocationId: string }>):
  readonly InstalledServerAuthenticationObservation[] | undefined {
  // Fixed text avoids untrusted metadata and assertion source reconstruction.
  function need(value: unknown): asserts value { assert(value, 'invalid fixed server authentication journal data'); }
  need(typeof text === 'string');
  need(expected && typeof expected === 'object' && !types.isProxy(expected) && !Array.isArray(expected));
  need([Object.prototype, null].includes(Object.getPrototypeOf(expected)));
  const fields = Object.getOwnPropertyDescriptors(expected), keys = Reflect.ownKeys(fields);
  need(keys.length === 3);
  for (const key of ['uid', 'pid', 'invocationId'])
    need(Object.hasOwn(fields, key) && fields[key]!.enumerable && Object.hasOwn(fields[key]!, 'value'));
  const { uid, pid, invocationId } = Object.fromEntries(keys.map(key => {
    need(typeof key === 'string' && ['uid', 'pid', 'invocationId'].includes(key));
    return [key, fields[key]!.value];
  }));
  need(Number.isSafeInteger(uid) && uid > 0); need(Number.isSafeInteger(pid) && pid > 0);
  need(typeof invocationId === 'string' && /^[0-9a-f]{32}$/u.test(invocationId));
  need(Buffer.byteLength(text, 'utf8') <= 256 * 1024);
  const lines = text.trim().split('\n').filter(Boolean); need(lines.length <= 80);
  const observations: InstalledServerAuthenticationObservation[] = [];
  const stages = new Map<number, { image: 'pending' | 'completed' | 'failed'; cas: Set<string> }>();
  let previousOrdinal: number | undefined;
  for (const line of lines) {
    const record = parseJsonStrict(line) as Record<string, unknown>;
    need(record && typeof record === 'object' && !Array.isArray(record));
    need(record._UID === String(uid)); need(record._PID === String(pid));
    need(record._TRANSPORT === 'stdout'); need(record._SYSTEMD_INVOCATION_ID === invocationId);
    need(typeof record.MESSAGE === 'string');
    if (!record.MESSAGE.startsWith('CLIQ_SERVER_AUTH_V1')) continue;
    const matched = /^CLIQ_SERVER_AUTH_V1:([1-9][0-9]{0,15}):(publish_started|(?:image_hash|process_cas|principal_cas|peer_cas|channel_cas)_(?:completed|failed)):(0|[1-9][0-9]{0,15})$/u.exec(record.MESSAGE);
    need(matched && matched[0] === record.MESSAGE && observations.length < 64);
    const ordinal = Number(matched[1]), phase = matched[2] as ServerAuthenticationPhase, elapsedNs = Number(matched[3]);
    need(Number.isSafeInteger(ordinal) && ordinal > 0 && Number.isSafeInteger(elapsedNs) && elapsedNs >= 0);
    if (phase === 'publish_started') {
      need(elapsedNs === 0 && !stages.has(ordinal));
      need(previousOrdinal === undefined || ordinal === previousOrdinal + 1);
      previousOrdinal = ordinal; stages.set(ordinal, { image: 'pending', cas: new Set() });
    } else {
      const stage = stages.get(ordinal);
      need(stage !== undefined);
      const name = phase.slice(0, phase.lastIndexOf('_'));
      if (name === 'image_hash') {
        need(stage.image === 'pending');
        stage.image = phase.endsWith('_failed') ? 'failed' : 'completed';
      } else {
        // These four complete CAS awaits are concurrent after the image hash.
        // Keep their real completion order, including siblings after failure;
        // no prefix or completion tuple establishes the producer's join.
        need(stage.image === 'completed' && !stage.cas.has(name));
        stage.cas.add(name);
      }
    }
    observations.push(Object.freeze({ ordinal, phase, elapsedNs }));
  }
  return observations.length ? Object.freeze(observations) : undefined;
}
