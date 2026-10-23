// Fixed-data journald observation only, not publication or clock authority.
import assert from 'node:assert/strict';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { PublicationRetirementDiagnostic } from '../../../src/state/publication-retirement-diagnostics.js';
import { decodeInstalledPublicationRetirements } from './installed-publication-retirement.js';

type Sender = Readonly<{
  uid: number; pid: number; invocationId: string; key: string;
}>;
function readRetirementJournal(text: string, expected: Sender, kind: 'original' | 'namespace'): PublicationRetirementDiagnostic | undefined {
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
  const packets = decodeInstalledPublicationRetirements(messages);
  assert.equal(packets.length, 1, kind === 'namespace' ? 'the current Supervisor must emit exactly one namespace retirement group' :
    'the captured Supervisor must emit exactly one original retirement group');
  const packet = packets[0]!;
  assert.equal(packet.kind, kind); assert.equal(packet.key, expected.key);
  return packet;
}

export function readInstalledNamespaceRetirementJournal(text: string, expected: Sender): PublicationRetirementDiagnostic | undefined {
  return readRetirementJournal(text, expected, 'namespace');
}

/** Original dispatch only, never a probe-nonce or process-death assertion. */
export function readInstalledOriginalRetirementJournal(text: string, expected: Sender): PublicationRetirementDiagnostic | undefined {
  return readRetirementJournal(text, expected, 'original');
}
