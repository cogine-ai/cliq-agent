// Root-owned, non-secret experiment selection and one bounded stdin lifetime.
// Neither input registers authority, changes a budget or starts a model call.
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import type { Readable } from 'node:stream';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { RunSpec } from '../../../src/kernel/types.js';
import { exactKeys } from '../../../src/policy/runtime-authority.js';
import { providerModelDefinition, type InstalledProviderModelDefinition } from '../installed-provider-model.js';

export type ProviderJourneyConfiguration = Readonly<{ definition: InstalledProviderModelDefinition; budgets: RunSpec['budgets'] }>;

export function decodeProviderJourneyConfiguration(value: unknown): ProviderJourneyConfiguration {
  assert(value && typeof value === 'object' && !Array.isArray(value) && exactKeys(value, ['definition', 'budgets']),
    'provider journey requires only its non-secret model and explicit budgets');
  const input = value as ProviderJourneyConfiguration, definition = providerModelDefinition(input.definition);
  assert.equal(definition.model, 'deepseek-flash');
  assert.deepEqual(definition.target, { hostAscii: 'api.deepseek.com', port: 443, basePath: '/' });
  assert.equal(definition.tls.serverNameAscii, 'api.deepseek.com');
  assert.equal(definition.claims.nativeToolCalling, true); assert.equal(definition.claims.trustedUsageEvidence, false);
  // This experiment reserves the published whole-request context and output
  // maxima at the non-discount price, including cache as an independent upper
  // component. Input estimates and returned usage never reduce that reserve.
  assert(definition.prices.input >= 300000 && definition.prices.output >= 1200000 && definition.prices.cacheRead >= 6000);
  assert.equal(definition.prices.cacheWrite, 0);
  assert(definition.requestTokenCeiling.inputTokens >= 1048576 && definition.requestTokenCeiling.outputTokens >= 393216 &&
    definition.requestTokenCeiling.cacheReadTokens >= 1048576);
  const budget = input.budgets;
  assert(budget && exactKeys(budget, ['wallTimeMs', 'modelTokens', 'costMicros', 'toolCalls', 'repairAttempts', 'childDepth', 'childConcurrency']));
  for (const [field, limit] of Object.entries(budget)) assert(Number.isSafeInteger(limit) && limit >=
    (field === 'repairAttempts' || field === 'childDepth' ? 0 : 1), 'provider experiment budgets must be explicit finite integers');
  return { definition, budgets: Object.freeze({ ...budget }) };
}

export async function readProviderJourneyConfiguration(filename: string): Promise<ProviderJourneyConfiguration> {
  assert.equal(await realpath(filename), filename, 'provider configuration may not traverse aliases');
  const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await held.stat({ bigint: true });
    assert(before.isFile() && before.uid === 0n && before.gid === 0n && before.nlink === 1n &&
      [0o400n, 0o444n].includes(before.mode & 0o7777n) && before.size > 0n && before.size <= 65536n,
    'provider configuration must be a bounded root-owned immutable file');
    const data = Buffer.alloc(Number(before.size) + 1); let count = 0;
    for (;;) {
      const read = await held.read(data, count, data.length - count, null); count += read.bytesRead;
      assert(count < data.length, 'provider configuration grew during its complete read');
      if (!read.bytesRead) break;
    }
    const after = await held.stat({ bigint: true }), named = await lstat(filename, { bigint: true });
    for (const field of ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const) {
      assert.equal(before[field], after[field]); assert.equal(after[field], named[field]);
    }
    assert.equal(BigInt(count), before.size);
    const bytes = data.subarray(0, count), value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    assert(canonicalJsonBytes(value).equals(bytes), 'provider configuration must contain exact canonical bytes');
    return decodeProviderJourneyConfiguration(value);
  } finally { await held.close(); }
}

/** Caller supplies bytes only after the fixed ready marker. Read EOF before
 * any build/installation child can inherit stdin; retain no string/key file.
 * The returned sole owned copy must be zeroed by that caller in finally. */
export async function readProviderJourneySecret(input: Readable): Promise<Buffer> {
  const secret = Buffer.alloc(4097); let size = 0;
  const timeout = setTimeout(() => input.destroy(new Error('provider secret stdin did not close within thirty seconds')), 30_000);
  try {
    for await (const bytes of input) {
      assert(Buffer.isBuffer(bytes), 'provider secret must arrive as raw stdin bytes');
      try {
        assert(size + bytes.length <= 4096, 'provider secret input exceeds its fixed bound');
        bytes.copy(secret, size); size += bytes.length;
      } finally { bytes.fill(0); }
    }
    assert(size > 0, 'provider secret stdin is empty');
    return secret.subarray(0, size);
  } catch (error) {
    secret.fill(0); throw error;
  } finally { clearTimeout(timeout); }
}
