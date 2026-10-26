import { createInstalledResourceSink } from './installed-resource-sink.js';
import assert from 'node:assert/strict';
import test from 'node:test';
import { RESOURCE_ROLES, RESOURCE_BOUNDARIES, RESOURCE_BITS, type ResourceNumbers } from '../../../src/state/installed-resource-kernel.js';
import { ResourceRetirementError } from '../../../src/state/errors.js';
import { createCredentialSecretScanner } from './credential-secret-scan.js';
import { decodeInstalledResourceLine, installedResourceLine, replayScannedResourceLines, INSTALLED_RESOURCE_PREFIX } from './installed-resource-wire.js';
const observed: ResourceNumbers = Object.freeze({ mask: RESOURCE_BITS.group | RESOURCE_BITS.memory | RESOURCE_BITS.memoryPeak,
  joined: 1, unavailable: 0, memory: 17, memoryPeak: 23, tasks: 0, tasksPeak: 0, cpu: 0, oom: 0, oomKill: 0,
  descriptors: 0, nofileSoft: 0, nofileHard: 0, memoryMax: 0, tasksMax: 0, cpuQuota: 0, cpus: 0, machineMemory: 0, machineAvailable: 0 });
const line = (numbers = observed) => installedResourceLine({ role: 'supervisor', boundary: 'preparation_ready', numbers });
test('all five roles and eight boundaries have one closed canonical numeric line, bounded to 40/16KiB', () => {
  const lines = RESOURCE_ROLES.flatMap(role => RESOURCE_BOUNDARIES.map(boundary => installedResourceLine({ role, boundary, numbers: observed })));
  assert.equal(lines.length, 40); assert(Buffer.concat(lines).length < 16384);
  for (const original of lines) assert.deepEqual(installedResourceLine(decodeInstalledResourceLine(original)), original);
  const output: Buffer[] = [], original = Buffer.concat(lines);
  assert.equal(replayScannedResourceLines(original, bytes => output.push(bytes)), 40);
  assert(Buffer.concat(output).equals(original));
  assert.throws(() => replayScannedResourceLines(Buffer.concat([original, line()]), () => {}));
});
test('unavailable/partial/foreign/wrong-mask/overflow data cannot be relabeled as genuine measurements', () => {
  for (const bytes of [line().subarray(0, -1), Buffer.from(line().toString().replace(':17:', ':017:')),
    Buffer.from(line().toString().replace(INSTALLED_RESOURCE_PREFIX + '0:', INSTALLED_RESOURCE_PREFIX + '5:')),
    Buffer.from(line().toString().replace(':17:', ':9007199254740992:')), Buffer.concat([line(), Buffer.from('x')])])
    assert.throws(() => decodeInstalledResourceLine(bytes));
  assert.throws(() => line({ ...observed, mask: RESOURCE_BITS.group, memoryPeak: 23 }));
  assert.throws(() => line({ ...observed, unavailable: 1 }));
  assert.throws(() => line({ ...observed, joined: 0 }));
  assert.throws(() => line({ ...observed, mask: 0, memory: 0, memoryPeak: 0, joined: 1, unavailable: 3 }));
  const failed: ResourceNumbers = { ...observed, mask: 0, memory: 0, memoryPeak: 0, joined: 0, unavailable: 3 };
  assert.throws(() => replayScannedResourceLines(line(failed), () => {}), ResourceRetirementError);
  let getters = 0;
  assert.throws(() => installedResourceLine({ get role() { getters++; return 'supervisor' as const; }, boundary: 'preparation_ready', numbers: observed }));
  assert.throws(() => installedResourceLine(new Proxy({}, { get() { getters++; return undefined; } }) as never));
  assert.equal(getters, 0);
});
test('original stdout/stderr scan completes before exact same-byte replay; JSON keys are never newly printed', () => {
  const original = Buffer.concat([Buffer.from('other already-scanned original line\n'), line()]), stderr = Buffer.from('other original stderr\n');
  const scanner = createCredentialSecretScanner([Buffer.from('memoryPeak')], { maxBytes: 8192, maxStreams: 2 });
  const out = scanner.openStream(), err = scanner.openStream(), writes: Buffer[] = [];
  try { out.scan(original); err.scan(stderr); }
  finally { out.close(); err.close(); }
  replayScannedResourceLines(original, bytes => { assert(original.includes(bytes)); writes.push(bytes); });
  assert.deepEqual(writes, [line()]); assert(!writes[0]!.includes(Buffer.from('memoryPeak')));
  const refusal = createCredentialSecretScanner([Buffer.from(INSTALLED_RESOURCE_PREFIX)], { maxBytes: 8192, maxStreams: 2 });
  let emitted = false; const guarded = refusal.openStream();
  assert.throws(() => { try { guarded.scan(original); } finally { guarded.close(); }
    replayScannedResourceLines(original, () => { emitted = true; }); });
  assert.equal(emitted, false);
});

test('a later cleanup failure survives role deduplication and the reserved final record', () => {
  const output: Buffer[] = [], sink = createInstalledResourceSink(bytes => { output.push(bytes); return bytes.length; });
  for (const role of RESOURCE_ROLES) for (const boundary of RESOURCE_BOUNDARIES) sink({ role, boundary, numbers: observed });
  assert.equal(output.length, 39);
  sink({ role: 'supervisor', boundary: 'preparation_ready', numbers: { ...observed, mask: 0, memory: 0, memoryPeak: 0, joined: 0, unavailable: 3 } });
  assert.equal(output.length, 40); assert(Buffer.concat(output).length <= 16384);
  assert.equal(decodeInstalledResourceLine(output.at(-1)!).numbers.joined, 0);
  assert.throws(() => replayScannedResourceLines(Buffer.concat(output), () => {}), ResourceRetirementError);
});
