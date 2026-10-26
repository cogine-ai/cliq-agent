// Data/output regressions only. No native result, accepted Run or death permit
// is fabricated by these fixtures.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { builtinToolInputBytes, decodeBuiltinToolInput } from '../sandbox/builtin-tool-data.js';
import { builtinCaptureModelContent, decodeBuiltinToolCapture, retainBuiltinCapturePublication,
  assertBuiltinCaptureObservation, type BuiltinToolCaptureV1 } from './builtin-tool-capture.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { acknowledgeNativeBuiltinToolResult, type LinuxBlockedInvocation, type NativeBuiltinToolResult } from '../sandbox/linux-worker.js';
import type { ToolObservationV1 } from '../kernel/tool-authorization.js';

function capture(stdout: Uint8Array, stderr = Buffer.alloc(0)): BuiltinToolCaptureV1 {
  const ref = 'a'.repeat(64), value: BuiltinToolCaptureV1 = { schemaVersion: 1, format: 'cliq-builtin-tool-capture-v1',
    runId: 'run', opId: 'op', attempt: 1, dispatchId: 'dispatch', leaseEpoch: 1, tool: 'bash', requestRef: ref, targetRef: ref,
    grantRef: ref, sandboxLaunchSpecRef: ref, startedAt: '2026-01-01T00:00:00.000Z', endedAt: '2026-01-01T00:00:00.001Z',
    durationMs: 1, terminationReason: 'exit', exitCode: 7, stdoutRef: ref, stdoutByteCount: stdout.length,
    stderrRef: ref, stderrByteCount: stderr.length, stdoutTruncated: false, stderrTruncated: false,
    containmentRef: ref, deathEvidenceRef: ref, captureDigest: '' };
  value.captureDigest = digestOmitting(value, 'captureDigest'); return value;
}
const capsule = (tool: 'bash' | 'read') => decodeBuiltinToolInput(builtinToolInputBytes(tool,
  tool === 'bash' ? { command: 'exit 7' } : { path: 'note.txt' }, { maxSingleFileBytes: 268435456, maxInvocationOutputBytes: 67108864 }));

test('builtin model output preserves real nonzero termination, binary encoding and independent clipping', () => {
  const stdout = Buffer.alloc(70000, 0), stderr = Buffer.from([0xff, 10]), observed = capture(stdout, stderr);
  const content = builtinCaptureModelContent(observed, stdout, stderr, capsule('bash')) as any;
  assert.equal(content.terminationReason, 'exit'); assert.equal(content.exitCode, 7);
  assert.equal(content.stdout.encoding, 'utf8_lossy'); assert.equal(content.stdout.byteCount, 70000);
  assert.equal(content.stdout.nativeTruncated, false); assert.equal(content.stdout.modelTruncated, true);
  assert.equal(content.stderr.text, '\ufffd\n'); assert.equal(content.stderr.modelTruncated, false);
  assert(canonicalJsonBytes(content).length <= 1048576);
  assert.equal(Object.hasOwn(content, 'stdoutRef'), false); assert.equal(Object.hasOwn(content, 'deathEvidenceRef'), false);
  assert.throws(() => builtinCaptureModelContent(observed, stdout.subarray(1), stderr, capsule('bash')), /original bytes/u);
});

test('read output retains its truthful partial frame; native truncation or foreign normalized input is rejected', () => {
  const frame = canonicalJsonBytes({ schemaVersion: 1, tool: 'read', scope: 'private_generation_non_git', path: 'note.txt', complete: false,
    reasons: ['output_limit'], scannedEntries: 1,
    content: { startLine: 1, endLine: 1, fileByteCount: 20, bytesRead: 20, text: 'sample', truncated: true, reachedEof: false } });
  const data = { ...capture(frame), tool: 'read' as const, exitCode: 0 };
  data.captureDigest = digestOmitting(data, 'captureDigest');
  const decoded = decodeBuiltinToolCapture(data), projected = builtinCaptureModelContent(decoded, frame, Buffer.alloc(0), capsule('read')) as any;
  assert.equal(projected.result.complete, false); assert.deepEqual(projected.result.reasons, ['output_limit']);
  assert.throws(() => builtinCaptureModelContent({ ...decoded, stdoutTruncated: true }, frame, Buffer.alloc(0), capsule('read')), /truncated/u);
  const foreign = decodeBuiltinToolInput(builtinToolInputBytes('read', { path: 'other.txt' }, capsule('read').limits));
  assert.throws(() => builtinCaptureModelContent(decoded, frame, Buffer.alloc(0), foreign));
});

test('closed capture decoder rejects foreign fields, termination substitutions, accessors and proxies without executing them', () => {
  const data = capture(Buffer.from('output'));
  assert.deepEqual(decodeBuiltinToolCapture(data), data);
  for (const change of [{ exitCode: 256 }, { terminationReason: 'timeout' }, { stdoutByteCount: 67108865 },
    { endedAt: '2025-01-01T00:00:00.000Z' }, { stdoutTruncated: 1 }, { runtimePermit: true }]) {
    const value = { ...data, ...change }; value.captureDigest = digestOmitting(value, 'captureDigest');
    assert.throws(() => decodeBuiltinToolCapture(value));
  }
  let calls = 0;
  const accessor = { ...data }; Object.defineProperty(accessor, 'terminationReason', { enumerable: true, get() { calls++; return 'exit'; } });
  assert.throws(() => decodeBuiltinToolCapture(accessor));
  const proxy = new Proxy(data, { ownKeys() { calls++; return []; }, get() { calls++; return undefined; },
    getOwnPropertyDescriptor() { calls++; return undefined; }, getPrototypeOf() { calls++; return Object.prototype; } });
  assert.throws(() => decodeBuiltinToolCapture(proxy)); assert.equal(calls, 0);
  const coercion = { [Symbol.toPrimitive]() { calls++; return 'exit'; } };
  assert(data.terminationReason === 'exit');
  const { exitCode: _exitCode, ...closedData } = data;
  assert.throws(() => decodeBuiltinToolCapture({ ...closedData, terminationReason: coercion })); assert.equal(calls, 0);
});

test('an inert death object cannot start builtin result publication', () => {
  let writes = 0;
  const artifacts = { publishBytes() { writes++; throw new Error('must not publish'); } } as unknown as ArtifactCatalog;
  assert.throws(() => retainBuiltinCapturePublication(artifacts, {} as any, {} as any, {} as any,
    { death: {} } as any, capsule('bash'))); assert.equal(writes, 0);
});

test('retained capture data, copied bytes and proxy handles cannot acknowledge an original native result', async () => {
  let accessed = 0;
  const producer = new Proxy({}, { get() { accessed++; throw new Error('a forged producer must not be inspected'); } }) as LinuxBlockedInvocation;
  const raw = capture(Buffer.from('output'));
  const proxy = new Proxy({}, { get() { accessed++; throw new Error('a forged result must not be inspected'); } });
  for (const result of [raw, { ...raw, stdout: Buffer.from('output'), stderr: Buffer.alloc(0) }, proxy])
    await assert.rejects(acknowledgeNativeBuiltinToolResult(producer, result as unknown as NativeBuiltinToolResult), TypeError);
  assert.equal(accessed, 0);
});

test('retained controller-stop projection never invents user cancellation or no-effect evidence', () => {
  const stdout = Buffer.from('entered before Supervisor close\n'), original = capture(stdout);
  assert(original.terminationReason === 'exit');
  const { exitCode: _exit, ...data } = original;
  const observed = { ...data, terminationReason: 'controller_stop' as const };
  observed.captureDigest = digestOmitting(observed, 'captureDigest');
  const content = builtinCaptureModelContent(decodeBuiltinToolCapture(observed), stdout, Buffer.alloc(0), capsule('bash')) as any;
  assert.equal(content.terminationReason, 'controller_stop'); assert.equal(Object.hasOwn(content, 'exitCode'), false);
  assert.equal(Object.hasOwn(content, 'cancelledByUser'), false); assert.equal(Object.hasOwn(content, 'noEffect'), false);
  assert.equal(content.stdout.text, stdout.toString('utf8'));
});

test('a valid large structured result is projected as an explicit prefix without losing original completeness or raw bytes', () => {
  const names = Array.from({ length: 200 }, (_, index) => `${Array(15).fill('a'.repeat(250)).join('/')}/file${index}`);
  const stdout = canonicalJsonBytes({ schemaVersion: 1, tool: 'find', scope: 'private_generation_non_git', path: '.',
    complete: true, reasons: [], scannedEntries: 200, content: names });
  assert(stdout.length < 1048576);
  const stderr = Buffer.alloc(65536, 0), data = { ...capture(stdout, stderr), tool: 'find' as const, exitCode: 0 };
  data.captureDigest = digestOmitting(data, 'captureDigest');
  const original = Buffer.from(stdout), input = decodeBuiltinToolInput(builtinToolInputBytes('find', { path: '.', name: 'file' }, capsule('read').limits));
  const content = builtinCaptureModelContent(decodeBuiltinToolCapture(data), stdout, stderr, input) as any;
  assert.equal(content.modelTruncated, true); assert.equal(content.sourceComplete, true); assert.equal(content.result.complete, false);
  assert.deepEqual(content.result.reasons, ['output_limit']); assert(content.result.content.length > 0 && content.result.content.length < 200);
  assert.deepEqual(content.result.content, names.slice(0, content.result.content.length)); assert(stdout.equals(original));
  assert.equal(content.stdoutByteCount, original.length); assert.equal(content.stdoutNativeTruncated, false);
  assert(canonicalJsonBytes(content).length <= 1048576);
});

test('schema-normalized script history follows the original captured observation instead of rejecting or replacing its raw outcome', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'builtin-capture-normalized-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(directory)), ref = 'a'.repeat(64), content = { tool: 'bash', exitCode: 7 };
  const original: ToolObservationV1 = { schemaVersion: 1, format: 'cliq-tool-observation-v1', runId: 'run', opId: 'op', attempt: 1,
    requestRef: ref, targetRef: ref, grantRef: ref, dispatchId: 'dispatch', observedAt: '2026-01-01T00:00:00.000Z',
    captureRef: ref, captureDigest: ref, outcome: 'executed', content, observationDigest: '' };
  original.observationDigest = digestOmitting(original, 'observationDigest');
  const retained = await artifacts.publishCanonical(original, original.format), diagnostic = { schemaVersion: 1,
    format: 'cliq-tool-output-diagnostic-v1', code: 'TOOL_PROTOCOL_ERROR', observationRef: retained.ref };
  const diagnosed = await artifacts.publishCanonical(diagnostic, diagnostic.format);
  const { content: _content, outcome: _outcome, observationDigest: _digest, ...base } = original;
  const normalized: ToolObservationV1 = { ...base, outcome: 'error', code: 'TOOL_PROTOCOL_ERROR', diagnosticRef: diagnosed.ref,
    diagnosticDigest: diagnosed.ref, observationDigest: '' };
  normalized.observationDigest = digestOmitting(normalized, 'observationDigest');
  const rejected = await artifacts.publishCanonical({ type: 'string' }, 'inert-output-schema'),
    accepted = await artifacts.publishCanonical({ type: 'object' }, 'inert-output-schema');
  const model = { outcome: 'executed' as const, content };
  await assertBuiltinCaptureObservation(artifacts, normalized, model, { ref: rejected.ref, digest: rejected.ref });
  await assert.rejects(assertBuiltinCaptureObservation(artifacts, normalized, model));
  await assert.rejects(assertBuiltinCaptureObservation(artifacts, normalized, model, { ref: accepted.ref, digest: accepted.ref }));
  await assert.rejects(assertBuiltinCaptureObservation(artifacts, { ...normalized, captureRef: 'b'.repeat(64) }, model,
    { ref: rejected.ref, digest: rejected.ref }));
  await assert.rejects(assertBuiltinCaptureObservation(artifacts, normalized, { ...model, content: { exitCode: 0 } },
    { ref: rejected.ref, digest: rejected.ref }));
  assert.deepEqual(await artifacts.readCanonical(retained.ref), JSON.parse(JSON.stringify(original)));
});

test('the fixed capture data tuple retains byte-identical original stdout/stderr refs across real grouped CAS publication', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'builtin-capture-group-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const groupRoot = path.join(directory, 'grouped'), singleRoot = path.join(directory, 'standalone');
  await mkdir(groupRoot, { mode: 0o700 }); await mkdir(singleRoot, { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(groupRoot));
  const originalCatalog = new ArtifactCatalog(new ContentAddressedStore(singleRoot));
  const stdout = Buffer.from([0xff, 0, 10, 7]), stderr = Buffer.from('original bounded stderr');
  const outputs = await Promise.all([stdout, stderr].map(bytes => artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-builtin-tool-output-v1')));
  await Promise.all([stdout, stderr].map(bytes => originalCatalog.publishBytes(bytes, 'application/octet-stream', 'cliq-builtin-tool-output-v1')));
  // Deliberately inert identity data: these objects cannot pass a native or
  // historical physical closure, and mint no StateOwner/Run/death authority.
  const inspector = { format: 'offline-inspector-data', bytes: 'original' }, inspectorRef = canonicalSha256(inspector);
  const containment = { format: 'offline-containment-data', inspectorRef }, containmentRef = canonicalSha256(containment);
  const death = { format: 'offline-death-data', containmentRef, inspectorRef }, deathRef = canonicalSha256(death);
  const receipt = { ...capture(stdout, stderr), stdoutRef: outputs[0]!.ref, stderrRef: outputs[1]!.ref,
    containmentRef, deathEvidenceRef: deathRef };
  receipt.captureDigest = digestOmitting(receipt, 'captureDigest');
  const values = [inspector, containment, death, receipt].map((value, index) => ({ value, schemaKind: `offline-capture-tuple-${index}` })) as
    [{ value: unknown; schemaKind: string }, { value: unknown; schemaKind: string }, { value: unknown; schemaKind: string }, { value: unknown; schemaKind: string }];
  const standalone = await Promise.all(values.map(value => originalCatalog.publishCanonical(value.value, value.schemaKind)));
  const grouped = await artifacts.publishCanonicalFour(values);
  assert.deepEqual(grouped, standalone);
  for (const [index, value] of values.entries()) {
    const bytes = await artifacts.readBytes(grouped[index]!.ref);
    assert(bytes.equals(canonicalJsonBytes(value.value))); assert.equal(sha256Bytes(bytes), grouped[index]!.ref);
  }
  const retained = decodeBuiltinToolCapture(await artifacts.readCanonical(grouped[3].ref));
  assert.equal(retained.stdoutRef, outputs[0]!.ref); assert.equal(retained.stderrRef, outputs[1]!.ref);
  assert((await artifacts.readBytes(retained.stdoutRef)).equals(stdout)); assert((await artifacts.readBytes(retained.stderrRef)).equals(stderr));
});
