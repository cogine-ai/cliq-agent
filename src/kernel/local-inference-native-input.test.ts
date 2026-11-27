import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULT_SANDBOX_RESOURCES } from './control-submit.js';
import { identityHash, sha256Bytes } from './identity.js';
import { decodeLocalInferenceNativeInput, decodeLocalInferenceNativeObservation, splitLocalInferenceNativeInput } from './local-inference-native-input.js';

function wireSource() {
  // These bytes are deliberately only a decoder fixture. A successful decode
  // supplies no native receiver, resource ownership or current observation.
  const config = Buffer.alloc(136688), origin = Buffer.alloc(4144);
  config.writeUInt32LE(0x434c5331, 0); config.writeUInt32LE(1, 4); config.writeUInt32LE(6, 8); config.writeUInt32LE(3, 12);
  for (let index = 0; index < 5; index++) config.write(identityHash('local-input-test', index), 16 + index * 257, 'ascii');
  const ref = 'a'.repeat(64);
  for (let index = 0; index < 18; index++) config.write(ref, 1301 + index * 65, 'ascii');
  config.writeBigUInt64LE(4n, 2472); config.writeBigUInt64LE(123000n, 2480); config.writeBigUInt64LE(243000n, 2488);
  config.writeUInt32LE(1, 2496); config.writeUInt32LE(49152, 2500);
  const r = DEFAULT_SANDBOX_RESOURCES;
  [r.maxProcesses, r.memoryBytes, r.cpuQuotaMicrosPerSecond, r.maxOpenFiles, r.maxSingleFileBytes, r.maxGenerationBytes,
    r.maxInvocationOutputBytes, r.maxIpcFrameBytes, r.maxQueuedIpcBytes]
    .forEach((value, index) => config.writeBigUInt64LE(BigInt(value), 2504 + index * 8));
  for (let index = 0; index < 3; index++) {
    config.write(ref, 2576 + index * 65, 'ascii'); config.writeBigUInt64LE(100n, 2776 + index * 8);
  }
  const files = [[1, '/models/model-manifest.json'], [2, '/models/tokenizer'], [3, '/models/files/blobs/sha256-content'],
    [4, '/runtime/bin/ollama'], [6, '/runtime/lib/ollama/llama-server'], [7, '/lib64/ld-linux-x86-64.so.2']] as const;
  for (const [index, [kind, path]] of files.entries()) {
    const offset = 2800 + index * 4184;
    config.writeUInt32LE(kind, offset); config.writeUInt32LE(kind >= 4 ? 0o500 : 0o400, offset + 4);
    config.writeBigUInt64LE(500n, offset + 8); config.write(ref, offset + 16, 'ascii'); config.write(path, offset + 81, 'ascii');
  }
  origin.writeUInt32LE(0x434c4231, 0); origin.writeUInt32LE(1, 4); origin.writeUInt32LE(1, 8); origin.writeUInt32LE(1, 12);
  const packet = origin.subarray(16, 3512);
  packet.writeUInt32LE(0x434c5331, 0); packet.writeUInt32LE(1, 4); packet.writeUInt32LE(2, 8);
  packet.write(sha256Bytes(config), 16, 'ascii'); config.copy(packet, 88, 16, 2576);
  origin.writeBigInt64LE(1900n, 3512); origin.write('linux-proc-start-ticks:12', 3520, 'ascii');
  origin.writeBigUInt64LE(1n, 3712); origin.writeBigUInt64LE(11n, 3720); origin.writeBigUInt64LE(1000n, 3728);
  for (let index = 0; index < 7; index++) {
    const offset = 3736 + index * 40;
    origin.writeBigUInt64LE(1n, offset); origin.writeBigUInt64LE(BigInt(index + 1), offset + 8);
    origin.writeBigUInt64LE(1000n, offset + 16); origin.writeBigUInt64LE(1000n, offset + 24);
    origin.writeBigUInt64LE(BigInt(index === 3 ? 0o100600 : 0o40700), offset + 32);
  }
  origin.write('controller-' + '1'.repeat(32), 4016, 'ascii');
  Buffer.from(sha256Bytes(origin.subarray(0, 4112)), 'hex').copy(origin, 4112);
  return Buffer.concat([config, origin]);
}

test('native source requires complete original bytes, first-frame binding and layout', () => {
  const bytes = wireSource(), result = decodeLocalInferenceNativeInput(bytes);
  assert.equal(result.data.binding.port, 49152);
  assert.deepEqual(result.origin.witness, { deviceId: '1', fileId: '4', uid: 1000, gid: 1000, mode: 0o100600 });
  assert.equal(result.data.files.length, 6);
  for (const offset of [19, 2471, 2771, 2799, 2800 + 6 * 4184, 136688 + 4112]) {
    const changed = Buffer.from(bytes);
    changed[offset] = (changed[offset] ?? 0) ^ 1;
    assert.throws(() => decodeLocalInferenceNativeInput(changed));
  }
  assert.throws(() => decodeLocalInferenceNativeInput(bytes.subarray(0, -1)));
});

test('birth data cannot stand in for a current local service observation', () => {
  const { config, origin } = splitLocalInferenceNativeInput(wireSource());
  const packet = Buffer.from(origin.subarray(16, 3512));
  assert.throws(() => decodeLocalInferenceNativeObservation(config, packet, 2));
  packet.writeBigUInt64LE(123001n, 2648);
  assert.equal(decodeLocalInferenceNativeObservation(config, packet, 2).observedAtMs, 123001);
  assert.throws(() => decodeLocalInferenceNativeObservation(config, packet, 15));
});
