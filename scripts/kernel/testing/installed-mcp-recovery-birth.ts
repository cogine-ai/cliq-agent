// Qualification observer for the original signed native birth bytes.
// It reads through held directory descriptors and exposes only observed data.
import assert from 'node:assert/strict';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, type FileHandle } from 'node:fs/promises';
import Module from 'node:module';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import type { McpStdioDirectoryIdentity, McpStdioRecoveryNativeLifecycle } from '../../../src/state/mcp-stdio-lifecycle.js';

const readDirectory = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const readFile = constants.O_RDONLY | constants.O_NOFOLLOW;
const statFields = ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const;
const descriptor = (file: FileHandle, name = '') => '/proc/self/fd/' + file.fd + (name ? '/' + name : '');
const same = (left: BigIntStats, right: BigIntStats) => statFields.every(key => left[key] === right[key]);
function matches(file: BigIntStats, identity: McpStdioDirectoryIdentity) {
  return file.dev.toString() === identity.deviceId && file.ino.toString() === identity.fileId && file.uid === BigInt(identity.ownerUid);
}

async function readExact(file: FileHandle, length: number) {
  const bytes = Buffer.alloc(length);
  for (let offset = 0; offset < length;) {
    const { bytesRead } = await file.read(bytes, offset, length - offset, offset);
    if (bytesRead === 0) return undefined;
    offset += bytesRead;
  }
  return bytes;
}

export type InstalledMcpRecoveryBirthSelector = Readonly<{
  runId: string; nonce: string; probeNonceDigest: string; probeDispatchDigest: string; probeDeadlineAt: string;
  originalStateOwnerEpoch: number; originalSupervisorInstanceId: string;
  originalSupervisor: Readonly<{ pid: number; processStartToken: string }>;
  originalController: Readonly<{ pid: number; processStartToken: string }>;
}>;

export async function prepareInstalledMcpRecoveryBirthObserver(input: Readonly<{
  stateRoot: string; uid: number; decoderImage: string; decoderDigest: string; decoderBytes: number;
}>) {
  assert(Number.isSafeInteger(input.decoderBytes) && input.decoderBytes > 0 && input.decoderBytes <= 16_777_216);
  const image = await open(input.decoderImage, readFile);
  let decode: (data: Buffer) => McpStdioRecoveryNativeLifecycle;
  try {
    const before = await image.stat({ bigint: true });
    assert(before.isFile() && before.uid === 0n && before.gid === 0n && before.nlink === 1n &&
      (before.mode & 0o7777n) === 0o500n && before.size === BigInt(input.decoderBytes));
    const bytes = await readExact(image, input.decoderBytes);
    assert(bytes); assert.equal(sha256Bytes(bytes), input.decoderDigest);
    assert(same(before, await image.stat({ bigint: true })) && same(before, await lstat(input.decoderImage, { bigint: true })));
    const loaded = new Module('cliq-installed-mcp-recovery-birth-observer');
    process.dlopen(loaded, descriptor(image));
    const native = loaded.exports as { decodeMcpStdioRecoveryLifecycle?: (data: Buffer) => McpStdioRecoveryNativeLifecycle };
    if (typeof native.decodeMcpStdioRecoveryLifecycle !== 'function') assert.fail('the actual signed native birth data decoder is missing');
    decode = native.decodeMcpStdioRecoveryLifecycle;
    assert(same(before, await image.stat({ bigint: true })));
  } finally { await image.close(); }

  return async (selector: InstalledMcpRecoveryBirthSelector) => {
    assert.match(selector.nonce, /^[0-9a-f]{64}$/u);
    assert.equal(sha256Bytes(Buffer.from(selector.nonce)), selector.probeNonceDigest);
    let root: FileHandle | undefined, runtime: FileHandle | undefined, parent: FileHandle | undefined, file: FileHandle | undefined;
    try {
      root = await open(input.stateRoot, readDirectory);
      runtime = await open(descriptor(root, 'runtime'), readDirectory);
      parent = await open(descriptor(runtime, 'recovery-mcp-stdio'), readDirectory);
      file = await open(descriptor(parent, selector.nonce), readFile);
      const roots = await Promise.all([root.stat({ bigint: true }), runtime.stat({ bigint: true }), parent.stat({ bigint: true })]);
      assert(roots.every(stat => stat.isDirectory() && stat.uid === BigInt(input.uid) && (stat.mode & 0o7777n) === 0o700n && stat.dev === roots[0]!.dev));
      const before = await file.stat({ bigint: true });
      assert(before.isFile() && before.uid === BigInt(input.uid) && before.nlink === 1n && (before.mode & 0o7777n) === 0o600n &&
        before.dev === roots[0]!.dev && before.size <= 16_777_216n);
      if (before.size === 0n) return undefined;
      const bytes = await readExact(file, Number(before.size)), after = await file.stat({ bigint: true });
      const named = await lstat(descriptor(parent, selector.nonce), { bigint: true });
      if (!bytes || !same(before, after) || !same(before, named)) return undefined;
      let lifecycle: McpStdioRecoveryNativeLifecycle;
      try { lifecycle = decode(bytes); } catch { return undefined; }
      if (lifecycle.progressKind !== 9) return undefined;
      assert.equal(lifecycle.schemaVersion, 1);
      assert.equal(lifecycle.format, 'cliq-mcp-stdio-recovery-native-lifecycle-v1'); assert.equal(lifecycle.binding.kind, 'recovery');
      assert.equal(lifecycle.binding.runId, selector.runId); assert.equal(lifecycle.binding.nonce, selector.nonce);
      assert.equal(lifecycle.binding.probeDispatchDigest, selector.probeDispatchDigest);
      assert.equal(lifecycle.binding.probeDeadlineAtMs, Date.parse(selector.probeDeadlineAt));
      assert.equal(lifecycle.binding.inspectorStateOwnerEpoch, selector.originalStateOwnerEpoch);
      assert.equal(lifecycle.binding.inspectorSupervisorInstanceId, selector.originalSupervisorInstanceId);
      assert.deepEqual(lifecycle.originalSupervisor, selector.originalSupervisor);
      assert.deepEqual(lifecycle.controller, selector.originalController);
      for (const [stat, identity] of [[roots[0]!, lifecycle.stateRootIdentity], [roots[1]!, lifecycle.runtimeIdentity],
        [roots[2]!, lifecycle.privateParentIdentity], [before, lifecycle.birthIdentity]] as const) assert(matches(stat, identity));
      assert(matches(await lstat(input.stateRoot, { bigint: true }), lifecycle.stateRootIdentity));
      assert(matches(await lstat(descriptor(root, 'runtime'), { bigint: true }), lifecycle.runtimeIdentity));
      assert(matches(await lstat(descriptor(runtime, 'recovery-mcp-stdio'), { bigint: true }), lifecycle.privateParentIdentity));
      assert.equal(lifecycle.reservation.cgroupName, 'cliq-mcp-stdio-recovery-' + selector.nonce);
      assert(lifecycle.retirement && lifecycle.containment && lifecycle.joined.execReleased && lifecycle.joined.deathJoined && lifecycle.joined.ownerDrained &&
        lifecycle.joined.outputCustodyRetired && lifecycle.joined.responseRefused && lifecycle.joined.statusReleased && !lifecycle.joined.protocolCompleted);
      return { birthDigest: sha256Bytes(bytes), lifecycle };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw error;
    } finally {
      try { await file?.close(); } finally { try { await parent?.close(); } finally { try { await runtime?.close(); } finally { await root?.close(); } } }
    }
  };
}
