// Readonly fixture observation only. A matching image is not a native launch,
// release, containment-death or cancellation proof.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, readlink, stat, statfs, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { ResourceRetirementError } from '../../../src/state/errors.js';

type Comm = 'node' | 'main_thread' | 'other';
export type GuestProcessObservation = Readonly<{ kind: 'matched' | 'not_node' | 'absent' | 'deadline'; comm?: Comm }>;
const metadata = ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const;
const same = (left: BigIntStats, right: BigIntStats) => metadata.every(key => left[key] === right[key]);
const sameDirectory = (left: BigIntStats, right: BigIntStats) =>
  ['dev', 'ino', 'uid', 'gid', 'mode'].every(key => left[key as keyof BigIntStats] === right[key as keyof BigIntStats]);

/** The caller supplies the signed original claim's executable and containment
 * path. The single absolute monotonic deadline is never renewed by a read.
 * comm is retained only as a fixed hint; every positive traverses full bytes.
 * verifier-node.h requires the actual namespace-private Node copy to be
 * effective-UID-owned, 0555 and singly linked before binding that same held
 * inode. The fixed bwrap --uid 0 map maps it back to the fixture's host UID.
 * Cross-mount-namespace /proc/exe path equality is deliberately fail-closed
 * here; the owned-child test does not qualify that real guest correspondence. */
export async function observeGuestVerifierProcess(input: {
  pid: number; uid: number; cgroupPath: string; executablePath: string; executableDigest: string; deadline: number;
}): Promise<GuestProcessObservation> {
  assert.equal(process.platform, 'linux');
  assert(Number.isSafeInteger(input.pid) && input.pid > 0 && input.pid <= 2147483647);
  assert(Number.isSafeInteger(input.uid) && input.uid >= 0);
  for (const name of [input.cgroupPath, input.executablePath]) assert(path.isAbsolute(name) && path.normalize(name) === name && !name.includes('\0'));
  assert.match(input.executableDigest, /^[0-9a-f]{64}$/u); assert(Number.isFinite(input.deadline));
  const handles: FileHandle[] = []; let failure: unknown, observation: GuestProcessObservation | undefined, comm: Comm | undefined;
  const current = () => performance.now() < input.deadline;
  const held = async (name: string, flags = constants.O_RDONLY | constants.O_NOFOLLOW) => {
    const handle = await open(name, flags); handles.push(handle); return handle;
  };
  const bounded = async (name: string, maximum: number) => {
    const handle = await held(name), buffer = Buffer.alloc(maximum + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0); assert(bytesRead <= maximum);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, bytesRead));
    // Proc/cgroup text is a fresh bounded kernel snapshot, not an immutable
    // file whose size/EOF can be compared across independently changing reads.
    return text;
  };
  const token = (raw: string) => {
    assert(raw.startsWith(`${input.pid} (`)); const end = raw.lastIndexOf(')'); assert(end > 0);
    const fields = raw.slice(end + 2).trim().split(/\s+/u);
    assert(fields.length >= 20 && !['Z', 'X', 'x'].includes(fields[0]!)); assert.match(fields[19]!, /^(0|[1-9][0-9]*)$/u);
    return fields[19]!;
  };
  try {
    if (!current()) observation = { kind: 'deadline' };
    else {
      const group = await held(input.cgroupPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW), groupBefore = await group.stat({ bigint: true });
      assert(groupBefore.isDirectory()); assert.equal((await statfs(`/proc/self/fd/${group.fd}`, { bigint: true })).type, 0x63677270n);
      const members = async () => {
        const raw = await bounded(`/proc/self/fd/${group.fd}/cgroup.procs`, 65536), ids = raw.trim() ? raw.trim().split('\n') : [];
        assert(ids.length <= 4096 && ids.every(id => /^[1-9][0-9]{0,9}$/u.test(id))); return ids.includes(String(input.pid));
      };
      if (!await members()) observation = { kind: 'not_node' };
      else {
        const procPath = `/proc/${input.pid}`, proc = await held(procPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        const procBefore = await proc.stat({ bigint: true }); assert.equal(procBefore.uid, BigInt(input.uid));
        const procRoot = `/proc/self/fd/${proc.fd}`, start = token(await bounded(`${procRoot}/stat`, 4096));
        const label = (await bounded(`${procRoot}/comm`, 64)).trim(); comm = label === 'node' ? 'node' : label === 'MainThread' ? 'main_thread' : 'other';
        const exe = `${procRoot}/exe`;
        if (await readlink(exe) !== input.executablePath) observation = { kind: 'not_node', comm };
        else {
          // /proc/PID/exe is the one intentionally followed kernel magiclink.
          // The held proc directory, start token and both named inode checks
          // prevent a pathname alias or reused PID from supplying the bytes.
          const image = await held(exe, constants.O_RDONLY), before = await image.stat({ bigint: true });
          assert(before.isFile() && before.uid === BigInt(input.uid) && before.nlink === 1n && (before.mode & 0o7777n) === 0o555n);
          assert(before.size > 0n && before.size <= 256n * 1024n * 1024n);
          assert(same(before, await stat(exe, { bigint: true })));
          const hash = createHash('sha256'), buffer = Buffer.allocUnsafe(1024 * 1024); let offset = 0;
          while (current() && offset < Number(before.size)) {
            const { bytesRead } = await image.read(buffer, 0, Math.min(buffer.length, Number(before.size) - offset), offset);
            assert(bytesRead > 0); hash.update(buffer.subarray(0, bytesRead)); offset += bytesRead;
          }
          if (!current()) observation = { kind: 'deadline', comm };
          else {
            assert.equal((await image.read(buffer, 0, 1, offset)).bytesRead, 0);
            const digest = hash.digest('hex'); assert(same(before, await image.stat({ bigint: true })) && same(before, await stat(exe, { bigint: true })));
            assert.equal(await readlink(exe), input.executablePath);
            assert.equal(token(await bounded(`${procRoot}/stat`, 4096)), start);
            assert(sameDirectory(procBefore, await proc.stat({ bigint: true })) && sameDirectory(procBefore, await lstat(procPath, { bigint: true })));
            const inGroup = await members();
            assert(sameDirectory(groupBefore, await group.stat({ bigint: true })) && sameDirectory(groupBefore, await lstat(input.cgroupPath, { bigint: true })));
            observation = { kind: !current() ? 'deadline' : inGroup && digest === input.executableDigest ? 'matched' : 'not_node', comm };
          }
        }
      }
    }
  } catch (error) {
    if (['ENOENT', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) observation = { kind: 'absent', ...(comm ? { comm } : {}) };
    else failure = error;
  }
  const closeErrors: unknown[] = [];
  for (const handle of handles.reverse()) try { await handle.close(); } catch (error) { closeErrors.push(error); }
  if (closeErrors.length) throw new ResourceRetirementError('guest process observation descriptors did not join',
    new AggregateError([failure, ...closeErrors].filter(Boolean)));
  if (failure) throw failure;
  if (observation?.kind === 'matched' && !current()) observation = { kind: 'deadline', ...(comm ? { comm } : {}) };
  assert(observation); return Object.freeze(observation);
}
