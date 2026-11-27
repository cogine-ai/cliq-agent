import { closeSync, fstatSync, type BigIntStats } from 'node:fs';
import { Socket } from 'node:net';
import type { Writable } from 'node:stream';
import { duplicateClientStdio, type NativeStateOwner } from '../state/native-owner.js';
import { ResourceRetirementError } from '../state/errors.js';
import { withHeldInstalledRuntime, type HeldInstalledRuntime } from '../state/installed-runtime.js';
import type { ClientIO } from './entry.js';

function same(a: BigIntStats, b: BigIntStats): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.uid === b.uid && a.gid === b.gid && a.mode === b.mode;
}

/** Node deliberately keeps process.stdout/stderr alive on destroy. The CLI
 * therefore owns a separate nonblocking descriptor for an inherited pipe;
 * ordinary SDK streams and synchronous terminal/file stdio remain borrowed. */
export async function openClientStdio(native: NativeStateOwner, io: ClientIO): Promise<Readonly<{ io: ClientIO; close(): Promise<void> }>> {
  const owned: Socket[] = [];
  const close = async () => {
    const results = await Promise.allSettled(owned.map(async stream => {
      if (stream.closed) return;
      await new Promise<void>((resolve, reject) => {
        let failure: Error | undefined;
        const error = (cause: Error) => { failure ??= cause; };
        stream.on('error', error);
        stream.once('close', () => { stream.removeListener('error', error); if (failure) reject(failure); else resolve(); });
        stream.destroy();
      });
    }));
    const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected').map(result => result.reason);
    if (failures.length) throw new ResourceRetirementError('client stdio descriptors did not retire', new AggregateError(failures));
  };
  const output = (stream: Writable, role: 'stdout' | 'stderr') => {
    const original = role === 'stdout' ? process.stdout : process.stderr, fd = role === 'stdout' ? 1 : 2;
    if (stream !== original) return stream;
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFIFO() && !before.isSocket()) return stream;
    if (original.writableLength !== 0 || original.writableNeedDrain || original.destroyed)
      throw new TypeError('original client stdio still has an outstanding writer');
    const duplicate = duplicateClientStdio(native, role);
    let socket: Socket | undefined;
    try {
      if (!same(before, fstatSync(duplicate, { bigint: true })) || !same(before, fstatSync(fd, { bigint: true })))
        throw new TypeError('client stdio descriptor identity changed');
      socket = new Socket({ fd: duplicate, readable: false, writable: true });
      owned.push(socket);
      if (!same(before, fstatSync(duplicate, { bigint: true })) || !same(before, fstatSync(fd, { bigint: true })))
        throw new TypeError('client stdio changed during ownership transfer');
      return socket;
    } catch (error) {
      if (!socket) {
        try { closeSync(duplicate); }
        catch (retirement) { throw new ResourceRetirementError('client stdio acquisition did not retire', new AggregateError([error, retirement])); }
      }
      throw error;
    }
  };
  try { return Object.freeze({ io: { ...io, output: output(io.output, 'stdout'), diagnostic: output(io.diagnostic, 'stderr') }, close }); }
  catch (error) {
    try { await close(); }
    catch (retirement) { throw new ResourceRetirementError('client stdio acquisition did not join', new AggregateError([error, retirement])); }
    throw error;
  }
}

/** Only the actual held installed selection chooses the native image. */
export async function openInstalledClientStdio(selected: HeldInstalledRuntime, io: ClientIO) {
  return withHeldInstalledRuntime(selected, async installed => openClientStdio(await installed.loadStateOwner(io.signal), io), io.signal);
}
