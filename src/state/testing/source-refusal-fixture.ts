// Owned source input only. This creates no refusal, Run or native authority.
import assert from 'node:assert/strict';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, mkdir, open, realpath, rmdir, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

export const INSTALLED_SOURCE_REFUSAL_NAME = 'unsupported-source-refusal-cafe\u0301';
const identityFields = ['dev', 'ino', 'uid', 'gid', 'mode'] as const;
function same(left: BigIntStats, right: BigIntStats): void {
  assert(left.isDirectory() && right.isDirectory());
  for (const field of identityFields) assert.equal(left[field], right[field]);
}

/** A real non-NFC source name reaches the original projection's closed
 * INVALID_REQUEST branch. The native inventory must actually observe it;
 * this helper never returns or manufactures a capture error response. */
export async function withInstalledSourceRefusalFixture<T>(input: Readonly<{ workspace: string; uid: number; gid: number }>,
  action: () => Promise<T>): Promise<T> {
  assert.equal(await realpath(input.workspace), input.workspace);
  for (const value of [input.uid, input.gid]) assert(Number.isSafeInteger(value) && value >= 0);
  assert.notEqual(INSTALLED_SOURCE_REFUSAL_NAME, INSTALLED_SOURCE_REFUSAL_NAME.normalize('NFC'));
  const name = path.join(input.workspace, INSTALLED_SOURCE_REFUSAL_NAME);
  await mkdir(name, { mode: 0o700 });
  const created = await lstat(name, { bigint: true });
  let held: FileHandle | undefined, expected = created, failed = false, primary: unknown, result!: T;
  try {
    held = await open(name, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    same(created, await held.stat({ bigint: true }));
    await held.chown(input.uid, input.gid);
    expected = await held.stat({ bigint: true });
    same(expected, await lstat(name, { bigint: true }));
    assert.equal(expected.uid, BigInt(input.uid)); assert.equal(expected.gid, BigInt(input.gid));
    result = await action();
  } catch (error) { failed = true; primary = error; }
  const cleanup: unknown[] = [];
  try {
    // Empty-directory removal cannot recursively erase a substituted tree.
    // Check the original held inode before touching its exact owned name.
    if (held) same(expected, await held.stat({ bigint: true }));
    same(expected, await lstat(name, { bigint: true })); await rmdir(name);
  } catch (error) { cleanup.push(error); }
  try { await held?.close(); } catch (error) { cleanup.push(error); }
  if (cleanup.length) throw new AggregateError([...(failed ? [primary] : []), ...cleanup], 'owned source refusal fixture cleanup failed');
  if (failed) throw primary;
  return result;
}
