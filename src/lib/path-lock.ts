import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

const LOCK_OWNER_FILE = 'owner';

export const LOCK_TIMEOUT_MS = 5000;
export const LOCK_RETRY_MS = 25;
export const LOCK_HEARTBEAT_MS = Math.max(LOCK_RETRY_MS, Math.floor(LOCK_TIMEOUT_MS / 3));

export type PathLock = {
  assertCurrentOwner: () => Promise<void>;
};

function sleep(ms: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export async function withPathLock<T>(target: string, callback: (lock: PathLock) => Promise<T>): Promise<T> {
  const lockPath = `${target}.lock`;
  const ownerToken = `${process.pid}:${crypto.randomUUID()}`;
  const startedAt = Date.now();
  await fs.mkdir(path.dirname(lockPath), { recursive: true });

  while (true) {
    try {
      await fs.mkdir(lockPath);
      try {
        await writeLockOwner(lockPath, ownerToken);
      } catch (error) {
        await fs.rm(lockPath, { recursive: true, force: true });
        throw error;
      }
      break;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'EEXIST') {
        throw error;
      }
      if (await removeStaleLock(lockPath)) {
        continue;
      }
      if (Date.now() - startedAt > LOCK_TIMEOUT_MS) {
        throw new Error(`timed out waiting for path lock: ${lockPath}`);
      }
      await sleep(LOCK_RETRY_MS);
    }
  }

  const heartbeat = startLockHeartbeat(lockPath, ownerToken);
  const lock: PathLock = {
    assertCurrentOwner: async () => {
      await assertPathLockOwner(lockPath, ownerToken);
    }
  };
  try {
    return await callback(lock);
  } finally {
    clearInterval(heartbeat);
    await releasePathLock(lockPath, ownerToken);
  }
}

async function writeLockOwner(lockPath: string, ownerToken: string) {
  await fs.writeFile(path.join(lockPath, LOCK_OWNER_FILE), ownerToken, { flag: 'wx' });
}

function startLockHeartbeat(lockPath: string, ownerToken: string) {
  const heartbeat = setInterval(() => {
    void refreshLockLease(lockPath, ownerToken).catch(() => {
      // The next lock waiter will decide whether the lease is stale. Heartbeat
      // failures should not mask the protected operation.
    });
  }, LOCK_HEARTBEAT_MS);
  heartbeat.unref?.();
  return heartbeat;
}

async function refreshLockLease(lockPath: string, ownerToken: string) {
  const ownerPath = path.join(lockPath, LOCK_OWNER_FILE);
  let handle: Awaited<ReturnType<typeof fs.open>> | undefined;
  try {
    handle = await fs.open(ownerPath, 'r+');
    const currentOwner = await handle.readFile({ encoding: 'utf8' });
    if (currentOwner !== ownerToken) {
      return false;
    }
    const now = new Date();
    await handle.utimes(now, now);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return false;
    }
    throw error;
  } finally {
    await handle?.close();
  }
}

async function releasePathLock(lockPath: string, ownerToken: string) {
  const currentOwner = await readLockOwner(lockPath);
  if (currentOwner !== ownerToken) {
    return;
  }
  await fs.rm(lockPath, { recursive: true, force: true });
}

async function assertPathLockOwner(lockPath: string, ownerToken: string) {
  const currentOwner = await readLockOwner(lockPath);
  if (currentOwner !== ownerToken) {
    throw new Error(`lost path lock: ${lockPath}`);
  }
  if (!(await refreshLockLease(lockPath, ownerToken))) {
    throw new Error(`lost path lock: ${lockPath}`);
  }
}

async function readLockOwner(lockPath: string) {
  try {
    return await fs.readFile(path.join(lockPath, LOCK_OWNER_FILE), 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function removeStaleLock(lockPath: string) {
  try {
    const ownerPath = path.join(lockPath, LOCK_OWNER_FILE);
    const owner = await readLockOwner(lockPath);
    const leaseStat = owner === null ? await fs.stat(lockPath) : await fs.stat(ownerPath);
    if (Date.now() - leaseStat.mtimeMs <= LOCK_TIMEOUT_MS) {
      return false;
    }
    await fs.rm(lockPath, { recursive: true, force: true });
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return true;
    }
    throw error;
  }
}
