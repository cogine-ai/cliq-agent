// Independent real procfs/locator observation; never produces an anchor or evidence.
import assert from 'node:assert/strict';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, readdir, readlink, stat, statfs, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const imageFields = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
const rootFields = ['dev', 'ino', 'uid', 'gid', 'mode'] as const;
// Linux fdinfo includes FD_CLOEXEC as O_CLOEXEC in the reported flags.
const oPath = 0o10000000n, sourceFlags = 0o12600000n;
const cgroup2 = 0x63677270;

function identity(metadata: BigIntStats, fields: readonly (typeof imageFields)[number][]) {
  return Object.fromEntries(fields.map(field => [field, metadata[field].toString()]));
}

async function bytesFrom(file: FileHandle, limit: number): Promise<Buffer> {
  const buffer = Buffer.alloc(limit + 1);
  let used = 0;
  while (used < buffer.length) {
    const { bytesRead } = await file.read(buffer, used, buffer.length - used, null);
    if (bytesRead === 0) break;
    used += bytesRead;
  }
  assert(used <= limit, 'actual observation exceeded its byte bound');
  return buffer.subarray(0, used);
}

async function procBytes(filename: string, limit = 64 * 1024): Promise<Buffer> {
  const file = await open(filename, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try { assert((await file.stat()).isFile()); return await bytesFrom(file, limit); }
  finally { await file.close(); }
}

async function procText(filename: string, limit?: number): Promise<string> {
  return new TextDecoder('utf-8', { fatal: true }).decode(await procBytes(filename, limit));
}

function fdField(text: string, field: string, digits: string): string {
  const lines = text.split('\n').filter(line => line.startsWith(`${field}:`));
  assert.equal(lines.length, 1, `actual fdinfo must have one ${field}`);
  const value = new RegExp(`^${field}:[ \\t]+(${digits})$`, 'u').exec(lines[0]!);
  assert(value, `actual fdinfo needs a canonical ${field}`);
  return value[1]!;
}

async function fdInfo(pid: number | 'self', descriptor: string) {
  const text = await procText(`/proc/${pid}/fdinfo/${descriptor}`, 16 * 1024);
  const flags = BigInt(`0o${fdField(text, 'flags', '0[0-7]{1,11}')}`);
  const mountId = fdField(text, 'mnt_id', '[1-9][0-9]{0,19}');
  const inode = fdField(text, 'ino', '(?:0|[1-9][0-9]{0,19})');
  assert(flags <= 0xffffffffn && BigInt(mountId) <= 0xffffffffffffffffn && BigInt(inode) <= 0xffffffffffffffffn);
  return { flags: flags.toString(), mountId, inode };
}

export async function descriptorInventory(pid: number) {
  const read = async () => {
    const names = (await readdir(`/proc/${pid}/fd`)).sort();
    assert(names.length > 0 && names.length <= 4096, 'keeper descriptor inventory must be complete and bounded');
    assert(names.every(name => /^(?:0|[1-9][0-9]*)$/u.test(name)));
    const descriptors = [];
    for (const descriptor of names) {
      const info = await fdInfo(pid, descriptor);
      const target = `/proc/${pid}/fd/${descriptor}`;
      const metadata = await stat(target, { bigint: true });
      const isCgroupPin = (BigInt(info.flags) & oPath) !== 0n && metadata.isDirectory() &&
        Number((await statfs(target)).type) === cgroup2;
      descriptors.push({ descriptor, ...info, target: identity(metadata, rootFields),
        link: await readlink(target), isCgroupPin });
    }
    return { names, descriptors, afterNames: (await readdir(`/proc/${pid}/fd`)).sort() };
  };
  const deadline = Date.now() + 30_000;
  for (;;) {
    try {
      const first = await read(), second = await read();
      if (JSON.stringify(first) === JSON.stringify(second) && JSON.stringify(first.names) === JSON.stringify(first.afterNames) &&
        first.descriptors.every(value => value.inode === value.target.ino))
        return { descriptors: first.descriptors, sources: first.descriptors.filter(value => value.isCgroupPin) };
    } catch (error) {
      // Churn retries a whole independent observation, never a reused resource.
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    assert(Date.now() < deadline, 'keeper descriptor identity inventory never stabilized');
    await delay(10);
  }
}

export async function qualifyInstalledAnchorSource(input: {
  pid: number; startTicks: string; uid: number; gid: number; stateRoot: string; bundleDigest: string;
  selectedImage: string; selectedMetadata: BigIntStats; root: { path: string; device: string; inode: string };
  report: Record<string, unknown>;
}): Promise<void> {
  assert.equal(process.platform, 'linux');
  input.report.qualified = false;
  const proc = `/proc/${input.pid}`, readyPath = path.join(input.stateRoot, 'runtime/keeper.ready');
  input.report.readyPath = readyPath;
  const root = await open(input.root.path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const heldRoot = identity(await root.stat({ bigint: true }), rootFields);
    assert.equal(heldRoot.dev, input.root.device); assert.equal(heldRoot.ino, input.root.inode);
    assert.equal(heldRoot.uid, String(input.uid)); assert.equal(heldRoot.gid, String(input.gid));
    assert.equal(BigInt(heldRoot.mode!) & 0o7777n, 0o700n);
    assert.equal(Number((await statfs(`/proc/self/fd/${root.fd}`)).type), cgroup2);
    const rootFdInfo = await fdInfo('self', String(root.fd));
    assert.equal(rootFdInfo.inode, heldRoot.ino);
    input.report.heldNamedRoot = { identity: heldRoot, mountId: rootFdInfo.mountId };
    const cut = async () => {
      const rawStat = await procText(`${proc}/stat`);
      assert(rawStat.startsWith(`${input.pid} (`));
      const fields = rawStat.slice(rawStat.lastIndexOf(')') + 2).trim().split(/\s+/u);
      assert(fields.length >= 20 && fields[0] !== 'Z' && fields[0] !== 'X' && fields[0] !== 'x');
      assert.match(fields[19]!, /^(?:0|[1-9][0-9]*)$/u); assert.equal(fields[19], input.startTicks);
      const credentials: Record<string, string[]> = {};
      const status = await procText(`${proc}/status`);
      for (const [field, expected] of [['Uid', input.uid], ['Gid', input.gid]] as const) {
        const matches = [...status.matchAll(new RegExp(`^${field}:[ \\t]+([0-9]+)[ \\t]+([0-9]+)[ \\t]+([0-9]+)[ \\t]+([0-9]+)$`, 'gmu'))];
        assert.equal(matches.length, 1); credentials[field] = matches[0]!.slice(1);
        assert(credentials[field]!.every(value => value === String(expected)));
      }
      const state = await lstat(input.stateRoot, { bigint: true });
      assert(state.isDirectory() && !state.isSymbolicLink()); assert.equal(state.uid, BigInt(input.uid));
      assert.equal(state.mode & 0o7777n, 0o700n); // StateRoot GID is bound, not assumed to equal EGID.
      const argv = [input.selectedImage, '--installed-keeper', input.stateRoot, input.bundleDigest,
        `${state.dev}:${state.ino}:${state.uid}`];
      assert.deepEqual(await procBytes(`${proc}/cmdline`), Buffer.from(argv.join('\0') + '\0'));
      const selected = await lstat(input.selectedImage, { bigint: true });
      assert(selected.isFile() && !selected.isSymbolicLink());
      const image = await stat(`${proc}/exe`, { bigint: true });
      assert(image.isFile()); assert.equal(await readlink(`${proc}/exe`), input.selectedImage);
      assert.deepEqual(identity(image, imageFields), identity(input.selectedMetadata, imageFields));
      assert.deepEqual(identity(selected, imageFields), identity(input.selectedMetadata, imageFields));
      assert.deepEqual(identity(await lstat(input.root.path, { bigint: true }), rootFields), heldRoot);
      assert.deepEqual(identity(await root.stat({ bigint: true }), rootFields), heldRoot);
      const membership = `0::${input.root.path.slice('/sys/fs/cgroup'.length)}/keeper`;
      assert.equal((await procText(`${proc}/cgroup`)).trim(), membership);
      const namespaces: Record<string, unknown> = {};
      for (const name of ['pid', 'mnt', 'cgroup', 'user', 'time']) {
        const actual = await stat(`${proc}/ns/${name}`, { bigint: true });
        const observer = await stat(`/proc/self/ns/${name}`, { bigint: true });
        assert.equal(actual.dev, observer.dev); assert.equal(actual.ino, observer.ino);
        namespaces[name] = { device: actual.dev.toString(), inode: actual.ino.toString() };
      }
      const bootId = (await procText('/proc/sys/kernel/random/boot_id', 128)).trim();
      assert.match(bootId, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u);
      return { pid: input.pid, startTicks: fields[19], credentials, argv, image: identity(image, imageFields),
        stateRoot: identity(state, rootFields), root: heldRoot, namespaces, bootId };
    };
    const before = await cut(); input.report.before = before;
    const inventory = await descriptorInventory(input.pid); input.report.inventory = inventory;
    assert.equal(inventory.sources.length, 1, 'actual keeper must own exactly one cgroup O_PATH directory');
    const source = inventory.sources[0]!;
    input.report.source = source;
    assert.equal(BigInt(source.flags), sourceFlags, 'original source pin needs exact O_PATH/directory/nofollow/cloexec flags');
    assert.deepEqual(source.target, heldRoot); assert.equal(source.inode, heldRoot.ino);
    assert.equal(source.mountId, rootFdInfo.mountId);
    let ready: Buffer | undefined, readyIdentity: ReturnType<typeof identity> | undefined, readyError: unknown;
    try {
      // Type=exec is not publication readiness. Only initial absence may wait;
      // a changed/missing inode after opening is an observation failure.
      const deadline = Date.now() + 30_000;
      const named = await (async () => {
        for (;;) {
          try { return await lstat(readyPath, { bigint: true }); }
          catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
            input.report.ready = { present: false, code: 'ENOENT' };
            if (Date.now() >= deadline) throw error;
            await delay(200);
          }
        }
      })();
      readyIdentity = identity(named, imageFields);
      input.report.ready = { present: true, metadata: readyIdentity };
      assert(named.isFile() && !named.isSymbolicLink()); assert.equal(named.uid, BigInt(input.uid));
      assert.equal(named.gid, BigInt(input.gid)); assert.equal(named.mode & 0o7777n, 0o600n);
      assert.equal(named.nlink, 1n); assert.equal(named.size, 40n);
      const file = await open(readyPath, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
      try {
        assert.deepEqual(identity(await file.stat({ bigint: true }), imageFields), identity(named, imageFields));
        ready = await bytesFrom(file, 40); input.report.readyBytes = ready.toString('hex');
        assert.deepEqual(identity(await file.stat({ bigint: true }), imageFields), identity(named, imageFields));
        assert.deepEqual(identity(await lstat(readyPath, { bigint: true }), imageFields), identity(named, imageFields));
      } finally { await file.close(); }
    } catch (error) {
      readyError = error;
      if ((error as NodeJS.ErrnoException).code === 'ENOENT' && input.report.ready === undefined)
        input.report.ready = { present: false, code: 'ENOENT' };
      input.report.readyError = String((error as Error).stack ?? error).slice(0, 8192);
    }
    // Preserve actual source evidence even for the expected missing-publication RED.
    const afterInventory = await descriptorInventory(input.pid); input.report.afterInventory = afterInventory;
    const after = await cut(); input.report.after = after;
    assert.deepEqual(after, before); assert.deepEqual(afterInventory.sources, inventory.sources);
    assert.deepEqual((await readdir(input.root.path, { withFileTypes: true }))
      .filter(entry => entry.isDirectory()).map(entry => entry.name), ['keeper']);
    if (readyError) throw readyError;
    assert(ready && readyIdentity); assert.equal(ready.length, 40);
    const published = await open(readyPath, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
    try {
      assert.deepEqual(identity(await published.stat({ bigint: true }), imageFields), readyIdentity);
      assert.deepEqual(await bytesFrom(published, 40), ready);
      assert.deepEqual(identity(await published.stat({ bigint: true }), imageFields), readyIdentity);
      assert.deepEqual(identity(await lstat(readyPath, { bigint: true }), imageFields), readyIdentity);
    } finally { await published.close(); }
    assert.deepEqual(ready.subarray(0, 8), Buffer.from('cliq-ak1', 'ascii'));
    const locator = { pid: ready.readUInt32LE(8), descriptor: ready.readUInt32LE(12),
      startTicks: ready.readBigUInt64LE(16).toString(), bootHex: ready.subarray(24).toString('hex') };
    input.report.locator = locator;
    assert(locator.pid > 0 && locator.pid <= 0x7fffffff && locator.descriptor >= 3 && locator.descriptor <= 0x7fffffff);
    assert.equal(locator.pid, input.pid); assert.equal(String(locator.descriptor), source.descriptor);
    assert.equal(locator.startTicks, input.startTicks);
    assert.equal(locator.bootHex, before.bootId.replaceAll('-', ''));
  } finally { await root.close(); }
  input.report.qualified = true;
}
