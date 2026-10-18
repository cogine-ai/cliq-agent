// Exercise the exact root harness's data guards without mounting, changing UID,
// executing native code, or claiming physical filesystem/cleanup qualification.
import assert from 'node:assert/strict';
import { constants, readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const shell = readFileSync(new URL('../qualify-systemd-user.sh', import.meta.url), 'utf8');
const marker = '"$probe_uid" "$probe_gid" "$probe_output/run-filesystem.json" <<\'NODE\'\n';
const start = shell.indexOf(marker); assert(start >= 0);
const source = shell.slice(start + marker.length, shell.indexOf('\nNODE\n}', start))
  .replace(/^import[\s\S]*?from 'node:assert\/strict';\n/u, '')
  .replace(/^import[\s\S]*?from 'node:fs';\n/u, '');
assert(source.includes("action === 'retire-cut'"));

// Node 26's generated assertion message can be undefined for an unmapped VM
// frame when a loader enables source maps. Keep the real assertion and exact
// guard expression, supplying only a fixed diagnosis in this data fixture.
const vmAssert = Object.assign((value, message = 'fixed bounded volume guard refused') => assert(value, message), assert);

const fixture = '/var/tmp/cliq-systemd-probe.Abc123', home = `${fixture}/home`, image = `${fixture}/run-home.ext4`;
const originalFile = `${fixture}/run-home-original.json`, mountedFile = `${fixture}/run-home-mounted.json`;
const output = '/var/tmp/cliq-systemd-output/run-filesystem.json', uid = 20001, size = 1024 ** 3;
const homeIdentity = { device: '1', inode: '2', uid, gid: uid, mode: 0o700 };
const imageIdentity = { device: '1', inode: '3', uid: 0, gid: 0, mode: 0o600, size: String(size), links: 1 };

function setup(overrides = {}) {
  const files = new Map([[originalFile, { uid: 0, gid: 0, mode: 0o444, links: 1,
    text: JSON.stringify({ home: homeIdentity, image: imageIdentity,
      beforeFilesystem: { filesystemType: 0xef53, totalBytes: 100 * size } }) }]]);
  const state = { mounted: true, id: '100', source: '/dev/loop17', device: '7:17', root: '/',
    type: 'ext4', options: 'rw,nosuid,nodev,relatime', homeUid: uid, homeGid: uid, homeMode: 0o700,
    mountedDevice: '1809', mountedInode: '2', backingFile: image, autoclear: '1', offset: '0', sizeLimit: '0',
    loopInode: 40n, loopRdev: 1809n, loopBlockDevice: true, loopSymlink: false,
    filesystemType: 0xef53n, blocks: BigInt(size / 4096), bsize: 4096n,
    image: { ...imageIdentity }, nestedMount: false, ...overrides };
  const descriptors = new Map(); let nextFd = 10;
  const metadata = (kind, fields) => ({ dev: BigInt(fields.device ?? 1), ino: BigInt(fields.inode ?? 1),
    uid: BigInt(fields.uid ?? 0), gid: BigInt(fields.gid ?? 0), mode: BigInt(fields.mode ?? 0o600),
    size: BigInt(fields.size ?? 0), nlink: BigInt(fields.links ?? 1),
    rdev: fields.rdev ?? 0n, isSymbolicLink: () => Boolean(fields.symlink),
    isDirectory: () => kind === 'directory', isFile: () => kind === 'file', isBlockDevice: () => kind === 'block' });
  const missing = () => Object.assign(new Error('absent fixture DATA'), { code: 'ENOENT' });
  const api = {
    constants,
    lstatSync(file) {
      if (file === fixture) return metadata('directory', { device: 1, inode: 1, uid: 0, mode: 0o755 });
      if (file === home) return metadata('directory', state.mounted
        ? { device: state.mountedDevice, inode: state.mountedInode, uid: state.homeUid, gid: state.homeGid, mode: state.homeMode }
        : homeIdentity);
      if (file === image) return metadata('file', state.image);
      if (file.startsWith('/dev/loop')) return metadata(state.loopBlockDevice ? 'block' : 'file',
        { inode: state.loopInode, rdev: state.loopRdev, symlink: state.loopSymlink, uid: 0, mode: 0o660 });
      const data = files.get(file); if (!data) throw missing();
      return metadata('file', { ...data, size: Buffer.byteLength(data.text) });
    },
    existsSync(file) {
      if (file.startsWith('/sys/dev/block/')) return state.backingFile !== undefined;
      return files.has(file);
    },
    readFileSync(file) {
      if (file === '/proc/self/mountinfo') return Buffer.from([
        '1 0 1:1 / / rw - ext4 /dev/root rw',
        ...(state.mounted ? [`${state.id} 1 ${state.device} ${state.root} ${home} ${state.options} - ${state.type} ${state.source} rw`] : []),
        ...(state.nestedMount ? [`101 100 7:17 / ${home}/nested rw - ext4 /dev/loop17 rw`] : []),
      ].join('\n'));
      if (file.startsWith('/sys/')) {
        const values = { backing_file: state.backingFile, autoclear: state.autoclear,
          offset: state.offset, sizelimit: state.sizeLimit };
        const value = values[file.split('/').at(-1)]; if (value === undefined) throw missing(); return `${value}\n`;
      }
      const data = files.get(file); if (!data) throw missing(); return data.text;
    },
    readdirSync: () => ['loop17'],
    statfsSync: () => ({ type: state.filesystemType, blocks: state.blocks, bsize: state.bsize }),
    openSync(file) { assert(!files.has(file)); const fd = nextFd++; files.set(file, { uid: 0, gid: 0, mode: 0o600, links: 1, text: '' }); descriptors.set(fd, file); return fd; },
    writeFileSync(fd, text) { files.get(descriptors.get(fd)).text = text; },
    fchmodSync(fd, mode) { files.get(descriptors.get(fd)).mode = mode; },
    fsyncSync() {}, closeSync() {}, ftruncateSync() { assert.fail('these data tests do not provision an image'); },
  };
  function run(action, code = source) {
    let stdout = '';
    vm.runInNewContext(code, { ...api, assert: vmAssert, Buffer,
      process: { geteuid: () => 0, argv: ['node', '-', action, fixture, '1:1:0', home, image, originalFile, mountedFile,
        String(uid), String(uid), output], stdout: { write(text) { stdout += text; } } } }, { timeout: 1000 });
    return stdout;
  }
  return { state, files, run };
}

test('current exact bounded ext4 fixture captures, revalidates and retires only after association disappears', () => {
  const context = setup(); context.run('capture');
  assert.equal(context.run('retire-cut'), 'mounted\n');
  const report = JSON.parse(context.files.get(output).text);
  assert.equal(report.dedicatedBoundedExt4, true); assert.equal(report.nativeGenerationQuotaVerified, false);
  assert(!JSON.stringify(report).includes(fixture));
  context.state.mounted = false;
  assert.throws(() => context.run('unmounted'), /AssertionError/u);
  context.state.backingFile = undefined; context.run('unmounted');
});

test('mount, loop, image, quota or nested-mount substitutions refuse before privileged unmount', () => {
  for (const changed of [
    { id: 'not-an-id' }, { source: '/dev/sda' }, { device: '8:17' }, { root: '/subtree' }, { type: 'tmpfs' },
    { options: 'rw,nodev,nosuid,noexec' }, { options: 'rw,nosuid' }, { loopRdev: 1810n }, { mountedDevice: '1810' },
    { loopBlockDevice: false }, { loopSymlink: true }, { backingFile: '/unrelated/image' }, { autoclear: '0' },
    { offset: '4096' }, { sizeLimit: String(size) }, { homeUid: uid + 1 }, { homeMode: 0o777 },
    { filesystemType: 0x01021994n }, { blocks: BigInt(size / 4096 + 1) }, { nestedMount: true },
    { image: { ...imageIdentity, inode: '999' } }, { image: { ...imageIdentity, links: 2 } },
  ]) assert.throws(() => setup(changed).run('capture'), /AssertionError/u, JSON.stringify(changed, (_, value) => typeof value === 'bigint' ? String(value) : value));
  for (const changed of [{ id: '101' }, { loopInode: 41n }, { mountedInode: '999' }]) {
    const context = setup(); context.run('capture'); Object.assign(context.state, changed);
    assert.throws(() => context.run('retire-cut'), /AssertionError/u);
  }
});

test('partial mount capture still requires the original frozen image and bounded kernel shape', () => {
  const context = setup({ homeUid: 0, homeGid: 0, homeMode: 0o755 });
  assert.throws(() => context.run('capture'), /AssertionError/u);
  assert.equal(context.run('retire-cut'), 'mounted\n');
  const noMount = setup({ mounted: false, backingFile: undefined });
  assert.equal(noMount.run('retire-cut'), 'unmounted\n'); noMount.run('unmounted');
  assert.throws(() => setup({ mounted: false }).run('retire-cut'), /AssertionError/u);
  const badRecord = setup(); badRecord.files.get(originalFile).mode = 0o644;
  assert.throws(() => badRecord.run('retire-cut'), /AssertionError/u);
});

test('a targeted quota-guard mutation is caught by the original oversized-capacity fixture', () => {
  const changed = setup({ blocks: BigInt(size / 4096 + 1) });
  assert.throws(() => changed.run('capture'), /AssertionError/u);
  const mutation = source.replace('assert(observed.totalBytes <= ceiling);', '/* deliberate test-only mutation */');
  assert.notEqual(mutation, source); changed.run('capture', mutation);
});

test('VM boolean refusal retains the real AssertionError and a fixed non-sensitive diagnosis', () => {
  assert.throws(() => setup({ options: 'rw,nodev,nosuid,noexec' }).run('capture'), error => {
    assert(error instanceof assert.AssertionError, 'the original guard must throw the real AssertionError');
    assert.equal(error.code, 'ERR_ASSERTION'); assert.equal(error.actual, false); assert.equal(error.expected, true);
    assert.equal(error.message, 'fixed bounded volume guard refused');
    return true;
  });
});
