// Exercise the exact root harness's data guards without mounting, changing UID,
// executing native code, or claiming physical filesystem/cleanup qualification.
import assert from 'node:assert/strict';
import { constants, readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const shell = readFileSync(new URL('../qualify-systemd-user.sh', import.meta.url), 'utf8');
const marker = '"$probe_uid" "$probe_gid" "$probe_output/run-filesystem.json" "$probe_volume_mode" <<\'NODE\'\n';
const start = shell.indexOf(marker); assert(start >= 0);
const source = shell.slice(start + marker.length, shell.indexOf('\nNODE\n}', start))
  .replace(/^import[\s\S]*?from 'node:assert\/strict';\n/u, '')
  .replace(/^import[\s\S]*?from 'node:crypto';\n/u, '')
  .replace(/^import[\s\S]*?from 'node:child_process';\n/u, '')
  .replace(/^import[\s\S]*?from 'node:fs';\n/u, '');
assert(source.includes("action === 'retire-cut'"));

// Node 26's generated assertion message can be undefined for an unmapped VM
// frame when a loader enables source maps. Keep the real assertion and exact
// guard expression, supplying only a fixed diagnosis in this data fixture.
const vmAssert = Object.assign((value, message = 'fixed bounded volume guard refused') => assert(value, message), assert);

const fixture = '/var/tmp/cliq-systemd-probe.Abc123', home = `${fixture}/home`, image = `${fixture}/run-home.ext4`;
const originalFile = `${fixture}/run-home-original.json`, mountedFile = `${fixture}/run-home-mounted.json`;
const chainFile = `${fixture}/run-home-device.json`, filesystemUuid = '12345678-1234-4123-8123-123456789abc';
const handoffFile = `${fixture}/run-home-handoff.json`;
const delayName = 'cliq-probe-Abc123-delay', delayUuid = `CLIQ-QUALIFY-${filesystemUuid}`;
const output = '/var/tmp/cliq-systemd-output/run-filesystem.json', uid = 20001, size = 1024 ** 3;
const homeIdentity = { device: '1', inode: '2', uid, gid: uid, mode: 0o700 };
const imageIdentity = { device: '1', inode: '3', uid: 0, gid: 0, mode: 0o600, size: String(size), links: 1 };

function setup(overrides = {}) {
  const files = new Map([[originalFile, { uid: 0, gid: 0, mode: 0o444, links: 1,
    text: JSON.stringify({ home: homeIdentity, image: imageIdentity, filesystemUuid,
      ...(overrides.volumeMode === 'delay-50ms' ? { delay: { name: delayName, uuid: delayUuid, delayMs: 50 } } : {}),
      beforeFilesystem: { filesystemType: 0xef53, totalBytes: 100 * size } }) }]]);
  const state = { mounted: true, id: '100', source: '/dev/loop17', device: '7:17', root: '/',
    type: 'ext4', options: 'rw,nosuid,nodev,relatime', homeUid: uid, homeGid: uid, homeMode: 0o700,
    mountedDevice: '1809', mountedInode: '2', backingFile: image, autoclear: '1', offset: '0', sizeLimit: '0',
    loopInode: 40n, loopRdev: 1809n, loopBlockDevice: true, loopSymlink: false,
    filesystemType: 0xef53n, blocks: BigInt(size / 4096), bsize: 4096n,
    image: { ...imageIdentity }, nestedMount: false,
    delayPresent: overrides.volumeMode === 'delay-50ms', delayName, delayUuid,
    dmDevice: '253:9', dmInode: 50n, dmRdev: 64777n, dmBlockDevice: true, dmSymlink: false,
    dmSuspended: '0', dmReadonly: '0', dmSectors: String(size / 512), dmHolders: [], dmSlaves: ['loop17'],
    loopHolders: overrides.volumeMode === 'delay-50ms' ? ['dm-9'] : [],
    loopBackingInode: '3', loopBackingDevice: '0:1', loopAssociations: ['loop17'], commandStatus: 0,
    dmModule: true, delayModule: true, controlCharacter: true, controlSymlink: false, controlUid: 0,
    targets: 'delay            v1.2.1\nlinear           v1.4.0', loopFdOpen: false, loopCloseError: false,
    table: '0 2097152 delay 7:17 0 50 7:17 0 50 7:17 0 50', filesystemUuid, ...overrides };
  if (overrides.volumeMode === 'delay-50ms' && overrides.chainPresent !== false) {
    files.set(chainFile, { uid: 0, gid: 0, mode: 0o444, links: 1, text: JSON.stringify({ image: imageIdentity,
      base: { mount: { id: '99', device: '7:17', root: '/', target: home, options: 'rw,nosuid,nodev,relatime', type: 'ext4', source: '/dev/loop17' },
        home: { device: '1809', inode: '2', uid: 0, gid: 0, mode: 0o755 }, image: imageIdentity,
        loop: { source: '/dev/loop17', device: '7:17', inode: '40', rdev: '1809', uid: 0, gid: 0, mode: 0o660,
          backingFile: image, offset: '0', sizeLimit: '0', autoclear: '1' },
        filesystem: { filesystemType: 0xef53, totalBytes: size }, filesystemUuid },
      delay: { source: '/dev/dm-9', device: '253:9', inode: '50', rdev: '64777', uid: 0, gid: 0, mode: 0o660,
        name: delayName, uuid: delayUuid, table: '0 2097152 delay 7:17 0 50 7:17 0 50 7:17 0 50' },
    }) });
    const retained = JSON.parse(files.get(chainFile).text);
    files.set(handoffFile, { uid: 0, gid: 0, mode: 0o444, links: 1, text: JSON.stringify({ image: retained.image, base: retained.base }) });
  }
  if (overrides.handoffPending) files.set(handoffFile, { uid: 0, gid: 0, mode: 0o444, links: 1, text: '{}' });
  const descriptors = new Map(), commands = [], commandOptions = []; let nextFd = 10;
  const metadata = (kind, fields) => ({ dev: BigInt(fields.device ?? 1), ino: BigInt(fields.inode ?? 1),
    uid: BigInt(fields.uid ?? 0), gid: BigInt(fields.gid ?? 0), mode: BigInt(fields.mode ?? 0o600),
    size: BigInt(fields.size ?? 0), nlink: BigInt(fields.links ?? 1),
    rdev: fields.rdev ?? 0n, isSymbolicLink: () => Boolean(fields.symlink),
    isDirectory: () => kind === 'directory', isFile: () => kind === 'file', isBlockDevice: () => kind === 'block',
    isCharacterDevice: () => kind === 'character' });
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
      if (file === '/dev/dm-9') return metadata(state.dmBlockDevice ? 'block' : 'file',
        { inode: state.dmInode, rdev: state.dmRdev, symlink: state.dmSymlink, uid: 0, mode: 0o660 });
      if (file === '/dev/mapper/control') return metadata(state.controlCharacter ? 'character' : 'file',
        { symlink: state.controlSymlink, uid: state.controlUid });
      const data = files.get(file); if (!data) throw missing();
      return metadata('file', { ...data, size: Buffer.byteLength(data.text) });
    },
    existsSync(file) {
      if (file === '/sys/module/dm_mod') return state.dmModule;
      if (file === '/sys/module/dm_delay') return state.delayModule;
      if (file.endsWith('/dm')) return state.delayPresent;
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
        const dm = { '/sys/block/dm-9/dev': state.dmDevice, '/sys/block/dm-9/dm/name': state.delayName,
          '/sys/block/dm-9/dm/uuid': state.delayUuid, '/sys/block/dm-9/dm/suspended': state.dmSuspended,
          '/sys/block/dm-9/ro': state.dmReadonly, '/sys/block/dm-9/size': state.dmSectors };
        if (file in dm) { if (!state.delayPresent) throw missing(); return `${dm[file]}\n`; }
        const values = { backing_file: state.backingFile, autoclear: state.autoclear,
          offset: state.offset, sizelimit: state.sizeLimit };
        const value = values[file.split('/').at(-1)]; if (value === undefined) throw missing(); return `${value}\n`;
      }
      const data = files.get(file); if (!data) throw missing(); return data.text;
    },
    readdirSync(file) {
      if (file === '/sys/block') return [...state.loopAssociations, ...(state.delayPresent ? ['dm-9'] : [])];
      if (file.endsWith('/7:17/holders')) return state.loopHolders;
      if (file.endsWith('/7:17/slaves')) return [];
      if (file === '/sys/block/dm-9/holders') return state.dmHolders;
      if (file === '/sys/block/dm-9/slaves') return state.dmSlaves;
      assert.fail('unexpected pure-data sysfs inventory');
    },
    spawnSync(program, args, options) {
      commands.push([program, ...args]);
      commandOptions.push(options);
      const failure = state.commandFailure;
      const selectedFailure = failure && failure.program === program && failure.operation === args[0];
      if (selectedFailure && !failure.afterEffect) return failure.result;
      let stdout;
      if (program === '/usr/sbin/blkid') stdout = state.filesystemUuid;
      else if (program === '/usr/sbin/losetup') stdout = `/dev/loop17 ${state.loopBackingInode} ${state.loopBackingDevice} 0 0 1`;
      else if (program === '/usr/sbin/dmsetup' && args[0] === 'table') stdout = state.table;
      else if (program === '/usr/sbin/dmsetup' && args[0] === 'targets') stdout = state.targets;
      else if (program === '/usr/sbin/dmsetup' && args[0] === 'create') {
        assert.deepEqual(Array.from(args), ['create', delayName, '--uuid', delayUuid, '--table', '0 2097152 delay 7:17 0 50 7:17 0 50 7:17 0 50']);
        assert.equal(state.mounted, false, 'dm must not claim an ext4-mounted original loop');
        assert.equal(state.loopFdOpen, true, 'the original AUTOCLEAR loop must remain held during handoff');
        assert.equal(state.delayPresent, false); state.delayPresent = true; state.loopHolders = ['dm-9']; stdout = '';
      } else if (program === '/usr/sbin/dmsetup' && args[0] === 'remove') {
        assert.deepEqual(Array.from(args), ['remove', delayName]);
        if (state.commandStatus !== 0) return { stdout: '', status: state.commandStatus, signal: null };
        assert.equal(state.delayPresent, true); state.delayPresent = false; state.loopHolders = []; state.backingFile = undefined; stdout = '';
      } else if (program === '/usr/bin/umount') {
        assert.deepEqual(Array.from(args), ['--', home]); assert.equal(state.mounted, true); assert.equal(state.loopFdOpen, true);
        state.mounted = false; stdout = '';
      }
      else assert.fail('these data tests do not execute privileged volume commands');
      return selectedFailure ? failure.result : { stdout, status: 0, signal: null };
    },
    statfsSync: () => ({ type: state.filesystemType, blocks: state.blocks, bsize: state.bsize }),
    openSync(file) {
      if (file === '/dev/loop17') { const fd = nextFd++; state.loopFdOpen = true; descriptors.set(fd, file); return fd; }
      assert(!files.has(file)); const fd = nextFd++; files.set(file, { uid: 0, gid: 0, mode: 0o600, links: 1, text: '' }); descriptors.set(fd, file); return fd;
    },
    fstatSync(fd) { assert.equal(descriptors.get(fd), '/dev/loop17'); return api.lstatSync('/dev/loop17'); },
    writeFileSync(fd, text) { files.get(descriptors.get(fd)).text = text; },
    fchmodSync(fd, mode) { files.get(descriptors.get(fd)).mode = mode; },
    fsyncSync() {}, closeSync(fd) {
      if (descriptors.get(fd) === '/dev/loop17') {
        if (state.loopCloseError) throw Object.assign(new Error('fixed loop close failure'), { code: 'EIO' });
        state.loopFdOpen = false;
      }
      descriptors.delete(fd);
    }, ftruncateSync() { assert.fail('these data tests do not provision an image'); },
  };
  function run(action, code = source) {
    let stdout = '';
    vm.runInNewContext(code, { ...api, assert: vmAssert, Buffer,
      process: { geteuid: () => 0, argv: ['node', '-', action, fixture, '1:1:0', home, image, originalFile, mountedFile,
        String(uid), String(uid), output, overrides.volumeMode ?? 'loop'], stdout: { write(text) { stdout += text; } } } }, { timeout: 1000 });
    return stdout;
  }
  return { state, files, commands, commandOptions, run };
}

test('all fixed volume commands keep the original output cap and request a bounded kill while awaiting actual return', () => {
  const context = setup(); context.run('capture'); assert(context.commandOptions.length > 0);
  for (const options of context.commandOptions) {
    assert.equal(options.timeout, 30_000); assert.equal(options.killSignal, 'SIGKILL');
    assert.equal(options.maxBuffer, 1024 * 1024); assert.equal(options.encoding, 'utf8');
    assert.deepEqual(Object.entries(options.env), [['PATH', '/usr/sbin:/usr/bin:/sbin:/bin'], ['LC_ALL', 'C']]);
  }
});

test('raw losetup padding is representation only; different backing identity and other escapes still refuse', () => {
  // util-linux formats BACK-MAJ:MIN with internal width padding even in its
  // raw table; libsmartcols encodes those spaces rather than a different dev.
  for (const volumeMode of ['loop', 'delay-50ms']) {
    const base = { volumeMode, ...(volumeMode === 'delay-50ms'
      ? { source: '/dev/dm-9', device: '253:9', mountedDevice: '64777' } : {}) };
    const context = setup({ ...base, loopBackingDevice: String.raw`\x20\x20\x20\x20\x20\x20\x200:1\x20\x20` });
    context.run('capture');
    assert(context.files.has(output));
    const paddedInode = setup({ ...base, loopBackingInode: String.raw`\x203\x20` });
    assert.throws(() => paddedInode.run('capture'), 'format decoding must never rewrite the original inode column');
    assert(!paddedInode.files.has(output));
    for (const device of [String.raw`\x200:2\x20`, String.raw`0\x20:1`, String.raw`\x090:1`,
      String.raw`\x200:1\x0a`, String.raw`\x200:1\x20extra`, String.raw`\x200:1\x20 7:1`, '']) {
      const refused = setup({ ...base, loopBackingDevice: device });
      assert.throws(() => refused.run('capture'));
      assert(!refused.files.has(output));
      assert(!refused.commands.some(command => command[0] === '/usr/bin/umount' || command[1] === 'remove'));
    }
  }
});

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

test('the fixed delayed-volume mode accepts only its original private device chain', () => {
  const context = setup({ volumeMode: 'delay-50ms', source: '/dev/dm-9', device: '253:9', mountedDevice: '64777' });
  context.run('capture');
  assert.equal(context.run('retire-cut'), 'mounted\n');
  const report = JSON.parse(context.files.get(output).text);
  assert.deepEqual(report.storageDelay, { kind: 'dm-delay', readMs: 50, writeMs: 50, flushMs: 50, scope: 'complete-home' });
  assert.equal(report.nativeGenerationQuotaVerified, false);
});

test('delayed capture refuses substitutions of the original image, backing identity, mapping, table or mount', () => {
  const base = { volumeMode: 'delay-50ms', source: '/dev/dm-9', device: '253:9', mountedDevice: '64777' };
  for (const changed of [
    { chainPresent: false }, { delayPresent: false }, { delayName: 'foreign-delay' }, { delayUuid: 'foreign-uuid' },
    { dmDevice: '253:10' }, { dmInode: 51n }, { dmRdev: 64778n }, { dmBlockDevice: false }, { dmSymlink: true },
    { dmSuspended: '1' }, { dmReadonly: '1' }, { dmSectors: '2097151' }, { dmHolders: ['dm-10'] },
    { dmSlaves: [] }, { dmSlaves: ['loop18'] }, { dmSlaves: ['loop17', 'loop18'] },
    { loopHolders: [] }, { loopHolders: ['dm-9', 'dm-10'] }, { loopAssociations: ['loop17', 'loop18'] },
    { loopBackingInode: '999' }, { loopBackingDevice: '0:2' }, { backingFile: '/foreign/image' },
    { autoclear: '0' }, { offset: '512' }, { sizeLimit: String(size) },
    { filesystemUuid: '99999999-1234-4123-8123-123456789abc' },
    { table: '0 2097152 delay 7:17 0 50 7:18 0 50 7:17 0 50' },
    { table: '0 2097152 delay 7:17 1 50 7:17 0 50 7:17 0 50' },
    { table: '0 2097152 delay 7:17 0 50 7:17 0 50 7:17 0 51' },
    { table: '0 2097151 delay 7:17 0 50 7:17 0 50 7:17 0 50' },
    { table: '0 2097152 delay 7:17 0 50' }, { table: '0 2097152 linear 7:17 0' },
    { table: '0 2097152 delay 7:17 0 50 7:17 0 50 7:17 0 50\n2097152 1 zero' },
    { nestedMount: true }, { root: '/foreign' }, { options: 'rw,nosuid' }, { homeUid: uid + 1 },
    { image: { ...imageIdentity, links: 2 } }, { image: { ...imageIdentity, inode: '999' } },
  ]) {
    const context = setup({ ...base, ...changed });
    assert.throws(() => context.run('capture'), changed.chainPresent === false ? { code: 'ENOENT' } : /AssertionError/u,
      JSON.stringify(changed, (_, value) => typeof value === 'bigint' ? String(value) : value));
    assert(context.commands.every(([, operation]) => ['table', '--probe', '--list'].includes(operation)), 'refusal must not issue a device mutation');
  }
  for (const changed of [{ id: '101' }, { mountedInode: '999' }, { dmInode: 51n }, { loopInode: 41n }]) {
    const context = setup(base); context.run('capture'); Object.assign(context.state, changed);
    assert.throws(() => context.run('retire-cut'), /AssertionError/u);
  }
});

test('delayed preparation retires original-loop and unmapped cuts without adopting partial resources', () => {
  const preparation = { volumeMode: 'delay-50ms', source: '/dev/loop17', device: '7:17', mountedDevice: '1809',
    id: '99', homeUid: 0, homeGid: 0, homeMode: 0o755 };
  const beforeLink = setup({ ...preparation, chainPresent: false, delayPresent: false, loopHolders: [] });
  assert.equal(beforeLink.run('retire-cut'), 'mounted\n');
  assert(!beforeLink.files.has(mountedFile));
  const afterLink = setup(preparation);
  assert.throws(() => afterLink.run('retire-cut'), /AssertionError/u, 'a completed handoff cannot still have the original loop mount');
  assert(!afterLink.files.has(mountedFile));
  afterLink.state.mounted = false;
  assert.equal(afterLink.run('retire-cut'), 'unmounted\n');
  const unregistered = setup({ ...preparation, chainPresent: false });
  assert.throws(() => unregistered.run('retire-cut'), /AssertionError/u);
  assert.throws(() => unregistered.run('remove-delay'), /AssertionError/u);
  assert(unregistered.commands.every(([, operation]) => ['table', '--probe', '--list'].includes(operation)));
  const lostMapping = setup({ ...preparation, mounted: false, delayPresent: false });
  assert.throws(() => lostMapping.run('remove-delay'), /AssertionError/u);
});

test('one delayed-volume lifecycle switches mounts and removes only the exact original mapping after normal unmount', () => {
  const context = setup({ volumeMode: 'delay-50ms', source: '/dev/loop17', device: '7:17', mountedDevice: '1809',
    id: '99', homeUid: 0, homeGid: 0, homeMode: 0o755, chainPresent: false, delayPresent: false, loopHolders: [] });
  context.run('link-delay');
  assert.equal(context.state.mounted, false, 'the filesystem must be normally unmounted before dm claims the original loop');
  assert(!context.files.has(mountedFile), 'the original loop mount must not be frozen as the later dm mount');
  context.state.mounted = false; assert.equal(context.run('delayed-mount-cut'), '/dev/dm-9\n');
  Object.assign(context.state, { mounted: true, source: '/dev/dm-9', device: '253:9', mountedDevice: '64777', id: '100' });
  context.run('ownership-cut');
  Object.assign(context.state, { homeUid: uid, homeGid: uid }); context.run('ownership-cut');
  context.state.homeMode = 0o700; context.run('capture');
  assert.equal(context.run('retire-cut'), 'mounted\n');
  assert.throws(() => context.run('remove-delay'), /AssertionError/u, 'a mounted filesystem must never be removed');
  context.state.mounted = false;
  context.run('remove-delay'); context.run('unmounted');
  const mutations = context.commands.filter(([, operation]) => ['create', 'remove'].includes(operation));
  assert.equal(mutations.length, 2);
  assert.deepEqual(mutations[1], ['/usr/sbin/dmsetup', 'remove', delayName]);
  assert(!context.commands.some(command => command.some(value => /^(?:--force|--deferred|remove_all|suspend|reload|--detach)$/u.test(value))));
});

test('busy, changed and half-created delayed resources remain, without forced or numerical cleanup', () => {
  const base = { volumeMode: 'delay-50ms', source: '/dev/dm-9', device: '253:9', mountedDevice: '64777' };
  const busy = setup({ ...base, mounted: false, commandStatus: 1 });
  assert.throws(() => busy.run('remove-delay'), /fixed owned-volume command failed/u);
  assert.equal(busy.state.delayPresent, true); assert.equal(busy.state.backingFile, image);
  assert.equal(busy.commands.filter(([, operation]) => operation === 'remove').length, 1);
  for (const changed of [{ dmInode: 51n }, { dmHolders: ['foreign'] }, { table: '0 2097152 linear 7:17 0' }, { loopBackingInode: '999' }]) {
    const context = setup({ ...base, mounted: false, ...changed });
    assert.throws(() => context.run('remove-delay'), /AssertionError/u);
    assert(!context.commands.some(([, operation]) => operation === 'remove'));
  }
  const gone = setup({ ...base, mounted: false, delayPresent: false, backingFile: undefined });
  gone.run('remove-delay'); gone.run('unmounted'); assert.equal(gone.commands.length, 0);
  const halfCreated = setup({ ...base, mounted: false, chainPresent: false });
  assert.throws(() => halfCreated.run('remove-delay'), /AssertionError/u);
  assert.equal(halfCreated.commands.length, 0);
});

test('the delayed mode refuses unavailable or substituted capabilities before provisioning any volume', () => {
  for (const changed of [
    { dmModule: false }, { delayModule: false }, { controlCharacter: false }, { controlSymlink: true }, { controlUid: uid },
    { targets: 'linear v1.4.0' }, { targets: 'delay v1.2.1\ndelay v1.2.1' }, { targets: 'delay malformed' },
  ]) {
    const context = setup({ volumeMode: 'delay-50ms', ...changed }), before = [...context.files.keys()];
    assert.throws(() => context.run('initialize'), /AssertionError/u);
    assert.deepEqual([...context.files.keys()], before);
    assert(context.commands.every(([, operation]) => operation === 'targets'));
  }
});

test('the fixed delay recipe guard rejects even a consistently recorded but different delay', () => {
  const table = '0 2097152 delay 7:17 0 50 7:17 0 50 7:17 0 51';
  const context = setup({ volumeMode: 'delay-50ms', source: '/dev/dm-9', device: '253:9', mountedDevice: '64777', table });
  const retained = JSON.parse(context.files.get(chainFile).text); retained.delay.table = table;
  context.files.get(chainFile).text = JSON.stringify(retained);
  assert.throws(() => context.run('capture'), /AssertionError/u);
  const guard = 'assert.equal(table, `0 ${ceiling / 512} delay ${retainedLoop.device} 0 50 ${retainedLoop.device} 0 50 ${retainedLoop.device} 0 50`);';
  const mutation = source.replace(guard, '/* deliberate pure-data fixed-recipe mutation */');
  assert.notEqual(mutation, source); context.run('capture', mutation);
});

test('a loop handoff close failure or missing completion retains its original mapping and immutable intent', () => {
  const preparation = { volumeMode: 'delay-50ms', source: '/dev/loop17', device: '7:17', mountedDevice: '1809',
    id: '99', homeUid: 0, homeGid: 0, homeMode: 0o755, chainPresent: false, delayPresent: false, loopHolders: [] };
  const context = setup({ ...preparation, loopCloseError: true });
  assert.throws(() => context.run('link-delay'), { code: 'EIO' });
  assert.equal(context.state.delayPresent, true); assert.equal(context.state.backingFile, image);
  assert(context.files.has(handoffFile)); assert(!context.files.has(chainFile));
  const priorCommands = context.commands.length;
  assert.throws(() => context.run('retire-cut'), /handoff is incomplete/u);
  assert.throws(() => context.run('remove-delay'), /handoff is incomplete/u);
  assert.equal(context.commands.length, priorCommands, 'incomplete handoff must not mutate or adopt its resources');
  for (const mounted of [true, false]) {
    const pending = setup({ ...preparation, mounted, handoffPending: true });
    assert.throws(() => pending.run('retire-cut'), /handoff is incomplete/u);
    assert.throws(() => pending.run('remove-delay'), /handoff is incomplete/u);
    assert.equal(pending.commands.length, 0);
  }
});

test('a returned timeout, error, signal or nonzero status cannot complete or adopt a partial loop handoff', () => {
  const preparation = { volumeMode: 'delay-50ms', source: '/dev/loop17', device: '7:17', mountedDevice: '1809',
    id: '99', homeUid: 0, homeGid: 0, homeMode: 0o755, chainPresent: false, delayPresent: false, loopHolders: [] };
  const failures = [
    { stdout: '', status: null, signal: 'SIGKILL', error: Object.assign(new Error('returned test timeout'), { code: 'ETIMEDOUT' }) },
    { stdout: '', status: 0, signal: null, error: Object.assign(new Error('returned test failure'), { code: 'EIO' }) },
    { stdout: '', status: 1, signal: null }, { stdout: '', status: 0, signal: 'SIGKILL' }, { stdout: '', status: null, signal: null },
  ];
  for (const [program, operation] of [['/usr/bin/umount', '--'], ['/usr/sbin/dmsetup', 'create']])
    for (const result of failures) for (const afterEffect of [false, true]) {
      const context = setup({ ...preparation, commandFailure: { program, operation, result, afterEffect } });
      assert.throws(() => context.run('link-delay'), /fixed owned-volume command failed/u);
      assert.equal(context.state.loopFdOpen, false, 'the original finally must complete before returning this failure');
      assert(context.files.has(handoffFile)); assert(!context.files.has(chainFile)); assert(!context.files.has(mountedFile));
      assert.equal(context.state.delayPresent, program === '/usr/sbin/dmsetup' && afterEffect);
      const priorCommands = context.commands.length;
      assert.throws(() => context.run('retire-cut'), /handoff is incomplete/u);
      assert.throws(() => context.run('remove-delay'), /handoff is incomplete/u);
      assert.equal(context.commands.length, priorCommands, 'a returned failed command cannot grant cleanup or adoption');
    }
});
