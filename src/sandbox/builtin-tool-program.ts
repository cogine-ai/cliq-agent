// One signed guest program, never a host tool adapter. The native owner has
// already claimed, confined and released this exact immutable invocation.
import { spawn } from 'node:child_process';
import { closeSync, constants, fstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { constants as osConstants } from 'node:os';
import { BUILTIN_SCRIPT_RECIPE, decodeBuiltinToolInput } from './builtin-tool-data.js';
import { readBuiltinTool, BuiltinToolReadError } from './builtin-tool-read.js';

function fixedData(fd: 3 | 4, maximum: number): Buffer {
  let failure: { error: unknown } | undefined, result: Buffer | undefined;
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.size < 0n || before.size > BigInt(maximum)) throw new TypeError('invalid fixed data descriptor');
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) { const n = readSync(fd, bytes, offset, bytes.length - offset, offset); if (!n) throw new TypeError('short fixed data'); offset += n; }
    if (readSync(fd, Buffer.alloc(1), 0, 1, offset) !== 0) throw new TypeError('long fixed data');
    const after = fstatSync(fd, { bigint: true });
    for (const key of ['dev', 'ino', 'mode', 'uid', 'gid', 'size', 'nlink', 'mtimeNs', 'ctimeNs'] as const)
      if (before[key] !== after[key]) throw new TypeError('changed fixed data');
    result = bytes;
  } catch (error) { failure = { error }; }
  // FD4 is intentionally retained until uv_spawn has inherited its readonly
  // command copy. Only fixed immutable input/code reaches this descriptor.
  if (fd === 3 || failure) { try { closeSync(fd); } catch { throw new TypeError('fixed data descriptor did not join'); } }
  if (failure) throw failure.error;
  return result!;
}
function confined(): void {
  if (process.platform !== 'linux' || process.pid !== 2 || process.ppid !== 1 || process.getuid!() !== 0 || process.getgid!() !== 0 ||
      process.cwd() !== '/work' || process.argv.length !== 2 || process.execArgv.length !== 1 || process.execArgv[0] !== '--no-addons')
    throw new TypeError('fixed tool requires its real native guest');
  const status = readFileSync('/proc/self/status', 'utf8');
  if (!/^NoNewPrivs:\s+1$/mu.test(status) || !/^CapEff:\s+0+$/mu.test(status) || !/^CapPrm:\s+0+$/mu.test(status) ||
      !/^CapInh:\s+0+$/mu.test(status) || !/^CapBnd:\s+0+$/mu.test(status) || !/^CapAmb:\s+0+$/mu.test(status)) throw new TypeError('fixed tool requires its original confinement');
  const keys = new Set(['LANG', 'LC_ALL', 'HOME', 'TMPDIR', 'PATH', 'GIT_OPTIONAL_LOCKS']);
  if (Object.keys(process.env).some(key => !keys.has(key)) || process.env.LANG !== 'C' || process.env.LC_ALL !== 'C' ||
      process.env.HOME !== '/home/cliq' || process.env.TMPDIR !== '/tmp') throw new TypeError('fixed tool has an unexpected environment');
}
async function execute(): Promise<void> {
  confined();
  const capsule = decodeBuiltinToolInput(fixedData(3, BUILTIN_SCRIPT_RECIPE.inputBytes));
  if (process.env.PATH !== (capsule.tool === 'bash' ? '/usr/bin:/bin' : '/usr/bin')) throw new TypeError('fixed tool path differs');
  if (process.env.GIT_OPTIONAL_LOCKS !== (capsule.tool === 'bash' ? '0' : undefined)) throw new TypeError('fixed Git environment differs');
  if (capsule.tool === 'bash') {
    const command = fixedData(4, BUILTIN_SCRIPT_RECIPE.inputBytes);
    if (!command.equals(Buffer.from(capsule.input.command as string))) { closeSync(4); throw new TypeError('fixed bash command differs from its original input'); }
    // Both script path and descriptor number are signed recipe literals. No
    // command, caller path, host fd, environment or startup file selects them.
    let commandFd: number;
    const before = fstatSync(4, { bigint: true });
    try { commandFd = openSync('/proc/self/fd/4', constants.O_RDONLY); }
    finally { closeSync(4); }
    let child: ReturnType<typeof spawn>;
    try {
      const after = fstatSync(commandFd, { bigint: true });
      for (const key of ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink', 'mtimeNs', 'ctimeNs'] as const)
        if (before[key] !== after[key]) throw new TypeError('changed fixed command descriptor');
      const match = /^flags:\s+([0-7]+)$/mu.exec(readFileSync(`/proc/self/fdinfo/${commandFd}`, 'utf8'));
      const flags = match ? Number.parseInt(match[1]!, 8) : -1;
      if (flags < 0 || (flags & 3) !== 0 || !(flags & 0o2000000)) throw new TypeError('command descriptor is not readonly close-on-exec');
      child = spawn(BUILTIN_SCRIPT_RECIPE.bashPath, ['--noprofile', '--norc', '/proc/self/fd/3'], {
        cwd: '/work', env: { LANG: 'C', LC_ALL: 'C', HOME: '/home/cliq', TMPDIR: '/tmp', PATH: '/usr/bin:/bin', GIT_OPTIONAL_LOCKS: '0' },
        stdio: ['ignore', 'inherit', 'inherit', commandFd] });
    } finally { closeSync(commandFd); }
    const ended = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
    });
    if (ended.signal) {
      const number = osConstants.signals[ended.signal];
      // The actual native executable is this fixed Node adapter. Preserve the
      // observed command signal as its conventional nonzero status; signalling
      // Node itself could trigger a reserved runtime action (e.g. SIGUSR1).
      process.stderr.write(`TOOL_COMMAND_SIGNAL:${ended.signal}\n`); process.exitCode = 128 + number;
    } else process.exitCode = ended.code ?? 70;
    return;
  }
  const root = await open('/work', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { process.stdout.write(await readBuiltinTool(root, capsule)); }
  finally { await root.close(); }
}
// This asset is only a standalone signed entry, never a reusable module.
// Do not infer execution from pathname equality (e.g. /var vs /private/var).
await execute().catch(error => {
  process.stderr.write(`${error instanceof BuiltinToolReadError ? error.code : 'FIXED_TOOL_EXECUTION_FAILED'}\n`);
  process.exitCode = 70;
});
