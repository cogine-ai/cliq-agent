import assert from 'node:assert/strict';
import test from 'node:test';

import { buildShellSpawn, resolveShellSpec } from './shell.js';

test('resolveShellSpec keeps bash -lc as the default on macOS and Linux', () => {
  for (const platform of ['darwin', 'linux'] as const) {
    const shell = resolveShellSpec({ platform });

    assert.equal(shell.provider, 'bash');
    assert.equal(shell.command, 'bash');
    assert.deepEqual(shell.args, ['-lc']);
    assert.equal(shell.label, 'bash');
    assert.deepEqual(buildShellSpawn(shell, 'echo ok'), {
      command: 'bash',
      args: ['-lc', 'echo ok']
    });
  }
});

test('resolveShellSpec defaults Windows to native PowerShell instead of bash', () => {
  const shell = resolveShellSpec({ platform: 'win32' });

  assert.equal(shell.provider, 'powershell');
  assert.equal(shell.command, 'powershell.exe');
  assert.deepEqual(shell.args, ['-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command']);
  assert.equal(shell.label, 'PowerShell');
  assert.deepEqual(buildShellSpawn(shell, 'Get-ChildItem'), {
    command: 'powershell.exe',
    args: ['-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', 'Get-ChildItem']
  });
});

test('resolveShellSpec honors configured shell provider defaults', () => {
  assert.deepEqual(resolveShellSpec({ platform: 'win32', config: { provider: 'cmd' } }), {
    provider: 'cmd',
    command: 'cmd.exe',
    args: ['/d', '/s', '/c'],
    label: 'cmd'
  });

  assert.deepEqual(resolveShellSpec({ platform: 'win32', config: { provider: 'bash' } }), {
    provider: 'bash',
    command: 'bash',
    args: ['-lc'],
    label: 'bash'
  });
});

test('resolveShellSpec honors explicit command and args as a custom shell', () => {
  const shell = resolveShellSpec({
    platform: 'linux',
    config: { command: 'nu', args: ['-c'], label: 'Nushell' }
  });

  assert.deepEqual(shell, {
    provider: 'custom',
    command: 'nu',
    args: ['-c'],
    label: 'Nushell'
  });
  assert.deepEqual(buildShellSpawn(shell, 'ls'), {
    command: 'nu',
    args: ['-c', 'ls']
  });
});
