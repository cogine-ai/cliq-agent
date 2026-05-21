import assert from 'node:assert/strict';
import test from 'node:test';

import { createSession } from '../session/store.js';
import { createToolRegistry } from './registry.js';
import { createOsPathTool, isWslLikeHost, resolveWindowsDesktopPaths } from './os-path.js';

test('resolveWindowsDesktopPaths queries personal and public Desktop with PowerShell known folders', async () => {
  const calls: Array<{ file: string; args: string[] }> = [];

  const result = await resolveWindowsDesktopPaths({
    platform: 'win32',
    env: {},
    runCommand: async (file, args) => {
      calls.push({ file, args });
      return {
        stdout: JSON.stringify({
          personalDesktop: 'D:\\HuaweiMoveData\\Users\\YJ\\Desktop',
          publicDesktop: 'C:\\Users\\Public\\Desktop'
        }),
        stderr: ''
      };
    }
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.file, 'powershell.exe');
  assert.match(calls[0]?.args.join(' ') ?? '', /DesktopDirectory/);
  assert.match(calls[0]?.args.join(' ') ?? '', /CommonDesktopDirectory/);
  assert.deepEqual(result, {
    host: 'windows',
    method: 'powershell.exe known folders',
    personalDesktop: 'D:\\HuaweiMoveData\\Users\\YJ\\Desktop',
    publicDesktop: 'C:\\Users\\Public\\Desktop'
  });
});

test('resolveWindowsDesktopPaths uses Windows-native PowerShell from WSL-like hosts', async () => {
  const result = await resolveWindowsDesktopPaths({
    platform: 'linux',
    env: { WSL_DISTRO_NAME: 'Ubuntu' },
    runCommand: async (file) => {
      assert.equal(file, 'powershell.exe');
      return {
        stdout: JSON.stringify({
          personalDesktop: 'C:\\Users\\YJ\\Desktop',
          publicDesktop: 'C:\\Users\\Public\\Desktop'
        }),
        stderr: ''
      };
    }
  });

  assert.equal(result.host, 'wsl');
  assert.equal(result.personalDesktop, 'C:\\Users\\YJ\\Desktop');
  assert.equal(result.publicDesktop, 'C:\\Users\\Public\\Desktop');
});

test('isWslLikeHost detects common WSL environment markers', () => {
  assert.equal(isWslLikeHost('linux', { WSL_INTEROP: '/run/WSL/1_interop' }), true);
  assert.equal(isWslLikeHost('linux', { WSL_DISTRO_NAME: 'Ubuntu' }), true);
  assert.equal(isWslLikeHost('linux', {}), false);
  assert.equal(isWslLikeHost('darwin', { WSL_DISTRO_NAME: 'Ubuntu' }), false);
});

test('os_path tool keeps personal and public Desktop sources separate', async () => {
  const tool = createOsPathTool({
    resolveDesktopPaths: async () => ({
      host: 'wsl',
      method: 'powershell.exe known folders',
      personalDesktop: 'D:\\HuaweiMoveData\\Users\\YJ\\Desktop',
      publicDesktop: 'C:\\Users\\Public\\Desktop'
    })
  });

  const result = await tool.execute(
    { os_path: { name: 'desktop' } },
    { cwd: '/tmp/workspace', session: createSession('/tmp/workspace') }
  );

  assert.equal(result.status, 'ok');
  assert.equal(result.meta.personalDesktop, 'D:\\HuaweiMoveData\\Users\\YJ\\Desktop');
  assert.equal(result.meta.publicDesktop, 'C:\\Users\\Public\\Desktop');
  assert.match(result.content, /Personal Desktop: D:\\HuaweiMoveData\\Users\\YJ\\Desktop/);
  assert.match(result.content, /Public Desktop: C:\\Users\\Public\\Desktop/);
  assert.match(result.content, /keep public shortcuts separate/i);
  assert.match(result.content, /avoid broad recursive scans/i);
});

test('default registry exposes os_path as a read tool', () => {
  const { definition } = createToolRegistry().resolve({ os_path: { name: 'desktop' } });

  assert.equal(definition.name, 'os_path');
  assert.equal(definition.access, 'read');
});
