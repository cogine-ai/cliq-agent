import { execFile } from 'node:child_process';

import type { OsPathAction } from '../protocol/model/actions.js';
import type { ToolDefinition, ToolResult } from './types.js';

type CommandResult = {
  stdout: string;
  stderr: string;
};

type CommandRunner = (file: string, args: string[]) => Promise<CommandResult>;

export type WindowsDesktopPaths = {
  host: 'windows' | 'wsl';
  method: string;
  personalDesktop: string;
  publicDesktop: string;
};

type DesktopResolverOptions = {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  runCommand?: CommandRunner;
};

type OsPathToolOptions = {
  resolveDesktopPaths?: () => Promise<WindowsDesktopPaths>;
};

const DESKTOP_DISCOVERY_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
  '$personal = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)',
  '$public = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonDesktopDirectory)',
  '[pscustomobject]@{ personalDesktop = $personal; publicDesktop = $public } | ConvertTo-Json -Compress'
].join('; ');

function runCommand(file: string, args: string[]): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    execFile(
      file,
      args,
      {
        encoding: 'utf8',
        timeout: 15_000,
        windowsHide: true,
        maxBuffer: 1024 * 1024
      },
      (error, stdout, stderr) => {
        if (error) {
          reject(error);
          return;
        }

        resolve({ stdout, stderr });
      }
    );
  });
}

export function isWslLikeHost(platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env) {
  return platform === 'linux' && Boolean(env.WSL_DISTRO_NAME || env.WSL_INTEROP || env.WSLENV);
}

function parseDesktopDiscoveryJson(raw: string) {
  const parsed = JSON.parse(raw.trim()) as { personalDesktop?: unknown; publicDesktop?: unknown };
  const personalDesktop = typeof parsed.personalDesktop === 'string' ? parsed.personalDesktop.trim() : '';
  const publicDesktop = typeof parsed.publicDesktop === 'string' ? parsed.publicDesktop.trim() : '';

  if (!personalDesktop && !publicDesktop) {
    throw new Error('Windows Desktop discovery returned no personal or public Desktop path');
  }

  return { personalDesktop, publicDesktop };
}

export async function resolveWindowsDesktopPaths({
  platform = process.platform,
  env = process.env,
  runCommand: runner = runCommand
}: DesktopResolverOptions = {}): Promise<WindowsDesktopPaths> {
  const isWindows = platform === 'win32';
  const isWsl = isWslLikeHost(platform, env);
  if (!isWindows && !isWsl) {
    throw new Error('Windows Desktop discovery is only available on native Windows or WSL hosts');
  }

  const result = await runner('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', DESKTOP_DISCOVERY_SCRIPT]);
  const paths = parseDesktopDiscoveryJson(result.stdout);

  return {
    host: isWsl ? 'wsl' : 'windows',
    method: 'powershell.exe known folders',
    ...paths
  };
}

function formatDesktopResult(paths: WindowsDesktopPaths): ToolResult {
  const lines = [
    'TOOL_RESULT os_path OK',
    'name=desktop',
    `host=${paths.host}`,
    `method=${paths.method}`,
    `Personal Desktop: ${paths.personalDesktop || '(not returned)'}`,
    `Public Desktop: ${paths.publicDesktop || '(not returned)'}`,
    'Guidance: inspect the personal desktop first, keep public shortcuts separate, and avoid broad recursive scans unless the user explicitly asks.'
  ];

  if (paths.host === 'wsl') {
    lines.push('WSL note: use Windows-native commands for redirected Windows paths, or convert paths intentionally before using bash.');
  }

  return {
    tool: 'os_path',
    status: 'ok',
    meta: {
      name: 'desktop',
      host: paths.host,
      method: paths.method,
      personalDesktop: paths.personalDesktop,
      publicDesktop: paths.publicDesktop
    },
    content: lines.join('\n')
  };
}

export function createOsPathTool({
  resolveDesktopPaths = () => resolveWindowsDesktopPaths()
}: OsPathToolOptions = {}): ToolDefinition<{ os_path: OsPathAction }> {
  return {
    name: 'os_path',
    access: 'read',
    supports(action): action is { os_path: OsPathAction } {
      return (
        typeof (action as { os_path?: unknown }).os_path === 'object' &&
        !!(action as { os_path?: unknown }).os_path &&
        (action as { os_path: { name?: unknown } }).os_path.name === 'desktop'
      );
    },
    async execute(action): Promise<ToolResult> {
      try {
        if (action.os_path.name !== 'desktop') {
          throw new Error(`unsupported os_path name: ${String(action.os_path.name)}`);
        }

        return formatDesktopResult(await resolveDesktopPaths());
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          tool: 'os_path',
          status: 'error',
          meta: { name: action.os_path.name, error: message },
          content: `TOOL_RESULT os_path ERROR\nname=${action.os_path.name}\n${message}`
        };
      }
    }
  };
}

export const osPathTool = createOsPathTool();
