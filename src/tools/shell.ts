import type { ShellConfig, ShellProvider } from '../workspace/config.js';

export type ResolvedShellProvider = ShellProvider | 'custom';

export type ShellSpec = {
  provider: ResolvedShellProvider;
  command: string;
  args: string[];
  label: string;
};

export type ShellResolutionOptions = {
  platform?: NodeJS.Platform;
  config?: ShellConfig;
};

type ProviderDefaults = Omit<ShellSpec, 'provider'> & { provider: ShellProvider };

function providerDefaults(provider: ShellProvider, platform: NodeJS.Platform): ProviderDefaults {
  if (provider === 'powershell') {
    return {
      provider,
      command: platform === 'win32' ? 'powershell.exe' : 'pwsh',
      args: platform === 'win32'
        ? ['-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command']
        : ['-NoLogo', '-NoProfile', '-Command'],
      label: 'PowerShell'
    };
  }

  if (provider === 'cmd') {
    return {
      provider,
      command: platform === 'win32' ? 'cmd.exe' : 'cmd',
      args: ['/d', '/s', '/c'],
      label: 'cmd'
    };
  }

  return {
    provider,
    command: 'bash',
    args: ['-lc'],
    label: 'bash'
  };
}

export function resolveShellSpec(options: ShellResolutionOptions = {}): ShellSpec {
  const platform = options.platform ?? process.platform;
  const config = options.config;

  if (config?.command && !config.provider) {
    return {
      provider: 'custom',
      command: config.command,
      args: config.args ?? [],
      label: config.label ?? config.command
    };
  }

  const defaults = providerDefaults(config?.provider ?? (platform === 'win32' ? 'powershell' : 'bash'), platform);
  return {
    provider: defaults.provider,
    command: config?.command ?? defaults.command,
    args: config?.args ?? defaults.args,
    label: config?.label ?? defaults.label
  };
}

export function buildShellSpawn(shell: ShellSpec, command: string) {
  return {
    command: shell.command,
    args: [...shell.args, command]
  };
}
