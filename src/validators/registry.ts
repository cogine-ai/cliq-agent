import type { TxValidatorsConfig } from '../workspace/config.js';
import { diffSanity } from './builtin/diff-sanity.js';
import { indexClean } from './builtin/index-clean.js';
import { sizeLimit } from './builtin/size-limit.js';
import { createShellValidator } from './shell.js';
import type { Validator } from './types.js';

export function buildValidatorRegistry(config: TxValidatorsConfig = {}): Validator[] {
  const disabled = new Set(config.disabled ?? []);
  const builtins: Validator[] = [diffSanity, indexClean, sizeLimit];
  const enabledBuiltins = builtins.filter((v) => !disabled.has(v.name));
  const shellHooks = (config.shell ?? [])
    .filter((s) => !disabled.has(s.name))
    .map((s) =>
      createShellValidator({
        name: s.name,
        command: s.command,
        severity: s.severity,
        timeoutMs: s.timeoutMs
      })
    );
  return [...enabledBuiltins, ...shellHooks];
}
