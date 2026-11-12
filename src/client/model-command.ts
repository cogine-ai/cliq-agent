import { controlWireText } from '../kernel/control-wire-data.js';

/** User intent only. No model, credential, backend or execution authority. */
export function modelCommand(argv: readonly string[]) {
  if (argv[1] === 'list' && argv.length === 2) return { kind: 'list' as const };
  const alias = argv[2];
  if (!alias || alias.startsWith('--')) throw new TypeError('use models add <alias>, models retire <alias> or models list');
  controlWireText(alias, 128);
  if (argv[1] === 'retire' && argv.length === 3) return { kind: 'retire' as const, alias };
  if (argv[1] !== 'add') throw new TypeError('use models add <alias>, models retire <alias> or models list');
  let profileId = 'default', input: 'stdin' | 'terminal' = 'terminal', manifestPath: string | undefined, localModel: string | undefined;
  const used = new Set<string>();
  for (let index = 3; index < argv.length; index++) {
    const flag = argv[index]!;
    if (used.has(flag)) throw new TypeError('model option may be supplied only once'); used.add(flag);
    if (flag === '--api-key-stdin') { input = 'stdin'; continue; }
    if (!['--profile', '--manifest', '--local'].includes(flag)) throw new TypeError('unsupported model option; keys are never command arguments');
    const value = argv[++index]; if (!value || value.startsWith('--')) throw new TypeError('model option needs one value');
    if (flag === '--profile') profileId = controlWireText(value, 128);
    else if (flag === '--manifest') manifestPath = controlWireText(value, 4096);
    else localModel = controlWireText(value, 512);
  }
  if (manifestPath !== undefined || localModel !== undefined) {
    if (manifestPath !== undefined && localModel !== undefined || used.has('--profile') || used.has('--api-key-stdin'))
      throw new TypeError('choose one local manifest or enrolled model; local models take no endpoint or key');
    return manifestPath !== undefined ? { kind: 'enroll' as const, alias, manifestPath }
      : { kind: 'local' as const, alias, model: localModel! };
  }
  return { kind: 'add' as const, alias, profileId, input };
}
