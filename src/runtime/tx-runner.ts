import type { TxBashPolicy, TxValidatorsConfig, TxStagedViewConfig } from '../workspace/config.js';

export type TxRunnerOptions = {
  mode: 'edit';
  auto: 'per-turn' | 'manual';
  applyPolicy: 'interactive' | 'auto-on-pass' | 'manual-only';
  bashPolicy: TxBashPolicy;
  headless: boolean;
  validatorsConfig: TxValidatorsConfig;
  stagedViewConfig: TxStagedViewConfig;
  workspaceId: string;
  workspaceRealPath: string;
  cliqHome?: string;
  confirmApply?: () => Promise<boolean>;
};

export function assertHeadlessCompatible(opts: TxRunnerOptions): void {
  if (opts.headless && opts.applyPolicy === 'interactive') {
    throw new Error('--tx-apply interactive requires a TTY; use --tx-apply manual-only or auto-on-pass for headless runs');
  }
}
