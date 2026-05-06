import type { Severity } from '../workspace/transactions/types.js';

export type ValidatorStatus = 'pass' | 'fail' | 'error';

export type Finding = {
  path?: string;
  line?: number;
  column?: number;
  severity?: Severity;
  message: string;
};

export type ValidatorResult = {
  name: string;
  severity: Severity;
  status: ValidatorStatus;
  durationMs: number;
  message?: string;
  findings?: Finding[];
  artifactPath?: string;
};

export type ValidatorContext = {
  txId: string;
  workspaceView: string;
  realCwd: string;
  signal: AbortSignal;
};

export type Validator = {
  name: string;
  defaultSeverity: Severity;
  run(ctx: ValidatorContext): Promise<ValidatorResult>;
};
