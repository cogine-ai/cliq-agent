import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { mock } from 'node:test';
import { promisify } from 'node:util';

import { HEADLESS_SCHEMA_VERSION } from './headless/contract.js';
import {
  cliExitCode,
  formatTxRuntimeEventLine,
  formatToolResultLine,
  isReportedCliError,
  parseArgs,
  printHelp,
  renderUnhandledError,
  resolveTuiDebug,
  resolveTuiInitialPolicy,
  resolveTuiPreference,
  resolveTxIdForReview,
  notifyIfPackageUpdateAvailable,
  hydratePlanProgressBestEffort,
  hydratePendingPlanReview,
  hydratePlanProgress,
  applyTuiModelSetupSelection,
  buildTuiModelSetupSnapshot,
  discoverTuiModelSetupModels,
  modelConfigForSetupError,
  resolveModelConfigWithInteractiveSetup,
  ReportedCliError,
  runCli
} from './cli.js';
import { authFilePath } from './model/auth-store.js';
import { ModelSetupRequiredError } from './model/config.js';
import type { ModelClient, ResolvedModelConfig } from './model/types.js';
import { approvePlan, createDraftPlan, finalizePlan, planProgressPath } from './plans/store.js';
import { createCheckpoint } from './session/checkpoints.js';
import { createSession, ensureSession, saveSession, sessionFilePath } from './session/store.js';
import { WorkspaceTrustError } from './session/trust.js';
import type { ToolResult } from './tools/types.js';
import type { UiAction, UiStore } from './tui/store.js';
import { appendBashEffect } from './workspace/transactions/bash-effects.js';
import type { WorkspaceConfig } from './workspace/config.js';
import {
  createTx,
  resolveTxRoot,
  validatorsDir,
  writeDiff,
  writeTxState
} from './workspace/transactions/store.js';

const execFileAsync = promisify(execFile);

test('parseArgs accepts --policy=plan', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--policy=plan', 'chat']), {
    cmd: 'chat',
    prompt: '',
    policy: 'plan',
    policyExplicit: true,
    skills: [],
    model: {}
  });
});

test('parseArgs accepts --policy accept-edits for prompt shorthand', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--policy', 'accept-edits', 'fix', 'tests']), {
    cmd: 'run',
    prompt: 'fix tests',
    policy: 'accept-edits',
    policyExplicit: true,
    skills: [],
    model: {}
  });
});

test('parseArgs accepts command-scoped run --jsonl', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'run', '--jsonl', 'inspect', 'repo']), {
    cmd: 'run',
    prompt: 'inspect repo',
    jsonl: true,
    policy: 'default',
    skills: [],
    model: {}
  });
});

test('parseArgs accepts --tui-debug', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--tui-debug', 'chat']), {
    cmd: 'chat',
    prompt: '',
    policy: 'default',
    skills: [],
    model: {},
    tuiDebug: true
  });
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--tui-debug=1', 'chat']),
    /--tui-debug does not accept a value/
  );
});

test('parseArgs normalizes non-interactive prompt shortcuts to run', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'inspect', 'repo']), {
    cmd: 'run',
    prompt: 'inspect repo',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'ask', '--literal', 'prompt']), {
    cmd: 'run',
    prompt: '--literal prompt',
    policy: 'default',
    skills: [],
    model: {}
  });
});

test('parseArgs accepts top-level version flags without stealing run prompts', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--version']), {
    cmd: 'version',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '-v']), {
    cmd: 'version',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'run', '-v']), {
    cmd: 'run',
    prompt: '-v',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--version', 'extra']),
    /Unknown --version argument: extra/i
  );
});

test('parseArgs keeps --jsonl in the prompt after the first prompt token', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'run', 'inspect', '--jsonl']), {
    cmd: 'run',
    prompt: 'inspect --jsonl',
    policy: 'default',
    skills: [],
    model: {}
  });
});

test('parseArgs accepts rpc as a no-prompt command and rejects extra args', () => {
  assert.deepEqual(parseArgs(['node', 'cliq', 'rpc']), {
    cmd: 'rpc',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.throws(() => parseArgs(['node', 'cliq', 'rpc', 'extra']), /Unknown rpc argument: extra/i);
});

test('parseArgs accepts providers status and validation commands', () => {
  assert.deepEqual(parseArgs(['node', 'cliq', 'providers']), {
    cmd: 'providers-status',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'cliq', 'providers', 'status', '--json']), {
    cmd: 'providers-status',
    json: true,
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'cliq', 'providers', 'validate', 'openai']), {
    cmd: 'providers-validate',
    provider: 'openai',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'cliq', 'providers', 'auth', 'set', 'openai', '--api-key', '--model', 'gpt-5.2']), {
    cmd: 'providers-auth-set',
    provider: 'openai',
    apiKeySource: 'prompt',
    authModel: { model: 'gpt-5.2' },
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'cliq', 'providers', 'auth', 'set', 'openai', '--api-key-stdin', '--model', 'gpt-5.2']), {
    cmd: 'providers-auth-set',
    provider: 'openai',
    apiKeySource: 'stdin',
    authModel: { model: 'gpt-5.2' },
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'cliq', 'providers', 'auth', 'set', 'openai', '--model', 'gpt-5.2']), {
    cmd: 'providers-auth-set',
    provider: 'openai',
    authModel: { model: 'gpt-5.2' },
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(
    parseArgs([
      'node',
      'cliq',
      'providers',
      'auth',
      'set',
      'openai-compatible',
      '--base-url',
      'http://localhost:4000/v1',
      '--streaming',
      'off'
    ]),
    {
      cmd: 'providers-auth-set',
      provider: 'openai-compatible',
      authModel: { baseUrl: 'http://localhost:4000/v1', streaming: 'off' },
      policy: 'default',
      skills: [],
      model: {}
    }
  );
  assert.throws(
    () => parseArgs(['node', 'cliq', 'providers', 'auth', 'set', 'openai', '--api-key', 'sk-secret']),
    /--api-key prompts securely and does not accept a value/i
  );
  assert.throws(
    () => parseArgs(['node', 'cliq', 'providers', 'auth', 'set', 'openai', '--api-key=sk-secret']),
    /--api-key prompts securely and does not accept a value/i
  );
  assert.throws(
    () => parseArgs(['node', 'cliq', 'providers', 'auth', 'set', 'openai', '--json', '--model', 'gpt-5.2']),
    /providers auth set does not support --json/i
  );
});

test('parseArgs requires a prompt for run aliases', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'run']), /missing prompt for cliq run/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'run', '--jsonl']), /missing prompt for cliq run/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'ask']), /missing prompt for cliq ask/i);
});

test('parseArgs rejects --jsonl outside cliq run', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'chat', '--jsonl']), /--jsonl is only supported with cliq run/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'ask', '--jsonl', 'inspect']), /--jsonl is only supported with cliq run/i);
});

test('parseArgs keeps --jsonl literal in prompt fallback paths', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'inspect', '--jsonl']), {
    cmd: 'run',
    prompt: 'inspect --jsonl',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--jsonl', 'inspect']), {
    cmd: 'run',
    prompt: '--jsonl inspect',
    policy: 'default',
    skills: [],
    model: {}
  });
});

test('parseArgs rejects invalid policy values', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--policy', 'invalid', 'chat']), /Unknown policy mode/i);
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--policy', 'read-only', 'chat']),
    /read-only has been replaced by plan/i
  );
});

test('parseArgs rejects missing policy values', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--policy']), /Missing value for --policy/i);
});

test('parseArgs --preset is an alias for --policy and marks policy explicit', () => {
  const flag = parseArgs(['node', 'src/index.ts', '--preset', 'default', 'chat']);
  assert.equal(flag.policy, 'default');
  assert.equal(flag.policyExplicit, true);

  const eq = parseArgs(['node', 'src/index.ts', '--preset=plan', 'chat']);
  assert.equal(eq.policy, 'plan');
  assert.equal(eq.policyExplicit, true);
});

test('parseArgs rejects --preset xxx unknown mode and missing value', () => {
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--preset', 'frobnicate']),
    /Unknown policy mode/i
  );
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--preset', 'confirm-bash']),
    /confirm-bash has been replaced by accept-edits/i
  );
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--preset']),
    /Missing value for --preset/i
  );
});

test('parseArgs refuses simultaneous --policy and --preset (either order)', () => {
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--policy', 'default', '--preset', 'default']),
    /--policy and --preset are mutually exclusive/i
  );
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--preset=yolo', '--policy=yolo']),
    /--preset and --policy are mutually exclusive/i
  );
});

test('parseArgs tolerates CLIQ_POLICY_MODE + --preset (env is not a CLI conflict)', () => {
  const previous = process.env.CLIQ_POLICY_MODE;
  process.env.CLIQ_POLICY_MODE = 'default';
  try {
    const parsed = parseArgs(['node', 'src/index.ts', '--preset', 'plan', 'chat']);
    assert.equal(parsed.policy, 'plan');
    assert.equal(parsed.policyExplicit, true);
  } finally {
    if (previous === undefined) delete process.env.CLIQ_POLICY_MODE;
    else process.env.CLIQ_POLICY_MODE = previous;
  }
});

test('parseArgs collects --allow / --deny / --ask as a layered cliPermissions block', () => {
  const parsed = parseArgs([
    'node',
    'src/index.ts',
    '--allow',
    'bash: git *',
    '--allow=fs-read: docs/*',
    '--deny',
    'fs-write: .env',
    '--ask=fs-write: src/*',
    'chat'
  ]);
  assert.deepEqual(parsed.cliPermissions, {
    allow: [
      { channel: 'bash', pattern: 'git *', source: 'cli' },
      { channel: 'fs-read', pattern: 'docs/*', source: 'cli' }
    ],
    deny: [{ channel: 'fs-write', pattern: '.env', source: 'cli' }],
    ask: [{ channel: 'fs-write', pattern: 'src/*', source: 'cli' }]
  });
});

test('parseArgs leaves cliPermissions undefined when no allow/deny/ask flag is given', () => {
  const parsed = parseArgs(['node', 'src/index.ts', 'chat']);
  assert.equal(parsed.cliPermissions, undefined);
});

test('parseArgs surfaces grammar errors for malformed --allow/--deny rules with the flag name', () => {
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--allow', 'no-colon-here']),
    /--allow.*missing a colon/i
  );
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--deny=unknown-channel: foo']),
    /--deny.*unknown channel/i
  );
});

test('parseArgs rejects invalid CLIQ_POLICY_MODE values', () => {
  const previous = process.env.CLIQ_POLICY_MODE;
  process.env.CLIQ_POLICY_MODE = 'invalid';

  try {
    assert.throws(
      () => parseArgs(['node', 'src/index.ts', 'chat']),
      /Invalid CLIQ_POLICY_MODE: invalid; expected one of:/i
    );
  } finally {
    if (previous === undefined) {
      delete process.env.CLIQ_POLICY_MODE;
    } else {
      process.env.CLIQ_POLICY_MODE = previous;
    }
  }
});

test('parseArgs lets explicit CLI policy override an invalid CLIQ_POLICY_MODE', () => {
  const previous = process.env.CLIQ_POLICY_MODE;
  process.env.CLIQ_POLICY_MODE = 'read-only';

  try {
    const parsed = parseArgs(['node', 'src/index.ts', '--policy', 'plan', 'chat']);
    assert.equal(parsed.policy, 'plan');
    assert.equal(parsed.policyExplicit, true);
  } finally {
    if (previous === undefined) {
      delete process.env.CLIQ_POLICY_MODE;
    } else {
      process.env.CLIQ_POLICY_MODE = previous;
    }
  }
});

test('parseArgs rejects legacy CLIQ_POLICY_MODE values with migration guidance', () => {
  const previous = process.env.CLIQ_POLICY_MODE;
  process.env.CLIQ_POLICY_MODE = 'read-only';

  try {
    assert.throws(
      () => parseArgs(['node', 'src/index.ts', 'chat']),
      /Invalid CLIQ_POLICY_MODE: read-only has been replaced by plan/i
    );
  } finally {
    if (previous === undefined) {
      delete process.env.CLIQ_POLICY_MODE;
    } else {
      process.env.CLIQ_POLICY_MODE = previous;
    }
  }
});

test('parseArgs collects repeated --skill flags', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--skill', 'reviewer', '--skill=safe-edit', 'chat']), {
    cmd: 'chat',
    prompt: '',
    policy: 'default',
    skills: ['reviewer', 'safe-edit'],
    model: {}
  });
});

test('parseArgs rejects missing --skill values', () => {
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--skill']),
    /Missing value for --skill/i
  );
});

test('parseArgs rejects --skill when the next token is another flag', () => {
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--skill', '--policy', 'plan', 'chat']),
    /Missing value for --skill/i
  );
});

test('parseArgs keeps skills on non-chat commands for downstream assembly parity', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--skill', 'reviewer', 'history']), {
    cmd: 'history',
    policy: 'default',
    skills: ['reviewer'],
    model: {}
  });
});

test('parseArgs accepts checkpoint fork id and name', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'fork', 'chk_123', 'alternate', 'path']), {
    cmd: 'checkpoint-fork',
    checkpointId: 'chk_123',
    name: 'alternate path',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(
    parseArgs(['node', 'src/index.ts', 'checkpoint', 'fork', 'chk_123', '--restore-files', '--yes', 'alternate', 'path']),
    {
      cmd: 'checkpoint-fork',
      checkpointId: 'chk_123',
      restoreFiles: true,
      yes: true,
      name: 'alternate path',
      policy: 'default',
      skills: [],
      model: {}
    }
  );
});

test('parseArgs rejects checkpoint fork without a checkpoint id', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'checkpoint', 'fork']), /Missing checkpoint id for checkpoint fork/i);
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', 'checkpoint', 'fork', 'chk_1', '--bad']),
    /Unknown checkpoint fork argument/i
  );
});

test('parseArgs accepts workflow asset commands', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'create', 'before', 'edit']), {
    cmd: 'checkpoint-create',
    name: 'before edit',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'list']), {
    cmd: 'checkpoint-list',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(
    parseArgs(['node', 'src/index.ts', 'checkpoint', 'restore', 'chk_1', '--scope', 'files', '--yes', '--allow-staged']),
    {
      cmd: 'checkpoint-restore',
      checkpointId: 'chk_1',
      scope: 'files',
      yes: true,
      allowStagedChanges: true,
      policy: 'default',
      skills: [],
      model: {}
    }
  );
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compact', 'create', '--before', 'chk_1', '--summary', 'summary text']), {
    cmd: 'compact-create',
    beforeCheckpointId: 'chk_1',
    summaryMarkdown: 'summary text',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compact', 'list']), {
    cmd: 'compact-list',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'handoff', 'create', '--checkpoint=chk_1']), {
    cmd: 'handoff-create',
    checkpointId: 'chk_1',
    policy: 'default',
    skills: [],
    model: {}
  });
});

test('parseArgs accepts workflow asset help commands', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint']), {
    cmd: 'help',
    topic: 'checkpoint',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'help']), {
    cmd: 'help',
    topic: 'checkpoint',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compact', '--help']), {
    cmd: 'help',
    topic: 'compact',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'handoff', '-h']), {
    cmd: 'help',
    topic: 'handoff',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'help', 'checkpoint']), {
    cmd: 'help',
    topic: 'checkpoint',
    policy: 'default',
    skills: [],
    model: {}
  });
});

test('parseArgs accepts leaf workflow asset help flags', () => {
  const expectedCheckpointHelp = {
    cmd: 'help',
    topic: 'checkpoint',
    policy: 'default',
    skills: [],
    model: {}
  };
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'create', '--help']), expectedCheckpointHelp);
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'list', '-h']), expectedCheckpointHelp);
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'restore', '--help']), expectedCheckpointHelp);
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'fork', '-h']), expectedCheckpointHelp);
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compact', 'create', '--help']), {
    cmd: 'help',
    topic: 'compact',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compact', 'list', '-h']), {
    cmd: 'help',
    topic: 'compact',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'handoff', 'create', '--help']), {
    cmd: 'help',
    topic: 'handoff',
    policy: 'default',
    skills: [],
    model: {}
  });
});

test('parseArgs rejects compact without an explicit summary', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'compact', 'create']), /Missing value for --summary/i);
});

test('parseArgs rejects restore without a checkpoint id or with an invalid scope', () => {
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', 'checkpoint', 'restore']),
    /Missing checkpoint id for checkpoint restore/i
  );
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', 'checkpoint', 'restore', 'chk_1', '--scope', 'bad']),
    /Unknown restore scope/i
  );
});

test('parseArgs recognizes cliq tx open with optional name', () => {
  const a = parseArgs(['node', 'src/index.ts', 'tx', 'open']);
  assert.equal(a.cmd, 'tx-open');
  if (a.cmd === 'tx-open') {
    assert.equal(a.name, undefined);
    assert.equal(a.explicit, true);
  }
  const b = parseArgs(['node', 'src/index.ts', 'tx', 'open', 'feature-x']);
  assert.equal(b.cmd, 'tx-open');
  if (b.cmd === 'tx-open') {
    assert.equal(b.name, 'feature-x');
    assert.equal(b.explicit, true);
  }
});

test('parseArgs recognizes cliq tx status with optional txId', () => {
  const a = parseArgs(['node', 'src/index.ts', 'tx', 'status']);
  assert.equal(a.cmd, 'tx-status');
  const b = parseArgs(['node', 'src/index.ts', 'tx', 'status', 'tx_abc']);
  assert.equal(b.cmd, 'tx-status');
  if (b.cmd === 'tx-status') {
    assert.equal(b.txId, 'tx_abc');
  }
});

test('parseArgs recognizes cliq tx list', () => {
  const a = parseArgs(['node', 'src/index.ts', 'tx', 'list']);
  assert.equal(a.cmd, 'tx-list');
});

test('parseArgs recognizes cliq tx review inspection commands', () => {
  const diff = parseArgs(['node', 'src/index.ts', 'tx', 'diff', 'tx_example']);
  assert.equal(diff.cmd, 'tx-diff');
  if (diff.cmd === 'tx-diff') {
    assert.equal(diff.txId, 'tx_example');
  }

  const show = parseArgs(['node', 'src/index.ts', 'tx', 'show', 'tx_example', '--json']);
  assert.equal(show.cmd, 'tx-show');
  if (show.cmd === 'tx-show') {
    assert.equal(show.txId, 'tx_example');
    assert.equal(show.json, true);
  }

  const validators = parseArgs([
    'node',
    'src/index.ts',
    'tx',
    'validators',
    'tx_example',
    '--json'
  ]);
  assert.equal(validators.cmd, 'tx-validators');
  if (validators.cmd === 'tx-validators') {
    assert.equal(validators.txId, 'tx_example');
    assert.equal(validators.json, true);
  }

  const activeDiff = parseArgs(['node', 'src/index.ts', 'tx', 'diff']);
  assert.equal(activeDiff.cmd, 'tx-diff');
  if (activeDiff.cmd === 'tx-diff') {
    assert.equal(activeDiff.txId, undefined);
  }
});

test('parseArgs recognizes cliq tx apply with --override and --reason', () => {
  const a = parseArgs([
    'node',
    'src/index.ts',
    'tx',
    'apply',
    'tx_abc',
    '--override',
    'size-limit',
    '--override',
    'tsc',
    '--reason',
    'manual override'
  ]);
  assert.equal(a.cmd, 'tx-apply');
  if (a.cmd === 'tx-apply') {
    assert.equal(a.txId, 'tx_abc');
    assert.deepEqual(a.overrides, ['size-limit', 'tsc']);
    assert.equal(a.reason, 'manual override');
  }
});

test('parseArgs rejects cliq tx apply without txId', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'tx', 'apply']), /requires <txId>/);
});

test('parseArgs cliq tx apply still accepts existing args (smart-pipeline lives in handler)', () => {
  const a = parseArgs(['node', 'src/index.ts', 'tx', 'apply', 'tx_abc', '--override', 'foo', '--reason', 'r']);
  assert.equal(a.cmd, 'tx-apply');
  if (a.cmd === 'tx-apply') {
    assert.equal(a.txId, 'tx_abc');
    assert.deepEqual(a.overrides, ['foo']);
    assert.equal(a.reason, 'r');
  }
});

test('parseArgs cliq tx apply accepts --allow-validator-error', () => {
  const a = parseArgs(['node', 'src/index.ts', 'tx', 'apply', 'tx_x', '--allow-validator-error', 'eslint', '--allow-validator-error', 'tsc']);
  assert.equal(a.cmd, 'tx-apply');
  if (a.cmd === 'tx-apply') {
    assert.deepEqual(a.allowValidatorError, ['eslint', 'tsc']);
  }
});

test('parseArgs recognizes cliq tx validate <txId>', () => {
  const a = parseArgs(['node', 'src/index.ts', 'tx', 'validate', 'tx_abc']);
  assert.equal(a.cmd, 'tx-validate');
  if (a.cmd === 'tx-validate') {
    assert.equal(a.txId, 'tx_abc');
  }
});

test('parseArgs rejects cliq tx validate without txId', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'tx', 'validate']), /requires <txId>/);
});

test('parseArgs cliq tx validate accepts --json and --headless', () => {
  const a = parseArgs(['node', 'src/index.ts', 'tx', 'validate', 'tx_x', '--json']);
  assert.equal(a.cmd, 'tx-validate');
  if (a.cmd === 'tx-validate') {
    assert.equal(a.json, true);
  }
  const b = parseArgs(['node', 'src/index.ts', 'tx', 'validate', 'tx_x', '--headless']);
  assert.equal(b.cmd, 'tx-validate');
  if (b.cmd === 'tx-validate') {
    assert.equal(b.headless, true);
  }
});

test('parseArgs recognizes cliq tx approve <txId> with overrides and reason', () => {
  const a = parseArgs(['node', 'src/index.ts', 'tx', 'approve', 'tx_abc', '--override', 'tsc', '--override', 'eslint', '--reason', 'manual review']);
  assert.equal(a.cmd, 'tx-approve');
  if (a.cmd === 'tx-approve') {
    assert.equal(a.txId, 'tx_abc');
    assert.deepEqual(a.overrides, ['tsc', 'eslint']);
    assert.equal(a.reason, 'manual review');
  }
});

test('parseArgs cliq tx approve --override-all', () => {
  const a = parseArgs(['node', 'src/index.ts', 'tx', 'approve', 'tx_abc', '--override-all', '--reason', 'mass']);
  assert.equal(a.cmd, 'tx-approve');
  if (a.cmd === 'tx-approve') {
    assert.equal(a.overrideAll, true);
  }
});

test('parseArgs cliq tx approve --allow-validator-error', () => {
  const a = parseArgs(['node', 'src/index.ts', 'tx', 'approve', 'tx_abc', '--allow-validator-error', 'eslint']);
  assert.equal(a.cmd, 'tx-approve');
  if (a.cmd === 'tx-approve') {
    assert.deepEqual(a.allowValidatorError, ['eslint']);
  }
});

test('parseArgs rejects cliq tx approve without txId', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'tx', 'approve']), /requires <txId>/);
});

test('parseArgs rejects --reason without an actual value when followed by another flag', () => {
  // Regression: consumeOption used to greedily eat the next token, so this
  // would mis-parse with reason="--override" and surface a misleading
  // "Unknown tx apply argument" further down the pipeline.
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', 'tx', 'apply', 'tx_abc', '--reason', '--override', 'size-limit']),
    /--reason requires a value/
  );
});

test('parseArgs recognizes cliq tx abort with --restore-confirmed', () => {
  const a = parseArgs([
    'node',
    'src/index.ts',
    'tx',
    'abort',
    'tx_abc',
    '--restore-confirmed',
    '--reason',
    'partial cleanup'
  ]);
  assert.equal(a.cmd, 'tx-abort');
  if (a.cmd === 'tx-abort') {
    assert.equal(a.txId, 'tx_abc');
    assert.equal(a.restoreConfirmed, true);
    assert.equal(a.keepPartial, undefined);
    assert.equal(a.reason, 'partial cleanup');
  }
});

test('parseArgs rejects cliq tx abort with both --restore-confirmed and --keep-partial', () => {
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', 'tx', 'abort', 'tx_abc', '--restore-confirmed', '--keep-partial']),
    /mutually exclusive/
  );
});

test('parseArgs accepts top-level --tx and --tx-apply flags', () => {
  // The v0.8 runner integration wires these flags into the runner; they
  // override workspace config transactions.mode / transactions.applyPolicy.
  const a = parseArgs(['node', 'src/index.ts', '--tx', 'edit', '--tx-apply', 'auto-on-pass', 'tx', 'list']);
  assert.equal(a.cmd, 'tx-list');
  if (a.cmd === 'tx-list') {
    assert.equal(a.txMode, 'edit');
    assert.equal(a.txApply, 'auto-on-pass');
  }
});

test('parseArgs --tx rejects invalid values', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--tx', 'bogus', 'tx', 'list']), /tx mode/i);
});

test('parseArgs unknown tx subcommand throws', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'tx', 'frobnicate']), /unknown tx subcommand/);
});

test('parseArgs accepts transaction help spellings', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'tx', 'help']), {
    cmd: 'help',
    topic: 'tx',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'tx', '--help']), {
    cmd: 'help',
    topic: 'tx',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'help', 'tx']), {
    cmd: 'help',
    topic: 'tx',
    policy: 'default',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'tx', 'apply', 'tx_abc', '--help']), {
    cmd: 'help',
    topic: 'tx',
    policy: 'default',
    skills: [],
    model: {}
  });
});

test('parseArgs rejects old workflow asset command spellings with migration hints', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'checkpoints']), /cliq checkpoint list/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'compactions']), /cliq compact list/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'fork', 'chk_1']), /cliq checkpoint fork/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'restore', 'chk_1']), /cliq checkpoint restore/i);
});

test('parseArgs accepts model provider flags', () => {
  assert.deepEqual(
    parseArgs([
      'node',
      'src/index.ts',
      '--provider',
      'ollama',
      '--model=qwen3:14b',
      '--base-url',
      'http://localhost:11434',
      '--streaming',
      'off',
      'chat'
    ]),
    {
      cmd: 'chat',
      prompt: '',
      policy: 'default',
      skills: [],
      model: {
        provider: 'ollama',
        model: 'qwen3:14b',
        baseUrl: 'http://localhost:11434',
        streaming: 'off'
      }
    }
  );
});

test('parseArgs rejects missing model flag values', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--provider']), /Missing value for --provider/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--model']), /Missing value for --model/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--base-url']), /Missing value for --base-url/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--streaming']), /Missing value for --streaming/i);
});

test('parseArgs rejects invalid provider and streaming values', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--provider', 'bad']), /Unknown model provider/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--streaming', 'bad']), /Unknown streaming mode/i);
});

test('printHelp documents aliases, policy modes, skills, and streaming', () => {
  const previousLog = console.log;
  let output = '';
  console.log = (value?: unknown) => {
    output += String(value);
  };

  try {
    printHelp();
  } finally {
    console.log = previousLog;
  }

  assert.match(output, /cliq run "prompt"/);
  assert.match(output, /cliq run --jsonl "prompt"/);
  assert.match(output, /Compatibility shortcuts/i);
  assert.match(output, /cliq "prompt"/);
  assert.match(output, /cliq ask "prompt"/);
  assert.doesNotMatch(output, /cliq "task"/);
  assert.doesNotMatch(output, /cliq run "task"/);
  assert.doesNotMatch(output, /cliq ask "task"/);
  assert.match(output, /cliq rpc\s+Start stdio JSON-RPC mode/);
  assert.match(output, /cliq checkpoint create/);
  assert.match(output, /cliq checkpoint list/);
  assert.match(output, /cliq compact create/);
  assert.match(output, /cliq compact list/);
  assert.match(output, /cliq handoff create/);
  assert.match(output, /cliq providers status/);
  assert.match(output, /checkpoint, compact, handoff, providers, or tx/);
  assert.match(output, /cliq tx help/);
  assert.match(output, /cliq tx diff \[<txId>\]/);
  assert.match(output, /cliq tx show \[<txId>\] \[--json\]/);
  assert.match(output, /cliq tx validators \[<txId>\]/);
  assert.doesNotMatch(output, /cliq checkpoint \[name\]/);
  assert.doesNotMatch(output, /cliq checkpoints/);
  assert.doesNotMatch(output, /cliq compactions/);
  assert.match(output, /-h, --help/);
  assert.match(output, /-v, --version/);
  assert.match(output, /--policy MODE/);
  assert.match(output, /default/);
  assert.match(output, /accept-edits/);
  assert.match(output, /plan/);
  assert.match(output, /yolo/);
  assert.doesNotMatch(output, /confirm-write/);
  assert.doesNotMatch(output, /read-only/);
  assert.doesNotMatch(output, /confirm-bash/);
  assert.doesNotMatch(output, /confirm-all/);
  // #62-B permission surface — all four new flags must appear in help so
  // operators can discover them without reading the README.
  assert.match(output, /--preset MODE/);
  assert.match(output, /mutually exclusive with --policy/i);
  assert.match(output, /--allow "<rule>"/);
  assert.match(output, /--deny\s+"<rule>"/);
  assert.match(output, /--ask\s+"<rule>"/);
  assert.match(output, /fs-read \| fs-write \| bash \| mcp \| network/);
  assert.match(output, /--skill NAME/);
  assert.match(output, /repeat/i);
  assert.match(output, /--streaming MODE/);
  assert.match(output, /--jsonl/);
  assert.match(output, /--tui-debug/);
  assert.match(output, /CLIQ_TUI_DEBUG/);
  assert.match(
    output,
    /cliq rpc\s+Reads newline-delimited JSON-RPC 2\.0 requests from stdin and writes protocol messages to stdout/
  );
  assert.match(output, /auto \| on \| off/);
  assert.match(output, /openai-compatible/);
  assert.match(output, /--base-url URL/);
});

test('runCli prints topic help for workflow asset command groups', async () => {
  const previousLog = console.log;
  let output = '';
  console.log = (value?: unknown) => {
    output += String(value);
  };

  try {
    await runCli(['node', 'src/index.ts', 'checkpoint', 'help']);
  } finally {
    console.log = previousLog;
  }

  assert.match(output, /cliq checkpoint create/);
  assert.match(output, /cliq checkpoint list/);
  assert.match(output, /cliq checkpoint restore/);
  assert.match(output, /cliq checkpoint fork/);
});

test('formatToolResultLine surfaces policy denial context when no path exists', () => {
  const result: ToolResult = {
    tool: 'edit',
    status: 'error',
    content: 'TOOL_RESULT edit ERROR\npolicy=default\nconfirmation denied',
    meta: {
      policy: 'default',
      reason: 'confirmation denied'
    }
  };

  assert.equal(formatToolResultLine(result), '[edit error] policy=default confirmation denied');
});

test('formatToolResultLine surfaces tool error reason alongside path', () => {
  const result: ToolResult = {
    tool: 'read',
    status: 'error',
    content: 'TOOL_RESULT read ERROR\npath=/etc/passwd\npath must stay inside the workspace and be workspace-relative',
    meta: {
      path: '/etc/passwd',
      error: 'path must stay inside the workspace and be workspace-relative'
    }
  };

  assert.equal(
    formatToolResultLine(result),
    '[read error] /etc/passwd - path must stay inside the workspace and be workspace-relative'
  );
});

test('formatTxRuntimeEventLine renders human-readable tx lifecycle lines', () => {
  const base = {
    schemaVersion: HEADLESS_SCHEMA_VERSION,
    eventId: 'evt_1',
    runId: 'run_1',
    timestamp: '2026-05-11T00:00:00.000Z'
  } as const;

  assert.equal(
    formatTxRuntimeEventLine({
      ...base,
      type: 'tx-staging-start',
      payload: { txId: 'tx_123', txKind: 'edit', trigger: 'auto-turn' }
    }),
    '[tx tx_123] staging started'
  );
  assert.equal(
    formatTxRuntimeEventLine({
      ...base,
      type: 'tx-finalized',
      payload: {
        txId: 'tx_123',
        txKind: 'edit',
        diffSummary: {
          filesChanged: 2,
          additions: 10,
          deletions: 3,
          creates: [],
          modifies: ['a.ts', 'b.ts'],
          deletes: []
        }
      }
    }),
    '[tx tx_123] finalized: 2 files changed (net +10/-3)'
  );
  assert.equal(
    formatTxRuntimeEventLine({
      ...base,
      type: 'tx-validated',
      payload: {
        txId: 'tx_123',
        txKind: 'edit',
        validators: {
          blocking: { pass: 2, fail: 0 },
          advisory: { pass: 1, fail: 1, names: ['size-limit'] }
        },
        blockingFailures: []
      }
    }),
    '[tx tx_123] validated: blocking 2 pass / 0 fail, advisory 1 pass / 1 fail'
  );
  assert.equal(
    formatTxRuntimeEventLine({
      ...base,
      type: 'tx-applied',
      payload: {
        txId: 'tx_123',
        txKind: 'edit',
        diffSummary: {
          filesChanged: 2,
          additions: 10,
          deletions: 3,
          creates: [],
          modifies: ['a.ts', 'b.ts'],
          deletes: []
        },
        validators: {
          blocking: { pass: 2, fail: 0 },
          advisory: { pass: 1, fail: 1, names: ['size-limit'] }
        },
        overrides: [],
        artifactRef: 'tx/tx_123/'
      }
    }),
    '[tx tx_123] applied: 2 files changed'
  );
  assert.equal(
    formatTxRuntimeEventLine({
      ...base,
      type: 'tx-aborted',
      payload: {
        txId: 'tx_123',
        txKind: 'edit',
        reason: 'validator-fail',
        artifactRef: 'tx/tx_123/'
      }
    }),
    '[tx tx_123] aborted: validator-fail'
  );
  assert.equal(
    formatTxRuntimeEventLine({
      ...base,
      type: 'model-progress',
      payload: { chunks: 1, chars: 2 }
    }),
    null
  );
});

test('resolveTxIdForReview uses provided tx id, then active tx id', () => {
  assert.equal(
    resolveTxIdForReview({
      providedTxId: 'tx_provided',
      sessionActiveTxId: 'tx_active',
      command: 'tx diff'
    }),
    'tx_provided'
  );
  assert.equal(
    resolveTxIdForReview({
      providedTxId: undefined,
      sessionActiveTxId: 'tx_active',
      command: 'tx diff'
    }),
    'tx_active'
  );
  assert.throws(
    () =>
      resolveTxIdForReview({
        providedTxId: undefined,
        sessionActiveTxId: undefined,
        command: 'tx diff'
      }),
    /tx diff requires <txId> because there is no active transaction/
  );
});

test('runCli marks already-rendered runtime errors as reported', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-cli-test-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousTrust = process.env.CLIQ_TRUST_WORKSPACE;
  let stdout = '';
  let stderr = '';
  const stdoutWrite = process.stdout.write;
  const stderrWrite = process.stderr.write;
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    throw new Error('fetch failed');
  });

  process.chdir(cwd);
  process.stdout.write = ((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  }) as typeof process.stderr.write;

  try {
    process.env.CLIQ_HOME = home;
    process.env.CLIQ_TRUST_WORKSPACE = 'trust';
    await assert.rejects(
      () =>
        runCli([
          'node',
          'src/index.ts',
          '--provider',
          'openai-compatible',
          '--model',
          'fake',
          '--base-url',
          'http://127.0.0.1:59999/v1',
          '--streaming',
          'off',
          'final-only'
        ]),
      isReportedCliError
    );
  } finally {
    process.stdout.write = stdoutWrite;
    process.stderr.write = stderrWrite;
    if (previousTrust === undefined) {
      delete process.env.CLIQ_TRUST_WORKSPACE;
    } else {
      process.env.CLIQ_TRUST_WORKSPACE = previousTrust;
    }
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    fetchMock.mock.restore();
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }

  assert.match(stdout, /\[model openai-compatible\/fake\]/);
  assert.equal((stderr.match(/\[model error\] fetch failed/g) ?? []).length, 1);
});

test('runCli run --jsonl writes only JSONL events to stdout for model errors', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-jsonl-cwd-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-jsonl-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousTrust = process.env.CLIQ_TRUST_WORKSPACE;
  const previousStdoutWrite = process.stdout.write;
  const previousStderrWrite = process.stderr.write;
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    throw new Error('fetch failed');
  });
  const chunks: string[] = [];
  const stderrChunks: string[] = [];

  process.chdir(cwd);
  process.env.CLIQ_HOME = home;
  process.env.CLIQ_TRUST_WORKSPACE = 'trust';
  process.stdout.write = ((chunk: string | Uint8Array) => {
    chunks.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    stderrChunks.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;

  try {
    await assert.rejects(
      () =>
        runCli([
          'node',
          'src/index.ts',
          '--provider',
          'openai-compatible',
          '--model',
          'fake',
          '--base-url',
          'http://127.0.0.1:59999/v1',
          '--streaming',
          'off',
          'run',
          '--jsonl',
          'hello'
        ]),
      isReportedCliError
    );
  } finally {
    process.stdout.write = previousStdoutWrite;
    process.stderr.write = previousStderrWrite;
    fetchMock.mock.restore();
    if (previousTrust === undefined) {
      delete process.env.CLIQ_TRUST_WORKSPACE;
    } else {
      process.env.CLIQ_TRUST_WORKSPACE = previousTrust;
    }
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }

  const lines = chunks.join('').trim().split('\n').filter(Boolean);
  assert.equal(lines.length >= 2, true);
  for (const line of lines) {
    assert.doesNotThrow(() => JSON.parse(line));
  }
  assert.equal(lines.some((line) => JSON.parse(line).type === 'run-start'), true);
  assert.equal(lines.some((line) => JSON.parse(line).type === 'error'), true);
  assert.equal(JSON.parse(lines.at(-1)!).type, 'run-end');
  assert.equal(stderrChunks.join('').trim(), '');
});

test('runCli --classic prints provider-first setup guidance for missing model config', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-classic-setup-cwd-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-classic-setup-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousTrust = process.env.CLIQ_TRUST_WORKSPACE;
  const previousProvider = process.env.CLIQ_MODEL_PROVIDER;
  const previousModel = process.env.CLIQ_MODEL;
  const previousBaseUrl = process.env.CLIQ_MODEL_BASE_URL;
  const previousStreaming = process.env.CLIQ_MODEL_STREAMING;
  const previousStdoutWrite = process.stdout.write;
  const previousStderrWrite = process.stderr.write;
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({ models: [] }));
  let stdout = '';
  let stderr = '';

  process.chdir(cwd);
  process.env.CLIQ_HOME = home;
  process.env.CLIQ_TRUST_WORKSPACE = 'trust';
  delete process.env.CLIQ_MODEL_PROVIDER;
  delete process.env.CLIQ_MODEL;
  delete process.env.CLIQ_MODEL_BASE_URL;
  delete process.env.CLIQ_MODEL_STREAMING;
  process.stdout.write = ((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  }) as typeof process.stderr.write;

  try {
    await assert.rejects(() => runCli(['node', 'src/index.ts', '--classic']), isReportedCliError);
  } finally {
    process.stdout.write = previousStdoutWrite;
    process.stderr.write = previousStderrWrite;
    if (previousTrust === undefined) delete process.env.CLIQ_TRUST_WORKSPACE;
    else process.env.CLIQ_TRUST_WORKSPACE = previousTrust;
    if (previousHome === undefined) delete process.env.CLIQ_HOME;
    else process.env.CLIQ_HOME = previousHome;
    if (previousProvider === undefined) delete process.env.CLIQ_MODEL_PROVIDER;
    else process.env.CLIQ_MODEL_PROVIDER = previousProvider;
    if (previousModel === undefined) delete process.env.CLIQ_MODEL;
    else process.env.CLIQ_MODEL = previousModel;
    if (previousBaseUrl === undefined) delete process.env.CLIQ_MODEL_BASE_URL;
    else process.env.CLIQ_MODEL_BASE_URL = previousBaseUrl;
    if (previousStreaming === undefined) delete process.env.CLIQ_MODEL_STREAMING;
    else process.env.CLIQ_MODEL_STREAMING = previousStreaming;
    process.chdir(previousCwd);
    fetchMock.mock.restore();
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }

  assert.equal(stdout, '');
  assert.match(stderr, /Cliq needs a model provider before chat can start/i);
  assert.match(stderr, /Provider configuration/i);
  assert.match(stderr, /Model selection/i);
  assert.match(stderr, /ollama pull qwen3\.5:4b/);
  assert.doesNotMatch(stderr, /No model provider or local Ollama model configured/);
});

test('renderUnhandledError suppresses workspace trust sentinel errors', () => {
  assert.equal(renderUnhandledError(new WorkspaceTrustError('workspace trust declined', 0)), null);
});

test('cliExitCode reads WorkspaceTrustError exit codes', () => {
  assert.equal(cliExitCode(new WorkspaceTrustError('trust env invalid', 2)), 2);
});

test('renderUnhandledError suppresses errors already reported by runtime events', () => {
  assert.equal(renderUnhandledError(new Error('plain failure')), 'plain failure');
  assert.equal(renderUnhandledError(new ReportedCliError(new Error('reported failure'))), null);
});

test('ReportedCliError preserves headless exit details for the CLI entrypoint', () => {
  const error = new ReportedCliError('cancelled', { exitCode: 130, status: 'cancelled' });

  assert.equal(error.exitCode, 130);
  assert.equal(error.status, 'cancelled');
  assert.equal(cliExitCode(error), 130);
  assert.equal(cliExitCode(new Error('plain failure')), 1);
});

type CliTestEnv = {
  cwd: string;
  home: string;
  output: string[];
  stderr: string[];
  outputText: () => string;
  stderrText: () => string;
};

async function withCliTestEnv(prefix: string, callback: (env: CliTestEnv) => Promise<void>) {
  const cwd = await mkdtemp(path.join(tmpdir(), `cliq-cli-${prefix}-`));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousLog = console.log;
  const previousStdoutWrite = process.stdout.write;
  const previousStderrWrite = process.stderr.write;
  const output: string[] = [];
  const stderr: string[] = [];

  process.chdir(cwd);
  console.log = (value?: unknown) => {
    output.push(String(value));
  };
  process.stdout.write = ((chunk: string | Uint8Array) => {
    output.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    stderr.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;

  try {
    process.env.CLIQ_HOME = home;
    await callback({
      cwd,
      home,
      output,
      stderr,
      outputText: () => (output.length > 0 ? `${output.join('\n')}\n` : ''),
      stderrText: () => stderr.join('')
    });
  } finally {
    console.log = previousLog;
    process.stdout.write = previousStdoutWrite;
    process.stderr.write = previousStderrWrite;
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
}

async function withMockStdin(input: string, callback: () => Promise<void>) {
  const previousStdin = Object.getOwnPropertyDescriptor(process, 'stdin');
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: Readable.from([input])
  });
  try {
    await callback();
  } finally {
    if (previousStdin) {
      Object.defineProperty(process, 'stdin', previousStdin);
    }
  }
}

function fakeModelClientForConfig(
  configs: ResolvedModelConfig[],
  config: ResolvedModelConfig
): ModelClient {
  configs.push(config);
  return {
    async complete() {
      return {
        provider: config.provider,
        model: config.model,
        content: 'ok'
      };
    }
  };
}

function emptyWorkspaceConfig(): WorkspaceConfig {
  return {
    instructionFiles: [],
    extensions: [],
    defaultSkills: [],
    autoCompact: {}
  };
}

test('applyTuiModelSetupSelection persists provider defaults and resolves a new OpenAI-compatible client', async () => {
  await withCliTestEnv('tui-model-setup-persist', async (env) => {
    const createdConfigs: ResolvedModelConfig[] = [];
    const result = await applyTuiModelSetupSelection({
      request: {
        provider: 'openai-compatible',
        model: 'direct-model-id',
        baseUrl: 'http://localhost:4000/v1',
        apiKey: 'sk-secret',
        persist: true
      },
      currentModelConfig: {
        provider: 'ollama',
        model: 'qwen3.5:4b',
        baseUrl: 'http://localhost:11434',
        streaming: 'off'
      },
      workspaceConfig: emptyWorkspaceConfig(),
      cliModel: { provider: 'ollama', model: 'qwen3.5:4b' },
      auth: { version: 1, providers: {} },
      cliqHome: env.home,
      createModelClientImpl: (config) => fakeModelClientForConfig(createdConfigs, config)
    });

    assert.equal(result.auth.activeProvider, 'openai-compatible');
    assert.equal(result.auth.providers['openai-compatible']?.model, 'direct-model-id');
    assert.equal(result.auth.providers['openai-compatible']?.baseUrl, 'http://localhost:4000/v1');
    assert.equal(result.auth.providers['openai-compatible']?.apiKey, 'sk-secret');
    assert.equal(result.modelConfig.provider, 'openai-compatible');
    assert.equal(result.modelConfig.model, 'direct-model-id');
    assert.equal(result.modelConfig.baseUrl, 'http://localhost:4000/v1');
    assert.equal(result.modelConfig.apiKey, 'sk-secret');
    assert.equal(result.modelConfig.streaming, 'off');
    assert.equal(createdConfigs.length, 1);
    assert.deepEqual(createdConfigs[0], result.modelConfig);

    const raw = await readFile(authFilePath(env.home), 'utf8');
    const payload = JSON.parse(raw) as {
      activeProvider?: string;
      providers?: { 'openai-compatible'?: { apiKey?: string; model?: string; baseUrl?: string } };
    };
    assert.equal(payload.activeProvider, 'openai-compatible');
    assert.equal(payload.providers?.['openai-compatible']?.model, 'direct-model-id');
    assert.equal(payload.providers?.['openai-compatible']?.baseUrl, 'http://localhost:4000/v1');
    assert.equal(payload.providers?.['openai-compatible']?.apiKey, 'sk-secret');
  });
});

test('applyTuiModelSetupSelection applies Enter session-only without writing startup defaults', async () => {
  await withCliTestEnv('tui-model-setup-session-only', async (env) => {
    const createdConfigs: ResolvedModelConfig[] = [];
    const result = await applyTuiModelSetupSelection({
      request: {
        provider: 'ollama',
        model: 'qwen-session:4b',
        persist: false
      },
      currentModelConfig: {
        provider: 'ollama',
        model: 'qwen3.5:4b',
        baseUrl: 'http://localhost:11434',
        streaming: 'auto'
      },
      workspaceConfig: emptyWorkspaceConfig(),
      cliModel: {},
      auth: { version: 1, providers: {} },
      cliqHome: env.home,
      createModelClientImpl: (config) => fakeModelClientForConfig(createdConfigs, config)
    });

    assert.equal(result.auth.activeProvider, undefined);
    assert.deepEqual(result.auth.providers, { ollama: { model: 'qwen-session:4b', transient: true } });
    assert.equal(result.modelConfig.provider, 'ollama');
    assert.equal(result.modelConfig.model, 'qwen-session:4b');
    assert.equal(result.modelConfig.baseUrl, 'http://localhost:11434');
    assert.equal(result.modelConfig.streaming, 'auto');
    assert.equal(createdConfigs.length, 1);

    await assert.rejects(() => readFile(authFilePath(env.home), 'utf8'), /ENOENT/);
  });
});

test('applyTuiModelSetupSelection can use a session-only API key without writing auth.json', async () => {
  await withCliTestEnv('tui-model-setup-session-key', async (env) => {
    const createdConfigs: ResolvedModelConfig[] = [];
    const result = await applyTuiModelSetupSelection({
      request: {
        provider: 'openai',
        model: 'gpt-5.2',
        apiKey: 'sk-session-only',
        persist: false
      },
      currentModelConfig: {
        provider: 'ollama',
        model: 'qwen3.5:4b',
        baseUrl: 'http://localhost:11434',
        streaming: 'auto'
      },
      workspaceConfig: emptyWorkspaceConfig(),
      cliModel: {},
      auth: { version: 1, providers: {} },
      cliqHome: env.home,
      createModelClientImpl: (config) => fakeModelClientForConfig(createdConfigs, config)
    });

    assert.equal(result.modelConfig.provider, 'openai');
    assert.equal(result.modelConfig.model, 'gpt-5.2');
    assert.equal(result.modelConfig.apiKey, 'sk-session-only');
    assert.equal(result.auth.providers.openai?.apiKey, 'sk-session-only');
    assert.equal(createdConfigs.length, 1);
    await assert.rejects(() => readFile(authFilePath(env.home), 'utf8'), /ENOENT/);
  });
});

test('applyTuiModelSetupSelection keeps session-only provider model and base URL in auth overlay', async () => {
  await withCliTestEnv('tui-model-setup-session-compatible-overlay', async (env) => {
    const createdConfigs: ResolvedModelConfig[] = [];
    const result = await applyTuiModelSetupSelection({
      request: {
        provider: 'openai-compatible',
        model: 'session-compatible-model',
        baseUrl: 'http://localhost:4000/v1',
        apiKey: 'sk-session-only',
        persist: false
      },
      currentModelConfig: {
        provider: 'ollama',
        model: 'qwen3.5:4b',
        baseUrl: 'http://localhost:11434',
        streaming: 'auto'
      },
      workspaceConfig: emptyWorkspaceConfig(),
      cliModel: {},
      auth: { version: 1, providers: {} },
      cliqHome: env.home,
      createModelClientImpl: (config) => fakeModelClientForConfig(createdConfigs, config)
    });

    assert.equal(result.modelConfig.provider, 'openai-compatible');
    assert.equal(result.modelConfig.model, 'session-compatible-model');
    assert.equal(result.modelConfig.baseUrl, 'http://localhost:4000/v1');
    assert.equal(result.modelConfig.apiKey, 'sk-session-only');
    assert.equal(result.auth.providers['openai-compatible']?.model, 'session-compatible-model');
    assert.equal(result.auth.providers['openai-compatible']?.baseUrl, 'http://localhost:4000/v1');
    assert.equal(result.auth.providers['openai-compatible']?.apiKey, 'sk-session-only');
    assert.equal(createdConfigs.length, 1);
    await assert.rejects(() => readFile(authFilePath(env.home), 'utf8'), /ENOENT/);
  });
});

test('applyTuiModelSetupSelection preserves session-only API keys when saving startup defaults', async () => {
  await withCliTestEnv('tui-model-setup-preserve-session-key', async (env) => {
    const createdConfigs: ResolvedModelConfig[] = [];
    const result = await applyTuiModelSetupSelection({
      request: {
        provider: 'ollama',
        model: 'qwen-save:4b',
        baseUrl: 'http://localhost:11434',
        persist: true
      },
      currentModelConfig: {
        provider: 'openai',
        model: 'gpt-5.2',
        baseUrl: 'https://api.openai.com/v1',
        apiKey: 'sk-session-only',
        streaming: 'auto'
      },
      workspaceConfig: emptyWorkspaceConfig(),
      cliModel: {},
      auth: {
        version: 1,
        providers: {
          openai: { apiKey: 'sk-session-only', transient: true }
        }
      },
      cliqHome: env.home,
      createModelClientImpl: (config) => fakeModelClientForConfig(createdConfigs, config)
    });

    assert.equal(result.auth.activeProvider, 'ollama');
    assert.equal(result.auth.providers.ollama?.model, 'qwen-save:4b');
    assert.equal(result.auth.providers.openai?.apiKey, 'sk-session-only');
    assert.equal(result.modelConfig.provider, 'ollama');
    assert.equal(result.modelConfig.model, 'qwen-save:4b');
    assert.equal(createdConfigs.length, 1);

    const raw = await readFile(authFilePath(env.home), 'utf8');
    const payload = JSON.parse(raw) as {
      providers?: { openai?: { apiKey?: string }; ollama?: { model?: string } };
    };
    assert.equal(payload.providers?.ollama?.model, 'qwen-save:4b');
    assert.equal(payload.providers?.openai?.apiKey, undefined);
  });
});

test('applyTuiModelSetupSelection persists same-provider fallback base URL with startup defaults', async () => {
  await withCliTestEnv('tui-model-setup-persist-fallback-base-url', async (env) => {
    const createdConfigs: ResolvedModelConfig[] = [];
    const result = await applyTuiModelSetupSelection({
      request: {
        provider: 'openai-compatible',
        model: 'saved-compatible-model',
        persist: true
      },
      currentModelConfig: {
        provider: 'openai-compatible',
        model: 'current-compatible-model',
        baseUrl: 'http://localhost:4000/v1',
        apiKey: 'sk-session-only',
        streaming: 'auto'
      },
      workspaceConfig: emptyWorkspaceConfig(),
      cliModel: {},
      auth: {
        version: 1,
        providers: {
          'openai-compatible': { apiKey: 'sk-session-only' }
        }
      },
      cliqHome: env.home,
      createModelClientImpl: (config) => fakeModelClientForConfig(createdConfigs, config)
    });

    assert.equal(result.modelConfig.provider, 'openai-compatible');
    assert.equal(result.modelConfig.model, 'saved-compatible-model');
    assert.equal(result.modelConfig.baseUrl, 'http://localhost:4000/v1');
    assert.equal(result.auth.providers['openai-compatible']?.baseUrl, 'http://localhost:4000/v1');
    assert.equal(createdConfigs.length, 1);

    const raw = await readFile(authFilePath(env.home), 'utf8');
    const payload = JSON.parse(raw) as {
      providers?: { 'openai-compatible'?: { model?: string; baseUrl?: string; apiKey?: string } };
    };
    assert.equal(payload.providers?.['openai-compatible']?.model, 'saved-compatible-model');
    assert.equal(payload.providers?.['openai-compatible']?.baseUrl, 'http://localhost:4000/v1');
    assert.equal(payload.providers?.['openai-compatible']?.apiKey, undefined);
  });
});

test('applyTuiModelSetupSelection persists workspace base URL for non-current compatible defaults', async () => {
  await withCliTestEnv('tui-model-setup-persist-workspace-compatible-base-url', async (env) => {
    const createdConfigs: ResolvedModelConfig[] = [];
    const result = await applyTuiModelSetupSelection({
      request: {
        provider: 'openai-compatible',
        model: 'workspace-compatible-model',
        persist: true
      },
      currentModelConfig: {
        provider: 'ollama',
        model: 'qwen3.5:4b',
        baseUrl: 'http://localhost:11434',
        streaming: 'auto'
      },
      workspaceConfig: {
        ...emptyWorkspaceConfig(),
        model: {
          provider: 'openai-compatible',
          baseUrl: 'http://localhost:4000/v1'
        }
      },
      cliModel: {},
      auth: { version: 1, providers: {} },
      cliqHome: env.home,
      env: {},
      createModelClientImpl: (config) => fakeModelClientForConfig(createdConfigs, config)
    });

    assert.equal(result.modelConfig.provider, 'openai-compatible');
    assert.equal(result.modelConfig.model, 'workspace-compatible-model');
    assert.equal(result.modelConfig.baseUrl, 'http://localhost:4000/v1');
    assert.equal(result.auth.providers['openai-compatible']?.baseUrl, 'http://localhost:4000/v1');
    assert.equal(createdConfigs.length, 1);

    const raw = await readFile(authFilePath(env.home), 'utf8');
    const payload = JSON.parse(raw) as {
      providers?: { 'openai-compatible'?: { model?: string; baseUrl?: string } };
    };
    assert.equal(payload.providers?.['openai-compatible']?.model, 'workspace-compatible-model');
    assert.equal(payload.providers?.['openai-compatible']?.baseUrl, 'http://localhost:4000/v1');
  });
});

test('applyTuiModelSetupSelection persists env base URL for non-current compatible defaults', async () => {
  await withCliTestEnv('tui-model-setup-persist-env-compatible-base-url', async (env) => {
    const createdConfigs: ResolvedModelConfig[] = [];
    const result = await applyTuiModelSetupSelection({
      request: {
        provider: 'openai-compatible',
        model: 'env-compatible-model',
        persist: true
      },
      currentModelConfig: {
        provider: 'ollama',
        model: 'qwen3.5:4b',
        baseUrl: 'http://localhost:11434',
        streaming: 'auto'
      },
      workspaceConfig: emptyWorkspaceConfig(),
      cliModel: {},
      auth: { version: 1, providers: {} },
      cliqHome: env.home,
      env: {
        CLIQ_MODEL_PROVIDER: 'openai-compatible',
        CLIQ_MODEL_BASE_URL: 'http://localhost:5000/v1'
      },
      createModelClientImpl: (config) => fakeModelClientForConfig(createdConfigs, config)
    });

    assert.equal(result.modelConfig.provider, 'openai-compatible');
    assert.equal(result.modelConfig.model, 'env-compatible-model');
    assert.equal(result.modelConfig.baseUrl, 'http://localhost:5000/v1');
    assert.equal(result.auth.providers['openai-compatible']?.baseUrl, 'http://localhost:5000/v1');
    assert.equal(createdConfigs.length, 1);

    const raw = await readFile(authFilePath(env.home), 'utf8');
    const payload = JSON.parse(raw) as {
      providers?: { 'openai-compatible'?: { model?: string; baseUrl?: string } };
    };
    assert.equal(payload.providers?.['openai-compatible']?.model, 'env-compatible-model');
    assert.equal(payload.providers?.['openai-compatible']?.baseUrl, 'http://localhost:5000/v1');
  });
});

test('applyTuiModelSetupSelection can save a same-provider model default with a session-only API key', async () => {
  await withCliTestEnv('tui-model-setup-save-same-provider-session-key', async (env) => {
    const createdConfigs: ResolvedModelConfig[] = [];
    const result = await applyTuiModelSetupSelection({
      request: {
        provider: 'openai',
        model: 'gpt-5.2',
        persist: true
      },
      currentModelConfig: {
        provider: 'openai',
        model: 'gpt-5.1',
        baseUrl: 'https://api.openai.com/v1',
        apiKey: 'sk-session-only',
        streaming: 'auto'
      },
      workspaceConfig: emptyWorkspaceConfig(),
      cliModel: {},
      auth: {
        version: 1,
        providers: {
          openai: { apiKey: 'sk-session-only', transient: true }
        }
      },
      cliqHome: env.home,
      createModelClientImpl: (config) => fakeModelClientForConfig(createdConfigs, config)
    });

    assert.equal(result.modelConfig.provider, 'openai');
    assert.equal(result.modelConfig.model, 'gpt-5.2');
    assert.equal(result.modelConfig.apiKey, 'sk-session-only');
    assert.equal(result.auth.activeProvider, 'openai');
    assert.equal(result.auth.providers.openai?.model, 'gpt-5.2');
    assert.equal(result.auth.providers.openai?.apiKey, 'sk-session-only');
    assert.equal(result.auth.providers.openai?.transient, undefined);
    assert.equal((result.auth.providers.openai as { transientApiKey?: boolean } | undefined)?.transientApiKey, true);
    assert.equal(createdConfigs.length, 1);

    const raw = await readFile(authFilePath(env.home), 'utf8');
    const payload = JSON.parse(raw) as {
      providers?: { openai?: { apiKey?: string; model?: string } };
    };
    assert.equal(payload.providers?.openai?.model, 'gpt-5.2');
    assert.equal(payload.providers?.openai?.apiKey, undefined);
  });
});

test('buildTuiModelSetupSnapshot includes discovered local Ollama models for the picker', async () => {
  const snapshot = await buildTuiModelSetupSnapshot({
    currentModelConfig: {
      provider: 'ollama',
      model: 'qwen-local:4b',
      baseUrl: 'http://localhost:11434',
      streaming: 'auto'
    },
    workspaceConfig: emptyWorkspaceConfig(),
    cliModel: {},
    auth: { version: 1, providers: {} },
    env: {},
    discoverOllamaModels: async (baseUrl) => {
      assert.equal(baseUrl, 'http://localhost:11434');
      return [{ name: 'qwen-local:4b' }, { name: 'other-local:latest' }];
    }
  });

  assert.equal(snapshot.selectedProvider, 'ollama');
  const rows = snapshot.modelsByProvider.ollama ?? [];
  const qwen = rows.find((row) => row.kind === 'model' && row.model === 'qwen-local:4b');
  const other = rows.find((row) => row.kind === 'model' && row.model === 'other-local:latest');
  assert.ok(qwen);
  assert.ok(qwen.labels.includes('Current'));
  assert.ok(qwen.labels.includes('Local'));
  assert.ok(other);
  assert.ok(other.labels.includes('Local'));
});

test('discoverTuiModelSetupModels maps OpenAI-compatible provider models into picker rows', async () => {
  const rows = await discoverTuiModelSetupModels({
    provider: 'openai-compatible',
    baseUrl: 'http://localhost:4000/v1',
    apiKey: 'sk-local',
    discoverOpenAICompatibleModels: async (baseUrl, apiKey) => {
      assert.equal(baseUrl, 'http://localhost:4000/v1');
      assert.equal(apiKey, 'sk-local');
      return [{ id: 'local-coder:latest' }, { id: 'qwen3.5:4b' }];
    }
  });

  assert.deepEqual(rows, [
    {
      kind: 'model',
      provider: 'openai-compatible',
      model: 'local-coder:latest',
      displayName: 'local-coder:latest',
      labels: ['Provider API']
    },
    {
      kind: 'model',
      provider: 'openai-compatible',
      model: 'qwen3.5:4b',
      displayName: 'qwen3.5:4b',
      labels: ['Provider API']
    }
  ]);
});

test('discoverTuiModelSetupModels uses configured OpenAI-compatible API keys when draft omits one', async () => {
  const apiKeys: Array<string | undefined> = [];
  const discoverOpenAICompatibleModels = async (_baseUrl: string, apiKey?: string) => {
    apiKeys.push(apiKey);
    return [{ id: 'local-coder:latest' }];
  };

  await discoverTuiModelSetupModels({
    provider: 'openai-compatible',
    baseUrl: 'http://localhost:4000/v1',
    auth: {
      version: 1,
      providers: {
        'openai-compatible': { apiKey: 'sk-auth' }
      }
    },
    env: {
      CLIQ_MODEL_API_KEY: 'sk-env',
      OPENAI_COMPATIBLE_API_KEY: 'sk-compatible-env'
    },
    discoverOpenAICompatibleModels
  });
  await discoverTuiModelSetupModels({
    provider: 'openai-compatible',
    baseUrl: 'http://localhost:4000/v1',
    auth: {
      version: 1,
      providers: {
        'openai-compatible': { apiKey: 'sk-auth' }
      }
    },
    env: {},
    discoverOpenAICompatibleModels
  });

  assert.deepEqual(apiKeys, ['sk-env', 'sk-auth']);
});

test('discoverTuiModelSetupModels returns no rows for non-compatible providers or missing base URLs', async () => {
  assert.deepEqual(
    await discoverTuiModelSetupModels({
      provider: 'openai',
      baseUrl: 'http://localhost:4000/v1',
      discoverOpenAICompatibleModels: async () => {
        throw new Error('discovery should not run');
      }
    }),
    []
  );
  assert.deepEqual(
    await discoverTuiModelSetupModels({
      provider: 'openai-compatible',
      discoverOpenAICompatibleModels: async () => {
        throw new Error('discovery should not run');
      }
    }),
    []
  );
});

test('discoverTuiModelSetupModels prefers OPENAI_COMPATIBLE_API_KEY when CLIQ_MODEL_API_KEY is unset', async () => {
  const apiKeys: Array<string | undefined> = [];
  await discoverTuiModelSetupModels({
    provider: 'openai-compatible',
    baseUrl: 'http://localhost:4000/v1',
    env: {
      OPENAI_COMPATIBLE_API_KEY: 'sk-compatible-env'
    },
    discoverOpenAICompatibleModels: async (_baseUrl, apiKey) => {
      apiKeys.push(apiKey);
      return [];
    }
  });

  assert.deepEqual(apiKeys, ['sk-compatible-env']);
});

test('model setup error config preserves configured streaming mode', () => {
  const config = modelConfigForSetupError(
    new ModelSetupRequiredError({
      reason: 'missing-provider-api-key',
      provider: 'openai'
    }),
    {
      workspaceConfig: {
        ...emptyWorkspaceConfig(),
        model: {
          provider: 'openai',
          streaming: 'off'
        }
      },
      cliModel: {},
      env: {}
    }
  );

  assert.equal(config.streaming, 'off');
});

test('interactive model setup can repair startup model config and continue', async () => {
  const authAfterSetup = {
    version: 1,
    activeProvider: 'openai',
    providers: {
      openai: { apiKey: 'sk-secret', model: 'gpt-5.2' }
    }
  } as const;

  const result = await resolveModelConfigWithInteractiveSetup({
    workspaceConfig: emptyWorkspaceConfig(),
    cliModel: { provider: 'openai' },
    initialAuth: { version: 1, providers: {} },
    wantsTui: true,
    mountSetup: async () => authAfterSetup
  });

  assert.equal(result?.modelConfig.provider, 'openai');
  assert.equal(result?.modelConfig.model, 'gpt-5.2');
  assert.equal(result?.modelConfig.apiKey, 'sk-secret');
  assert.equal(result?.auth.providers.openai?.apiKey, 'sk-secret');
});

async function createCliTxFixture(env: CliTestEnv) {
  const session = createSession(env.cwd);
  const root = resolveTxRoot(env.home);
  const txId = 'tx_cli_review';
  const tx = await createTx(root, {
    id: txId,
    kind: 'edit',
    workspaceId: 'ws_cli',
    sessionId: session.id,
    workspaceRealPath: env.cwd
  });
  await writeDiff(root, txId, {
    files: [
      {
        path: 'a.txt',
        op: 'modify',
        oldContent: 'one\n',
        newContent: 'one\ntwo\n'
      }
    ],
    outOfBand: []
  });
  await appendBashEffect(root, txId, {
    command: 'npm test',
    exitCode: 0,
    ts: '2026-05-11T00:00:00Z',
    pathsChanged: ['package-lock.json'],
    outOfBand: true
  });
  await mkdir(validatorsDir(root, txId), { recursive: true });
  await writeFile(
    path.join(validatorsDir(root, txId), 'tsc.json'),
    JSON.stringify({
      name: 'tsc',
      severity: 'blocking',
      status: 'pass',
      durationMs: 42
    }),
    'utf8'
  );
  await writeTxState(root, {
    ...tx,
    state: 'validated',
    diffSummary: {
      filesChanged: 1,
      additions: 1,
      deletions: 0,
      creates: [],
      modifies: ['a.txt'],
      deletes: []
    },
    validators: [{ name: 'tsc', severity: 'blocking', status: 'pass', durationMs: 42 }],
    blockingFailures: []
  });
  session.activeTxId = txId;
  await saveSession(env.cwd, session);
  return txId;
}

test('runCli tx validate --json emits trust refusal as stdout JSON instead of stderr only', async () => {
  await withCliTestEnv('tx-validate-trust-json', async (env) => {
    const previousTrust = process.env.CLIQ_TRUST_WORKSPACE;
    delete process.env.CLIQ_TRUST_WORKSPACE;

    try {
      await assert.rejects(
        () => runCli(['node', 'src/index.ts', 'tx', 'validate', 'tx_any', '--json']),
        isReportedCliError
      );
    } finally {
      if (previousTrust === undefined) {
        delete process.env.CLIQ_TRUST_WORKSPACE;
      } else {
        process.env.CLIQ_TRUST_WORKSPACE = previousTrust;
      }
    }

    const payloads = env.output
      .join('')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line) as { type?: string; message?: string });

    assert.equal(payloads.length, 1);
    assert.equal(payloads[0]?.type, 'error');
    assert.ok(
      /untrusted workspace|non-interactive mode/i.exec(payloads[0]?.message ?? ''),
      'expected gate copy to mention non-interactive refuse'
    );
    assert.equal(env.stderrText().trim(), '');
  });
});

test('runCli bare chat surfaces CLIQ_TRUST_WORKSPACE=deny on stderr before exit', async () => {
  await withCliTestEnv('chat-trust-deny-stderr', async (env) => {
    const previousTrust = process.env.CLIQ_TRUST_WORKSPACE;
    process.env.CLIQ_TRUST_WORKSPACE = 'deny';

    try {
      await assert.rejects(() => runCli(['node', 'src/index.ts']), isReportedCliError);
    } finally {
      if (previousTrust === undefined) {
        delete process.env.CLIQ_TRUST_WORKSPACE;
      } else {
        process.env.CLIQ_TRUST_WORKSPACE = previousTrust;
      }
    }

    assert.match(env.stderrText(), /CLIQ_TRUST_WORKSPACE=deny/);
    assert.ok(env.stderrText().includes(env.cwd), 'message should cite the workspace path');
  });
});

test('runCli providers status --json emits safe provider status without starting chat', async () => {
  await withCliTestEnv('providers-status-json', async (env) => {
    const previousTrust = process.env.CLIQ_TRUST_WORKSPACE;
    const previousOpenAi = process.env.OPENAI_API_KEY;
    const previousModel = process.env.CLIQ_MODEL;
    const previousBaseUrl = process.env.CLIQ_MODEL_BASE_URL;
    const previousStreaming = process.env.CLIQ_MODEL_STREAMING;
    const fetchMock = mock.method(globalThis, 'fetch', async () => {
      throw new Error('Ollama unavailable in test');
    });

    try {
      process.env.CLIQ_TRUST_WORKSPACE = 'trust';
      process.env.OPENAI_API_KEY = 'sk-secret';
      delete process.env.CLIQ_MODEL;
      delete process.env.CLIQ_MODEL_BASE_URL;
      delete process.env.CLIQ_MODEL_STREAMING;
      await mkdir(path.join(env.cwd, '.cliq'), { recursive: true });
      await writeFile(
        path.join(env.cwd, '.cliq', 'config.json'),
        JSON.stringify({ model: { provider: 'openai', model: 'gpt-workspace' } }),
        'utf8'
      );

      await runCli(['node', 'src/index.ts', 'providers', 'status', '--json']);
    } finally {
      fetchMock.mock.restore();
      if (previousTrust === undefined) delete process.env.CLIQ_TRUST_WORKSPACE;
      else process.env.CLIQ_TRUST_WORKSPACE = previousTrust;
      if (previousOpenAi === undefined) delete process.env.OPENAI_API_KEY;
      else process.env.OPENAI_API_KEY = previousOpenAi;
      if (previousModel === undefined) delete process.env.CLIQ_MODEL;
      else process.env.CLIQ_MODEL = previousModel;
      if (previousBaseUrl === undefined) delete process.env.CLIQ_MODEL_BASE_URL;
      else process.env.CLIQ_MODEL_BASE_URL = previousBaseUrl;
      if (previousStreaming === undefined) delete process.env.CLIQ_MODEL_STREAMING;
      else process.env.CLIQ_MODEL_STREAMING = previousStreaming;
    }

    const payload = JSON.parse(env.outputText()) as {
      type: string;
      report: {
        activeProvider: string;
        providers: Array<{
          provider: string;
          displayName: string;
          current: boolean;
          state: string;
          sources: string[];
          issues: unknown[];
          setup: string[];
          model?: string;
          baseUrl?: string;
        }>;
        credentialPersistence: { mode: string; supportsManagedCredentials: boolean };
      };
    };
    assert.equal(payload.type, 'providers-status');
    assert.equal(payload.report.activeProvider, 'openai');
    const current = payload.report.providers[0]!;
    assert.equal(current.provider, 'openai');
    assert.equal(current.displayName, 'OpenAI');
    assert.equal(current.current, true);
    assert.equal(current.state, 'configured');
    assert.deepEqual(current.sources, ['ENV', 'Workspace']);
    assert.deepEqual(current.issues, []);
    assert.equal(current.model, 'gpt-workspace');
    assert.equal(current.baseUrl, 'https://api.openai.com/v1');
    assert.ok(current.setup.some((line) => /OPENAI_API_KEY/.test(line)));
    assert.equal(payload.report.credentialPersistence.mode, 'local-auth-file');
    assert.equal(payload.report.credentialPersistence.supportsManagedCredentials, true);
    assert.doesNotMatch(env.outputText(), /sk-secret/);
    assert.equal(env.stderrText(), '');
  });
});

test('runCli providers auth set writes local auth without echoing the API key', async () => {
  await withCliTestEnv('providers-auth-set', async (env) => {
    await withMockStdin('sk-secret\n', async () => {
      await runCli([
        'node',
        'src/index.ts',
        'providers',
        'auth',
        'set',
        'openai',
        '--api-key-stdin',
        '--model',
        'gpt-5.2'
      ]);
    });

    const raw = await readFile(path.join(env.home, 'auth.json'), 'utf8');
    const payload = JSON.parse(raw) as {
      activeProvider?: string;
      providers?: {
        openai?: {
          apiKey?: string;
          model?: string;
        };
      };
    };

    assert.equal(payload.activeProvider, 'openai');
    assert.equal(payload.providers?.openai?.apiKey, 'sk-secret');
    assert.equal(payload.providers?.openai?.model, 'gpt-5.2');
    assert.match(env.outputText(), /OpenAI credential saved/);
    assert.match(env.outputText(), /model gpt-5\.2/);
    assert.doesNotMatch(env.outputText(), /sk-secret/);
    assert.equal(env.stderrText(), '');
  });
});

test('runCli providers validate --json returns structured configuration failures', async () => {
  await withCliTestEnv('providers-validate-json', async (env) => {
    const previousTrust = process.env.CLIQ_TRUST_WORKSPACE;
    const previousOpenAi = process.env.OPENAI_API_KEY;
    const previousModel = process.env.CLIQ_MODEL;
    const previousBaseUrl = process.env.CLIQ_MODEL_BASE_URL;
    const previousStreaming = process.env.CLIQ_MODEL_STREAMING;
    const fetchMock = mock.method(globalThis, 'fetch', async () => {
      throw new Error('Ollama unavailable in test');
    });

    try {
      process.env.CLIQ_TRUST_WORKSPACE = 'trust';
      delete process.env.OPENAI_API_KEY;
      delete process.env.CLIQ_MODEL;
      delete process.env.CLIQ_MODEL_BASE_URL;
      delete process.env.CLIQ_MODEL_STREAMING;
      await mkdir(path.join(env.cwd, '.cliq'), { recursive: true });
      await writeFile(
        path.join(env.cwd, '.cliq', 'config.json'),
        JSON.stringify({ model: { provider: 'openai', model: 'gpt-workspace' } }),
        'utf8'
      );

      await assert.rejects(
        () => runCli(['node', 'src/index.ts', 'providers', 'validate', 'openai', '--json']),
        isReportedCliError
      );
    } finally {
      fetchMock.mock.restore();
      if (previousTrust === undefined) delete process.env.CLIQ_TRUST_WORKSPACE;
      else process.env.CLIQ_TRUST_WORKSPACE = previousTrust;
      if (previousOpenAi === undefined) delete process.env.OPENAI_API_KEY;
      else process.env.OPENAI_API_KEY = previousOpenAi;
      if (previousModel === undefined) delete process.env.CLIQ_MODEL;
      else process.env.CLIQ_MODEL = previousModel;
      if (previousBaseUrl === undefined) delete process.env.CLIQ_MODEL_BASE_URL;
      else process.env.CLIQ_MODEL_BASE_URL = previousBaseUrl;
      if (previousStreaming === undefined) delete process.env.CLIQ_MODEL_STREAMING;
      else process.env.CLIQ_MODEL_STREAMING = previousStreaming;
    }

    const payload = JSON.parse(env.outputText()) as {
      type: string;
      ok: boolean;
      provider: string;
      state: string;
      issues: Array<{ code: string; envVar?: string }>;
    };
    assert.equal(payload.type, 'provider-validation');
    assert.equal(payload.ok, false);
    assert.equal(payload.provider, 'openai');
    assert.equal(payload.state, 'not-configured');
    assert.deepEqual(payload.issues.map((issue) => issue.code), ['missing-api-key']);
    assert.equal(payload.issues[0]?.envVar, 'OPENAI_API_KEY');
    assert.equal(env.stderrText(), '');
  });
});

test('runCli version flags print package version without workspace trust', async () => {
  const current = await readPackageVersionForTest();

  await withCliTestEnv('version', async (env) => {
    const previousTrust = process.env.CLIQ_TRUST_WORKSPACE;
    process.env.CLIQ_TRUST_WORKSPACE = 'deny';

    try {
      await runCli(['node', 'src/index.ts', '--version']);
      await runCli(['node', 'src/index.ts', '-v']);
    } finally {
      if (previousTrust === undefined) {
        delete process.env.CLIQ_TRUST_WORKSPACE;
      } else {
        process.env.CLIQ_TRUST_WORKSPACE = previousTrust;
      }
    }

    assert.equal(env.outputText(), `${current}\n${current}\n`);
    assert.equal(env.stderrText(), '');
  });
});

test('runCli tx review commands inspect the provided or active transaction', async () => {
  await withCliTestEnv('tx-review', async (env) => {
    const txId = await createCliTxFixture(env);

    await runCli(['node', 'src/index.ts', 'tx', 'diff']);
    assert.match(env.outputText(), /M a\.txt \(net \+1\/-0\)/);

    env.output.length = 0;
    await runCli(['node', 'src/index.ts', 'tx', 'show', txId, '--json']);
    const show = JSON.parse(env.outputText()) as {
      type: string;
      txId: string;
      artifactRef: string;
      bashEffects: unknown[];
    };
    assert.equal(show.type, 'tx-show');
    assert.equal(show.txId, txId);
    assert.equal(show.artifactRef, `tx/${txId}/`);
    assert.equal(show.bashEffects.length, 1);

    env.output.length = 0;
    await runCli(['node', 'src/index.ts', 'tx', 'validators', txId]);
    assert.match(env.outputText(), /PASS blocking tsc 42ms/);
  });
});

test('runCli reset creates a global active session without referencing workspace .cliq', async () => {
  await withCliTestEnv('reset', async ({ outputText }) => {
    await runCli(['node', 'src/index.ts', 'reset']);

    assert.match(outputText(), /reset active session/i);
    assert.doesNotMatch(outputText(), /\.cliq/);
  });
});

test('runCli history prints the active global session for the current workspace', async () => {
  await withCliTestEnv('history', async ({ outputText }) => {
    const runtimeCwd = process.cwd();
    await runCli(['node', 'src/index.ts', 'history']);

    const session = JSON.parse(outputText()) as { id: string; cwd: string; records: unknown[] };
    assert.equal(session.id.startsWith('sess_'), true);
    assert.equal(session.cwd, runtimeCwd);
    assert.deepEqual(session.records, []);
  });
});

test('runCli fork switches the active global session to a checkpoint prefix', async () => {
  await withCliTestEnv('fork', async ({ cwd, outputText }) => {
    const session = createSession(cwd);
    session.records.push(
      {
        id: 'usr_1',
        ts: '2026-04-29T00:00:00.000Z',
        kind: 'user',
        role: 'user',
        content: 'first'
      },
      {
        id: 'usr_2',
        ts: '2026-04-29T00:00:01.000Z',
        kind: 'user',
        role: 'user',
        content: 'second'
      }
    );
    session.checkpoints.push({
      id: 'chk_cli',
      kind: 'manual',
      createdAt: '2026-04-29T00:00:02.000Z',
      recordIndex: 1,
      turn: 1
    });
    await saveSession(cwd, session);

    await runCli(['node', 'src/index.ts', 'checkpoint', 'fork', 'chk_cli', 'cli branch']);
    const active = await ensureSession(cwd);

    assert.notEqual(active.id, session.id);
    assert.equal(active.parentSessionId, session.id);
    assert.equal(active.forkedFromCheckpointId, 'chk_cli');
    assert.deepEqual(active.records.map((record) => record.id), ['usr_1']);

    assert.match(outputText(), /forked session/i);
    assert.match(outputText(), /chk_cli/);
  });
});

test('runCli checkpoint create and list operate on the active global session without model setup', async () => {
  await withCliTestEnv('checkpoint', async ({ cwd, outputText, stderrText }) => {
    const session = createSession(cwd);
    session.records.push({
      id: 'usr_1',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'user',
      role: 'user',
      content: 'first'
    });
    await saveSession(cwd, session);

    await runCli(['node', 'src/index.ts', 'checkpoint', 'create', 'before edit']);
    const checkpointed = await ensureSession(cwd);
    await runCli(['node', 'src/index.ts', 'checkpoint', 'list']);

    assert.equal(checkpointed.checkpoints.length, 1);
    assert.equal(checkpointed.checkpoints[0]?.name, 'before edit');
    assert.match(outputText(), /created checkpoint/);
    assert.match(outputText(), /before edit/);
    assert.match(outputText(), /workspace snapshot unavailable: not-git/);
    assert.match(stderrText(), /workspace snapshot unavailable: not-git/);
  });
});

test('runCli compact create and list operate on stored session records', async () => {
  await withCliTestEnv('compact', async ({ cwd, outputText }) => {
    const session = createSession(cwd);
    session.records.push(
      {
        id: 'usr_1',
        ts: '2026-04-29T00:00:00.000Z',
        kind: 'user',
        role: 'user',
        content: 'first'
      },
      {
        id: 'usr_2',
        ts: '2026-04-29T00:00:01.000Z',
        kind: 'user',
        role: 'user',
        content: 'second'
      },
      {
        id: 'usr_3',
        ts: '2026-04-29T00:00:02.000Z',
        kind: 'user',
        role: 'user',
        content: 'third'
      }
    );
    await saveSession(cwd, session);

    await runCli(['node', 'src/index.ts', 'compact', 'create', '--summary', '## Objective\nKeep first two summarized']);
    const compacted = await ensureSession(cwd);
    await runCli(['node', 'src/index.ts', 'compact', 'list']);

    assert.equal(compacted.compactions.length, 1);
    assert.equal(compacted.compactions[0]?.status, 'active');
    assert.equal(compacted.compactions[0]?.firstKeptRecordId, 'usr_3');
    assert.match(outputText(), /created compaction/);
    assert.match(outputText(), /Keep first two summarized/);
  });
});

test('runCli compact create fails clearly when there is no compactable tail', async () => {
  await withCliTestEnv('compact-short', async ({ cwd }) => {
    const session = createSession(cwd);
    session.records.push({
      id: 'usr_1',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'user',
      role: 'user',
      content: 'single'
    });
    await saveSession(cwd, session);

    await assert.rejects(
      () => runCli(['node', 'src/index.ts', 'compact', 'create', '--summary', 'single summary']),
      /compact requires at least two session records/i
    );
  });
});

test('runCli compact create fails clearly when --before leaves no compactable range', async () => {
  await withCliTestEnv('compact-before-start', async ({ cwd }) => {
    const session = createSession(cwd);
    session.records.push(
      {
        id: 'usr_1',
        ts: '2026-04-29T00:00:00.000Z',
        kind: 'user',
        role: 'user',
        content: 'first'
      },
      {
        id: 'usr_2',
        ts: '2026-04-29T00:00:01.000Z',
        kind: 'user',
        role: 'user',
        content: 'second'
      }
    );
    session.checkpoints.push({
      id: 'chk_start',
      kind: 'auto',
      createdAt: '2026-04-29T00:00:00.000Z',
      recordIndex: 0,
      turn: 0
    });
    await saveSession(cwd, session);

    await assert.rejects(
      () => runCli(['node', 'src/index.ts', 'compact', 'create', '--before', 'chk_start', '--summary', 'summary']),
      /checkpoint chk_start does not leave a compactable range/i
    );
  });
});

test('runCli handoff exports an artifact and creates a handoff checkpoint when needed', async () => {
  await withCliTestEnv('handoff', async ({ cwd, outputText }) => {
    const session = createSession(cwd);
    session.records.push({
      id: 'usr_1',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'user',
      role: 'user',
      content: 'prepare handoff'
    });
    await saveSession(cwd, session);

    await runCli(['node', 'src/index.ts', 'handoff', 'create']);
    const handedOff = await ensureSession(cwd);

    assert.equal(handedOff.checkpoints.at(-1)?.kind, 'handoff');
    assert.match(outputText(), /created handoff/);
    assert.match(outputText(), /HANDOFF\.md/);
  });
});

test('runCli restore --scope session switches the active session to a checkpoint prefix', async () => {
  await withCliTestEnv('restore-session', async ({ cwd, outputText }) => {
    const session = createSession(cwd);
    session.records.push(
      {
        id: 'usr_1',
        ts: '2026-04-29T00:00:00.000Z',
        kind: 'user',
        role: 'user',
        content: 'keep'
      },
      {
        id: 'usr_2',
        ts: '2026-04-29T00:00:01.000Z',
        kind: 'user',
        role: 'user',
        content: 'discard'
      }
    );
    session.checkpoints.push({
      id: 'chk_restore',
      kind: 'manual',
      createdAt: '2026-04-29T00:00:02.000Z',
      recordIndex: 1,
      turn: 1
    });
    await saveSession(cwd, session);

    await runCli(['node', 'src/index.ts', 'checkpoint', 'restore', 'chk_restore', '--scope', 'session']);
    const restored = await ensureSession(cwd);

    assert.notEqual(restored.id, session.id);
    assert.equal(restored.forkedFromCheckpointId, 'chk_restore');
    assert.deepEqual(restored.records.map((record) => record.id), ['usr_1']);

    assert.match(outputText(), /restored session/i);
    assert.match(outputText(), /chk_restore/);
  });
});

test('runCli restore --scope files requires --yes before changing files', async () => {
  await withCliTestEnv('restore-files', async ({ cwd }) => {
    const session = createSession(cwd);
    session.checkpoints.push({
      id: 'chk_files',
      kind: 'manual',
      createdAt: '2026-04-29T00:00:00.000Z',
      recordIndex: 0,
      turn: 0,
      workspaceCheckpointId: 'wchk_missing'
    });
    await saveSession(cwd, session);

    await assert.rejects(
      () => runCli(['node', 'src/index.ts', 'checkpoint', 'restore', 'chk_files', '--scope', 'files']),
      /requires --yes/i
    );
  });
});

test('runCli restore --scope files does not let --yes overwrite staged changes', async () => {
  await withCliTestEnv('restore-staged', async ({ cwd }) => {
    await execFileAsync('git', ['init'], { cwd });
    await execFileAsync('git', ['config', 'user.name', 'Cliq Test'], { cwd });
    await execFileAsync('git', ['config', 'user.email', 'test@cliq.local'], { cwd });
    await writeFile(path.join(cwd, 'tracked.txt'), 'before\n', 'utf8');
    await execFileAsync('git', ['add', 'tracked.txt'], { cwd });
    await execFileAsync('git', ['commit', '-m', 'initial'], { cwd });

    const session = createSession(cwd);
    const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual' });
    await writeFile(path.join(cwd, 'tracked.txt'), 'after\n', 'utf8');
    await execFileAsync('git', ['add', 'tracked.txt'], { cwd });

    await assert.rejects(
      () => runCli(['node', 'src/index.ts', 'checkpoint', 'restore', checkpoint.id, '--scope', 'files', '--yes']),
      /staged changes/i
    );
  });
});

test('runCli restore --scope files creates a restore-safety checkpoint before changing files', async () => {
  await withCliTestEnv('restore-files-safety', async ({ cwd }) => {
    await execFileAsync('git', ['init'], { cwd });
    await execFileAsync('git', ['config', 'user.name', 'Cliq Test'], { cwd });
    await execFileAsync('git', ['config', 'user.email', 'test@cliq.local'], { cwd });
    await writeFile(path.join(cwd, 'tracked.txt'), 'before\n', 'utf8');
    await execFileAsync('git', ['add', 'tracked.txt'], { cwd });
    await execFileAsync('git', ['commit', '-m', 'initial'], { cwd });

    const session = createSession(cwd);
    const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual' });
    await writeFile(path.join(cwd, 'tracked.txt'), 'after\n', 'utf8');

    await runCli(['node', 'src/index.ts', 'checkpoint', 'restore', checkpoint.id, '--scope', 'files', '--yes']);
    const active = await ensureSession(cwd);

    assert.equal(await readFile(path.join(cwd, 'tracked.txt'), 'utf8'), 'before\n');
    assert.deepEqual(
      active.checkpoints.map((candidate) => candidate.kind),
      ['manual', 'restore-safety']
    );
  });
});

test('runCli restore --scope both validates workspace restore before creating a safety checkpoint', async () => {
  await withCliTestEnv('restore-both-non-git', async ({ cwd }) => {
    const session = createSession(cwd);
    session.records.push({
      id: 'usr_1',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'user',
      role: 'user',
      content: 'before restore'
    });
    const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual' });

    await assert.rejects(
      () => runCli(['node', 'src/index.ts', 'checkpoint', 'restore', checkpoint.id, '--scope', 'both', '--yes']),
      /workspace checkpoint cannot be restored: not-git/i
    );

    const after = await ensureSession(cwd);
    assert.deepEqual(
      after.checkpoints.map((candidate) => candidate.id),
      [checkpoint.id]
    );
  });
});

test('runCli checkpoint fork --restore-files requires --yes before changing files', async () => {
  await withCliTestEnv('fork-files', async ({ cwd }) => {
    const session = createSession(cwd);
    session.checkpoints.push({
      id: 'chk_files',
      kind: 'manual',
      createdAt: '2026-04-29T00:00:00.000Z',
      recordIndex: 0,
      turn: 0,
      workspaceCheckpointId: 'wchk_missing'
    });
    await saveSession(cwd, session);

    await assert.rejects(
      () => runCli(['node', 'src/index.ts', 'checkpoint', 'fork', 'chk_files', '--restore-files']),
      /requires --yes/i
    );
  });
});

test('runCli checkpoint fork --restore-files creates a restore-safety checkpoint before changing files', async () => {
  await withCliTestEnv('fork-files-safety', async ({ cwd }) => {
    await execFileAsync('git', ['init'], { cwd });
    await execFileAsync('git', ['config', 'user.name', 'Cliq Test'], { cwd });
    await execFileAsync('git', ['config', 'user.email', 'test@cliq.local'], { cwd });
    await writeFile(path.join(cwd, 'tracked.txt'), 'before\n', 'utf8');
    await execFileAsync('git', ['add', 'tracked.txt'], { cwd });
    await execFileAsync('git', ['commit', '-m', 'initial'], { cwd });

    const session = createSession(cwd);
    session.records.push({
      id: 'usr_1',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'user',
      role: 'user',
      content: 'before fork'
    });
    const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual' });
    await writeFile(path.join(cwd, 'tracked.txt'), 'after\n', 'utf8');

    await runCli(['node', 'src/index.ts', 'checkpoint', 'fork', checkpoint.id, '--restore-files', '--yes', 'child']);
    const parent = JSON.parse(await readFile(sessionFilePath(session), 'utf8')) as {
      checkpoints: Array<{ kind: string }>;
    };
    const child = await ensureSession(cwd);

    assert.equal(await readFile(path.join(cwd, 'tracked.txt'), 'utf8'), 'before\n');
    assert.equal(child.parentSessionId, session.id);
    assert.deepEqual(
      parent.checkpoints.map((candidate) => candidate.kind),
      ['manual', 'restore-safety']
    );
  });
});

test('parseArgs marks policy as explicit when --policy is set', () => {
  const explicit = parseArgs(['node', 'index.js', '--policy', 'yolo']);
  assert.equal(explicit.policy, 'yolo');
  assert.equal(explicit.policyExplicit, true);

  const equals = parseArgs(['node', 'index.js', '--policy=plan']);
  assert.equal(equals.policy, 'plan');
  assert.equal(equals.policyExplicit, true);

  const implicit = parseArgs(['node', 'index.js']);
  assert.equal(implicit.policy, 'default'); // global default
  assert.notEqual(implicit.policyExplicit, true);
});

test('resolveTuiInitialPolicy uses the canonical default unless explicit', () => {
  // No --policy -> canonical default.
  assert.equal(
    resolveTuiInitialPolicy({ policy: 'default', policyExplicit: false }),
    'default'
  );
  // Explicit --policy yolo wins.
  assert.equal(
    resolveTuiInitialPolicy({ policy: 'yolo', policyExplicit: true }),
    'yolo'
  );
  // Explicit --policy plan also passes through.
  assert.equal(
    resolveTuiInitialPolicy({ policy: 'plan', policyExplicit: true }),
    'plan'
  );
});

test('resolveTuiPreference precedence: --classic > --tui > CLIQ_TUI=0 > TTY default', () => {
  // Default on a TTY: TUI on.
  assert.equal(
    resolveTuiPreference({ classic: false, tui: false, envOptOut: false, isTTY: true }),
    true
  );
  // Default off a TTY: legacy readline.
  assert.equal(
    resolveTuiPreference({ classic: false, tui: false, envOptOut: false, isTTY: false }),
    false
  );
  // CLIQ_TUI=0 overrides the TTY default.
  assert.equal(
    resolveTuiPreference({ classic: false, tui: false, envOptOut: true, isTTY: true }),
    false
  );
  // --tui overrides CLIQ_TUI=0 (explicit CLI flag wins over env).
  assert.equal(
    resolveTuiPreference({ classic: false, tui: true, envOptOut: true, isTTY: true }),
    true
  );
  // --classic wins over --tui (most conservative explicit choice).
  assert.equal(
    resolveTuiPreference({ classic: true, tui: true, envOptOut: false, isTTY: true }),
    false
  );
  // --classic wins on non-TTY too (redundant but consistent).
  assert.equal(
    resolveTuiPreference({ classic: true, tui: false, envOptOut: false, isTTY: false }),
    false
  );
});

test('resolveTuiDebug enables debug notices from CLI flag or env', () => {
  assert.equal(resolveTuiDebug({ tuiDebug: false, envDebug: false }), false);
  assert.equal(resolveTuiDebug({ tuiDebug: true, envDebug: false }), true);
  assert.equal(resolveTuiDebug({ tuiDebug: false, envDebug: true }), true);
});

test('hydratePendingPlanReview restores finalized active plans for TUI restart', async () => {
  const previousHome = process.env.CLIQ_HOME;
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-tui-plan-ws-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-tui-plan-home-'));
  process.env.CLIQ_HOME = home;
  try {
    const session = createSession(cwd);
    const draft = await createDraftPlan(cwd, session, {
      title: 'Restart plan',
      contentMarkdown: '## Steps\n- Resume review'
    });
    await finalizePlan(cwd, session, { planId: draft.id });

    const actions: UiAction[] = [];
    await hydratePendingPlanReview(captureDispatchStore(actions), cwd, session);

    assert.equal(actions.length, 1);
    assert.equal(actions[0]?.type, 'runtime-event');
    if (actions[0]?.type === 'runtime-event') {
        assert.equal(actions[0].event.type, 'plan-finalized');
      if (actions[0].event.type === 'plan-finalized') {
        assert.equal(actions[0].event.plan.id, draft.id);
        assert.equal(actions[0].event.plan.contentMarkdown, '## Steps\n- Resume review');
        assert.deepEqual(actions[0].event.plan.items, [{ id: 'item_1', title: 'Resume review', status: 'pending' }]);
        assert.match(actions[0].event.plan.markdownPath, /plan\.md$/);
      }
    }
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('hydratePlanProgress restores approved plan execution tracker for TUI restart', async () => {
  const previousHome = process.env.CLIQ_HOME;
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-tui-progress-ws-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-tui-progress-home-'));
  process.env.CLIQ_HOME = home;
  try {
    const session = createSession(cwd);
    const draft = await createDraftPlan(cwd, session, {
      title: 'Restart progress',
      contentMarkdown: '## Steps\n- Resume work'
    });
    await finalizePlan(cwd, session, { planId: draft.id });
    await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });

    const actions: UiAction[] = [];
    await hydratePlanProgress(captureDispatchStore(actions), cwd, session);

    assert.equal(actions.length, 1);
    assert.equal(actions[0]?.type, 'runtime-event');
    if (actions[0]?.type === 'runtime-event') {
      assert.equal(actions[0].event.type, 'plan-progress-updated');
      if (actions[0].event.type === 'plan-progress-updated') {
        assert.equal(actions[0].event.progress.planId, draft.id);
        assert.equal(actions[0].event.progress.title, 'Restart progress');
        assert.deepEqual(actions[0].event.progress.items, [
          { id: 'item_1', title: 'Resume work', status: 'pending', activeForm: 'Working on Resume work' }
        ]);
      }
    }
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('hydratePlanProgressBestEffort does not fail plan approval when TUI hydration fails', async () => {
  const previousHome = process.env.CLIQ_HOME;
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-tui-progress-best-effort-ws-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-tui-progress-best-effort-home-'));
  process.env.CLIQ_HOME = home;
  try {
    const session = createSession(cwd);
    const draft = await createDraftPlan(cwd, session, {
      title: 'Best effort progress',
      contentMarkdown: '## Steps\n- Resume work'
    });
    await finalizePlan(cwd, session, { planId: draft.id });
    await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });
    const warnings: string[] = [];

    await assert.doesNotReject(() =>
      hydratePlanProgressBestEffort(
        {
          ...captureDispatchStore([]),
          dispatch() {
            throw new Error('dispatch failed');
          }
        },
        cwd,
        session,
        draft.id,
        (message) => warnings.push(message)
      )
    );
    assert.equal(warnings.length, 1);
    assert.match(warnings[0] ?? '', /plan progress hydration failed/i);
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('hydratePlanProgressBestEffort seeds and dispatches historical approved plans missing progress', async () => {
  const previousHome = process.env.CLIQ_HOME;
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-tui-progress-missing-ws-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-tui-progress-missing-home-'));
  process.env.CLIQ_HOME = home;
  try {
    const session = createSession(cwd);
    const draft = await createDraftPlan(cwd, session, {
      title: 'Historical progress',
      contentMarkdown: '## Steps\n- Resume legacy work'
    });
    await finalizePlan(cwd, session, { planId: draft.id });
    await approvePlan(cwd, session, { planId: draft.id, targetMode: 'default' });
    await rm(await planProgressPath(cwd, session, draft.id), { force: true });

    const actions: UiAction[] = [];
    await hydratePlanProgressBestEffort(captureDispatchStore(actions), cwd, session, draft.id);

    assert.equal(actions.length, 1);
    assert.equal(actions[0]?.type, 'runtime-event');
    if (actions[0]?.type === 'runtime-event') {
      assert.equal(actions[0].event.type, 'plan-progress-updated');
      if (actions[0].event.type === 'plan-progress-updated') {
        assert.equal(actions[0].event.progress.planId, draft.id);
        assert.deepEqual(actions[0].event.progress.items, [
          { id: 'item_1', title: 'Resume legacy work', status: 'pending', activeForm: 'Working on Resume legacy work' }
        ]);
      }
    }
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

function captureDispatchStore(actions: UiAction[]): UiStore {
  return {
    getState() {
      throw new Error('getState is not used by notifyIfPackageUpdateAvailable');
    },
    subscribe() {
      throw new Error('subscribe is not used by notifyIfPackageUpdateAvailable');
    },
    dispatch(action) {
      actions.push(action);
    }
  };
}

async function readPackageVersionForTest(): Promise<string> {
  const raw = await readFile(new URL('../package.json', import.meta.url), 'utf8');
  const parsed = JSON.parse(raw) as { version?: unknown };
  if (typeof parsed.version !== 'string') {
    throw new Error('package.json version must be a string');
  }
  return parsed.version;
}

function nextPatchVersion(version: string): string {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  assert.ok(match, `expected semver package version, got ${version}`);
  return `${match[1]}.${match[2]}.${Number(match[3]) + 1}`;
}

test('notifyIfPackageUpdateAvailable dispatches when npm has a newer version', async () => {
  const actions: UiAction[] = [];
  const current = await readPackageVersionForTest();
  const latest = nextPatchVersion(current);
  const fetchMock = mock.method(globalThis, 'fetch', async () =>
    Response.json({ version: latest })
  );

  try {
    await notifyIfPackageUpdateAvailable(captureDispatchStore(actions));
  } finally {
    fetchMock.mock.restore();
  }

  assert.deepEqual(actions, [
    { type: 'version-update', notice: { current, latest } }
  ]);
});

test('notifyIfPackageUpdateAvailable is silent when no update is available or check fails', async () => {
  const current = await readPackageVersionForTest();
  const sameVersionActions: UiAction[] = [];
  const sameVersionFetch = mock.method(globalThis, 'fetch', async () =>
    Response.json({ version: current })
  );
  try {
    await notifyIfPackageUpdateAvailable(captureDispatchStore(sameVersionActions));
  } finally {
    sameVersionFetch.mock.restore();
  }
  assert.equal(sameVersionActions.length, 0);

  const failingActions: UiAction[] = [];
  const failingFetch = mock.method(globalThis, 'fetch', async () => {
    throw new Error('offline');
  });
  try {
    await notifyIfPackageUpdateAvailable(captureDispatchStore(failingActions));
  } finally {
    failingFetch.mock.restore();
  }
  assert.equal(failingActions.length, 0);
});

test('notifyIfPackageUpdateAvailable absorbs dispatch errors', async () => {
  const latest = nextPatchVersion(await readPackageVersionForTest());
  const fetchMock = mock.method(globalThis, 'fetch', async () =>
    Response.json({ version: latest })
  );

  try {
    await assert.doesNotReject(() =>
      notifyIfPackageUpdateAvailable({
        getState() {
          throw new Error('getState is not used by notifyIfPackageUpdateAvailable');
        },
        subscribe() {
          throw new Error('subscribe is not used by notifyIfPackageUpdateAvailable');
        },
        dispatch() {
          throw new Error('dispatch failed');
        }
      })
    );
  } finally {
    fetchMock.mock.restore();
  }
});
