import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { mock } from 'node:test';
import { promisify } from 'node:util';

import {
  cliExitCode,
  formatTxRuntimeEventLine,
  formatToolResultLine,
  isReportedCliError,
  parseArgs,
  printHelp,
  renderUnhandledError,
  resolveTuiInitialPolicy,
  resolveTuiPreference,
  resolveTxIdForReview,
  notifyIfPackageUpdateAvailable,
  ReportedCliError,
  runCli
} from './cli.js';
import { createCheckpoint } from './session/checkpoints.js';
import { createSession, ensureSession, saveSession, sessionFilePath } from './session/store.js';
import { WorkspaceTrustError } from './session/trust.js';
import type { ToolResult } from './tools/types.js';
import type { UiAction, UiStore } from './tui/store.js';
import { appendBashEffect } from './workspace/transactions/bash-effects.js';
import {
  createTx,
  resolveTxRoot,
  validatorsDir,
  writeDiff,
  writeTxState
} from './workspace/transactions/store.js';

const execFileAsync = promisify(execFile);

test('parseArgs accepts --policy=read-only', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--policy=read-only', 'chat']), {
    cmd: 'chat',
    prompt: '',
    policy: 'read-only',
    policyExplicit: true,
    skills: [],
    model: {}
  });
});

test('parseArgs accepts --policy confirm-all for one-shot prompt', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--policy', 'confirm-all', 'fix', 'tests']), {
    cmd: 'chat',
    prompt: 'fix tests',
    policy: 'confirm-all',
    policyExplicit: true,
    skills: [],
    model: {}
  });
});

test('parseArgs accepts command-scoped run --jsonl', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'run', '--jsonl', 'inspect', 'repo']), {
    cmd: 'chat',
    prompt: 'inspect repo',
    jsonl: true,
    policy: 'auto',
    skills: [],
    model: {}
  });
});

test('parseArgs keeps --jsonl in the prompt after the first prompt token', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'run', 'inspect', '--jsonl']), {
    cmd: 'chat',
    prompt: 'inspect --jsonl',
    policy: 'auto',
    skills: [],
    model: {}
  });
});

test('parseArgs accepts rpc as a no-prompt command and rejects extra args', () => {
  assert.deepEqual(parseArgs(['node', 'cliq', 'rpc']), {
    cmd: 'rpc',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.throws(() => parseArgs(['node', 'cliq', 'rpc', 'extra']), /Unknown rpc argument: extra/i);
});

test('parseArgs accepts ask as a prompt-only run alias', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'ask', '--literal', 'prompt']), {
    cmd: 'chat',
    prompt: '--literal prompt',
    policy: 'auto',
    skills: [],
    model: {}
  });
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
    cmd: 'chat',
    prompt: 'inspect --jsonl',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--jsonl', 'inspect']), {
    cmd: 'chat',
    prompt: '--jsonl inspect',
    policy: 'auto',
    skills: [],
    model: {}
  });
});

test('parseArgs rejects invalid policy values', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--policy', 'invalid', 'chat']), /Unknown policy mode/i);
});

test('parseArgs rejects missing policy values', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--policy']), /Missing value for --policy/i);
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

test('parseArgs collects repeated --skill flags', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--skill', 'reviewer', '--skill=safe-edit', 'chat']), {
    cmd: 'chat',
    prompt: '',
    policy: 'auto',
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
    () => parseArgs(['node', 'src/index.ts', '--skill', '--policy', 'read-only', 'chat']),
    /Missing value for --skill/i
  );
});

test('parseArgs keeps skills on non-chat commands for downstream assembly parity', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--skill', 'reviewer', 'history']), {
    cmd: 'history',
    policy: 'auto',
    skills: ['reviewer'],
    model: {}
  });
});

test('parseArgs accepts checkpoint fork id and name', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'fork', 'chk_123', 'alternate', 'path']), {
    cmd: 'checkpoint-fork',
    checkpointId: 'chk_123',
    name: 'alternate path',
    policy: 'auto',
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
      policy: 'auto',
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
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'list']), {
    cmd: 'checkpoint-list',
    policy: 'auto',
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
      policy: 'auto',
      skills: [],
      model: {}
    }
  );
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compact', 'create', '--before', 'chk_1', '--summary', 'summary text']), {
    cmd: 'compact-create',
    beforeCheckpointId: 'chk_1',
    summaryMarkdown: 'summary text',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compact', 'list']), {
    cmd: 'compact-list',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'handoff', 'create', '--checkpoint=chk_1']), {
    cmd: 'handoff-create',
    checkpointId: 'chk_1',
    policy: 'auto',
    skills: [],
    model: {}
  });
});

test('parseArgs accepts workflow asset help commands', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint']), {
    cmd: 'help',
    topic: 'checkpoint',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'help']), {
    cmd: 'help',
    topic: 'checkpoint',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compact', '--help']), {
    cmd: 'help',
    topic: 'compact',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'handoff', '-h']), {
    cmd: 'help',
    topic: 'handoff',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'help', 'checkpoint']), {
    cmd: 'help',
    topic: 'checkpoint',
    policy: 'auto',
    skills: [],
    model: {}
  });
});

test('parseArgs accepts leaf workflow asset help flags', () => {
  const expectedCheckpointHelp = {
    cmd: 'help',
    topic: 'checkpoint',
    policy: 'auto',
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
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compact', 'list', '-h']), {
    cmd: 'help',
    topic: 'compact',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'handoff', 'create', '--help']), {
    cmd: 'help',
    topic: 'handoff',
    policy: 'auto',
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
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'tx', '--help']), {
    cmd: 'help',
    topic: 'tx',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'help', 'tx']), {
    cmd: 'help',
    topic: 'tx',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'tx', 'apply', 'tx_abc', '--help']), {
    cmd: 'help',
    topic: 'tx',
    policy: 'auto',
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
      policy: 'auto',
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

  assert.match(output, /cliq run "task"/);
  assert.match(output, /cliq run --jsonl "task"/);
  assert.match(output, /cliq ask "task"/);
  assert.match(output, /cliq rpc\s+Start stdio JSON-RPC mode/);
  assert.match(output, /cliq checkpoint create/);
  assert.match(output, /cliq checkpoint list/);
  assert.match(output, /cliq compact create/);
  assert.match(output, /cliq compact list/);
  assert.match(output, /cliq handoff create/);
  assert.match(output, /cliq tx help/);
  assert.match(output, /cliq tx diff \[<txId>\]/);
  assert.match(output, /cliq tx show \[<txId>\] \[--json\]/);
  assert.match(output, /cliq tx validators \[<txId>\]/);
  assert.doesNotMatch(output, /cliq checkpoint \[name\]/);
  assert.doesNotMatch(output, /cliq checkpoints/);
  assert.doesNotMatch(output, /cliq compactions/);
  assert.match(output, /-h, --help/);
  assert.match(output, /--policy MODE/);
  assert.match(output, /confirm-write/);
  assert.match(output, /read-only/);
  assert.match(output, /confirm-bash/);
  assert.match(output, /confirm-all/);
  assert.match(output, /--skill NAME/);
  assert.match(output, /repeat/i);
  assert.match(output, /--streaming MODE/);
  assert.match(output, /--jsonl/);
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
    content: 'TOOL_RESULT edit ERROR\npolicy=confirm-write\nconfirmation denied',
    meta: {
      policy: 'confirm-write',
      reason: 'confirmation denied'
    }
  };

  assert.equal(formatToolResultLine(result), '[edit error] policy=confirm-write confirmation denied');
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
    schemaVersion: 1 as const,
    eventId: 'evt_1',
    runId: 'run_1',
    timestamp: '2026-05-11T00:00:00.000Z'
  };

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
  const explicit = parseArgs(['node', 'index.js', '--policy', 'auto']);
  assert.equal(explicit.policy, 'auto');
  assert.equal(explicit.policyExplicit, true);

  const equals = parseArgs(['node', 'index.js', '--policy=read-only']);
  assert.equal(equals.policy, 'read-only');
  assert.equal(equals.policyExplicit, true);

  const implicit = parseArgs(['node', 'index.js']);
  assert.equal(implicit.policy, 'auto'); // global default
  assert.notEqual(implicit.policyExplicit, true);
});

test('resolveTuiInitialPolicy overrides the global default with confirm-all unless explicit', () => {
  // No --policy → confirm-all (TUI safer default).
  assert.equal(
    resolveTuiInitialPolicy({ policy: 'auto', policyExplicit: false }),
    'confirm-all'
  );
  // Explicit --policy auto wins.
  assert.equal(
    resolveTuiInitialPolicy({ policy: 'auto', policyExplicit: true }),
    'auto'
  );
  // Explicit --policy read-only also passes through.
  assert.equal(
    resolveTuiInitialPolicy({ policy: 'read-only', policyExplicit: true }),
    'read-only'
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
