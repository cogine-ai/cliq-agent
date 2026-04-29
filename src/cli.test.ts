import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { mock } from 'node:test';
import { promisify } from 'node:util';

import {
  formatToolResultLine,
  isReportedCliError,
  parseArgs,
  printHelp,
  renderUnhandledError,
  ReportedCliError,
  runCli
} from './cli.js';
import { createCheckpoint } from './session/checkpoints.js';
import { createSession, ensureSession, saveSession } from './session/store.js';
import type { ToolResult } from './tools/types.js';

const execFileAsync = promisify(execFile);

test('parseArgs accepts --policy=read-only', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--policy=read-only', 'chat']), {
    cmd: 'chat',
    prompt: '',
    policy: 'read-only',
    skills: [],
    model: {}
  });
});

test('parseArgs accepts --policy confirm-all for one-shot prompt', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--policy', 'confirm-all', 'fix', 'tests']), {
    cmd: 'chat',
    prompt: 'fix tests',
    policy: 'confirm-all',
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
  assert.match(output, /cliq ask "task"/);
  assert.match(output, /cliq checkpoint create/);
  assert.match(output, /cliq checkpoint list/);
  assert.match(output, /cliq compact create/);
  assert.match(output, /cliq compact list/);
  assert.match(output, /cliq handoff create/);
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

test('runCli marks already-rendered runtime errors as reported', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-cli-test-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
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

test('renderUnhandledError suppresses errors already reported by runtime events', () => {
  assert.equal(renderUnhandledError(new Error('plain failure')), 'plain failure');
  assert.equal(renderUnhandledError(new ReportedCliError(new Error('reported failure'))), null);
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
  const previousStderrWrite = process.stderr.write;
  const output: string[] = [];
  const stderr: string[] = [];

  process.chdir(cwd);
  console.log = (value?: unknown) => {
    output.push(String(value));
  };
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
