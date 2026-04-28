import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { mock } from 'node:test';

import {
  formatToolResultLine,
  isReportedCliError,
  parseArgs,
  printHelp,
  renderUnhandledError,
  ReportedCliError,
  runCli
} from './cli.js';
import { createSession, ensureSession, saveSession } from './session/store.js';
import type { ToolResult } from './tools/types.js';

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

test('parseArgs accepts fork checkpoint id and name', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'fork', 'chk_123', 'alternate', 'path']), {
    cmd: 'fork',
    checkpointId: 'chk_123',
    name: 'alternate path',
    policy: 'auto',
    skills: [],
    model: {}
  });
});

test('parseArgs rejects fork without a checkpoint id', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'fork']), /Missing checkpoint id for fork/i);
});

test('parseArgs accepts workflow asset commands', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoint', 'before', 'edit']), {
    cmd: 'checkpoint',
    name: 'before edit',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'checkpoints']), {
    cmd: 'checkpoints',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compact', '--before', 'chk_1', '--summary', 'summary text']), {
    cmd: 'compact',
    beforeCheckpointId: 'chk_1',
    summaryMarkdown: 'summary text',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'compactions']), {
    cmd: 'compactions',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'handoff', '--checkpoint=chk_1']), {
    cmd: 'handoff',
    checkpointId: 'chk_1',
    policy: 'auto',
    skills: [],
    model: {}
  });
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'restore', 'chk_1', '--scope', 'files', '--yes']), {
    cmd: 'restore',
    checkpointId: 'chk_1',
    scope: 'files',
    yes: true,
    policy: 'auto',
    skills: [],
    model: {}
  });
});

test('parseArgs rejects compact without an explicit summary', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'compact']), /Missing value for --summary/i);
});

test('parseArgs rejects restore without a checkpoint id or with an invalid scope', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'restore']), /Missing checkpoint id for restore/i);
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', 'restore', 'chk_1', '--scope', 'bad']),
    /Unknown restore scope/i
  );
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

test('runCli reset creates a global active session without referencing workspace .cliq', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-cli-reset-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousLog = console.log;
  let output = '';

  process.chdir(cwd);
  console.log = (value?: unknown) => {
    output += String(value);
  };

  try {
    process.env.CLIQ_HOME = home;
    await runCli(['node', 'src/index.ts', 'reset']);
  } finally {
    console.log = previousLog;
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }

  assert.match(output, /reset active session/i);
  assert.doesNotMatch(output, /\.cliq/);
});

test('runCli history prints the active global session for the current workspace', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-cli-history-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousLog = console.log;
  let output = '';

  process.chdir(cwd);
  const runtimeCwd = process.cwd();
  console.log = (value?: unknown) => {
    output += String(value);
  };

  try {
    process.env.CLIQ_HOME = home;
    await runCli(['node', 'src/index.ts', 'history']);
  } finally {
    console.log = previousLog;
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }

  const session = JSON.parse(output) as { id: string; cwd: string; records: unknown[] };
  assert.equal(session.id.startsWith('sess_'), true);
  assert.equal(session.cwd, runtimeCwd);
  assert.deepEqual(session.records, []);
});

test('runCli fork switches the active global session to a checkpoint prefix', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-cli-fork-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousLog = console.log;
  let output = '';

  process.chdir(cwd);
  console.log = (value?: unknown) => {
    output += String(value);
  };

  try {
    process.env.CLIQ_HOME = home;
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

    await runCli(['node', 'src/index.ts', 'fork', 'chk_cli', 'cli branch']);
    const active = await ensureSession(cwd);

    assert.notEqual(active.id, session.id);
    assert.equal(active.parentSessionId, session.id);
    assert.equal(active.forkedFromCheckpointId, 'chk_cli');
    assert.deepEqual(active.records.map((record) => record.id), ['usr_1']);
  } finally {
    console.log = previousLog;
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }

  assert.match(output, /forked session/i);
  assert.match(output, /chk_cli/);
});

test('runCli checkpoint and checkpoints operate on the active global session without model setup', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-cli-checkpoint-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousLog = console.log;
  let output = '';

  process.chdir(cwd);
  console.log = (value?: unknown) => {
    output += `${String(value)}\n`;
  };

  try {
    process.env.CLIQ_HOME = home;
    const session = createSession(cwd);
    session.records.push({
      id: 'usr_1',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'user',
      role: 'user',
      content: 'first'
    });
    await saveSession(cwd, session);

    await runCli(['node', 'src/index.ts', 'checkpoint', 'before edit']);
    const checkpointed = await ensureSession(cwd);
    await runCli(['node', 'src/index.ts', 'checkpoints']);

    assert.equal(checkpointed.checkpoints.length, 1);
    assert.equal(checkpointed.checkpoints[0]?.name, 'before edit');
    assert.match(output, /created checkpoint/);
    assert.match(output, /before edit/);
  } finally {
    console.log = previousLog;
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('runCli compact and compactions operate on stored session records', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-cli-compact-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousLog = console.log;
  let output = '';

  process.chdir(cwd);
  console.log = (value?: unknown) => {
    output += `${String(value)}\n`;
  };

  try {
    process.env.CLIQ_HOME = home;
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

    await runCli(['node', 'src/index.ts', 'compact', '--summary', '## Objective\nKeep first two summarized']);
    const compacted = await ensureSession(cwd);
    await runCli(['node', 'src/index.ts', 'compactions']);

    assert.equal(compacted.compactions.length, 1);
    assert.equal(compacted.compactions[0]?.status, 'active');
    assert.equal(compacted.compactions[0]?.firstKeptRecordId, 'usr_3');
    assert.match(output, /created compaction/);
    assert.match(output, /Keep first two summarized/);
  } finally {
    console.log = previousLog;
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('runCli handoff exports an artifact and creates a handoff checkpoint when needed', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-cli-handoff-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousLog = console.log;
  let output = '';

  process.chdir(cwd);
  console.log = (value?: unknown) => {
    output += `${String(value)}\n`;
  };

  try {
    process.env.CLIQ_HOME = home;
    const session = createSession(cwd);
    session.records.push({
      id: 'usr_1',
      ts: '2026-04-29T00:00:00.000Z',
      kind: 'user',
      role: 'user',
      content: 'prepare handoff'
    });
    await saveSession(cwd, session);

    await runCli(['node', 'src/index.ts', 'handoff']);
    const handedOff = await ensureSession(cwd);

    assert.equal(handedOff.checkpoints.at(-1)?.kind, 'handoff');
    assert.match(output, /created handoff/);
    assert.match(output, /HANDOFF\.md/);
  } finally {
    console.log = previousLog;
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('runCli restore --scope session switches the active session to a checkpoint prefix', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-cli-restore-session-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousLog = console.log;
  let output = '';

  process.chdir(cwd);
  console.log = (value?: unknown) => {
    output += `${String(value)}\n`;
  };

  try {
    process.env.CLIQ_HOME = home;
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

    await runCli(['node', 'src/index.ts', 'restore', 'chk_restore', '--scope', 'session']);
    const restored = await ensureSession(cwd);

    assert.notEqual(restored.id, session.id);
    assert.equal(restored.forkedFromCheckpointId, 'chk_restore');
    assert.deepEqual(restored.records.map((record) => record.id), ['usr_1']);
  } finally {
    console.log = previousLog;
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }

  assert.match(output, /restored session/i);
  assert.match(output, /chk_restore/);
});

test('runCli restore --scope files requires --yes before changing files', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-cli-restore-files-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;

  process.chdir(cwd);

  try {
    process.env.CLIQ_HOME = home;
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
      () => runCli(['node', 'src/index.ts', 'restore', 'chk_files', '--scope', 'files']),
      /requires --yes/i
    );
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});
