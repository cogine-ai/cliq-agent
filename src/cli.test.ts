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
