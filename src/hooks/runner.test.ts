import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  MAX_HOOK_STDERR_BYTES,
  MAX_HOOK_STDIN_BYTES,
  MAX_HOOK_STDOUT_BYTES,
  parseMatcher,
  runHookCommand,
  selectHookCommands
} from './runner.js';
import type { HookInput, HooksConfig } from './types.js';

function baseInput(overrides: Partial<HookInput> = {}): HookInput {
  return {
    schemaVersion: 1,
    hookEventName: 'PreToolUse',
    sessionId: 'sess_1',
    cwd: '/tmp/workspace',
    toolName: 'bash',
    ...overrides
  };
}

function commandFor(scriptPath: string): string {
  return `${JSON.stringify(process.execPath)} ${JSON.stringify(scriptPath)}`;
}

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-hooks-runner-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('runHookCommand sends JSON input to stdin and parses JSON stdout', async () => {
  await withTempDir(async (dir) => {
    const script = path.join(dir, 'echo.js');
    await writeFile(
      script,
      `let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const parsed = JSON.parse(input);
  process.stdout.write(JSON.stringify({
    additionalContext: parsed.toolName + ':' + parsed.hookEventName
  }));
});
`,
      'utf8'
    );

    const result = await runHookCommand(
      { type: 'command', command: commandFor(script) },
      baseInput({ hookEventName: 'PreToolUse', toolName: 'bash' }),
      { cwd: dir }
    );

    assert.equal(result.status, 'ok');
    assert.deepEqual(result.output, { additionalContext: 'bash:PreToolUse' });
  });
});

test('runHookCommand denies non-object JSON stdout', async () => {
  await withTempDir(async (dir) => {
    for (const stdout of ['null', '["array"]', '"text"']) {
      const result = await runHookCommand(
        {
          type: 'command',
          command: `${JSON.stringify(process.execPath)} -e ${JSON.stringify(
            `process.stdout.write(${JSON.stringify(stdout)});`
          )}`
        },
        baseInput(),
        { cwd: dir }
      );

      assert.equal(result.status, 'denied');
      assert.deepEqual(result.decision, { behavior: 'deny', reason: 'invalid hook output: non-object JSON' });
      assert.equal(result.stdout, stdout);
      assert.equal(result.exitCode, 0);
      assert.equal(result.timedOut, false);
    }
  });
});

test('runHookCommand treats empty stdout on exit zero as continue', async () => {
  await withTempDir(async (dir) => {
    const result = await runHookCommand(
      { type: 'command', command: `${JSON.stringify(process.execPath)} -e ""` },
      baseInput(),
      { cwd: dir }
    );

    assert.equal(result.status, 'ok');
    assert.equal(result.output, null);
  });
});

test('runHookCommand treats exit code 2 as deny with stderr reason', async () => {
  await withTempDir(async (dir) => {
    const result = await runHookCommand(
      {
        type: 'command',
        command: `${JSON.stringify(process.execPath)} -e "process.stderr.write('blocked by hook'); process.exit(2)"`
      },
      baseInput(),
      { cwd: dir }
    );

    assert.equal(result.status, 'denied');
    assert.deepEqual(result.decision, { behavior: 'deny', reason: 'blocked by hook' });
  });
});

test('runHookCommand treats other non-zero exits as infrastructure errors', async () => {
  await withTempDir(async (dir) => {
    const result = await runHookCommand(
      {
        type: 'command',
        command: `${JSON.stringify(process.execPath)} -e "process.stderr.write('boom'); process.exit(9)"`
      },
      baseInput(),
      { cwd: dir }
    );

    assert.equal(result.status, 'error');
    assert.equal(result.exitCode, 9);
    assert.match(result.error, /hook command exited with code 9/i);
    assert.match(result.stderr, /boom/);
  });
});

test('runHookCommand times out commands and reports infrastructure error', async () => {
  await withTempDir(async (dir) => {
    const result = await runHookCommand(
      {
        type: 'command',
        command: `${JSON.stringify(process.execPath)} -e "setTimeout(() => {}, 1000)"`,
        timeoutMs: 25
      },
      baseInput(),
      { cwd: dir }
    );

    assert.equal(result.status, 'error');
    assert.equal(result.timedOut, true);
    assert.match(result.error, /timed out/i);
  });
});

test('runHookCommand caps stdout and stderr with visible truncation markers', async () => {
  await withTempDir(async (dir) => {
    const script = path.join(dir, 'large-output.js');
    await writeFile(
      script,
      `const stdoutDone = new Promise((resolve) => {
  process.stdout.write('o'.repeat(${MAX_HOOK_STDOUT_BYTES + 10}), resolve);
});
const stderrDone = new Promise((resolve) => {
  process.stderr.write('e'.repeat(${MAX_HOOK_STDERR_BYTES + 10}), resolve);
});
Promise.all([stdoutDone, stderrDone]).then(() => process.exit(1));
`,
      'utf8'
    );

    const result = await runHookCommand(
      {
        type: 'command',
        command: commandFor(script)
      },
      baseInput(),
      { cwd: dir }
    );

    assert.equal(result.status, 'error');
    assert.equal(Buffer.byteLength(result.stdout, 'utf8') <= MAX_HOOK_STDOUT_BYTES, true);
    assert.equal(Buffer.byteLength(result.stderr, 'utf8') <= MAX_HOOK_STDERR_BYTES, true);
    assert.match(result.stdout, /\.\.\. \(truncated\)$/);
    assert.match(result.stderr, /\.\.\. \(truncated\)$/);
  });
});

test('runHookCommand caps oversized JSON stdin and marks truncated tool result content', async () => {
  await withTempDir(async (dir) => {
    const script = path.join(dir, 'inspect-stdin.js');
    await writeFile(
      script,
      `let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const parsed = JSON.parse(input);
  process.stdout.write(JSON.stringify({
    stdinBytes: Buffer.byteLength(input, 'utf8'),
    truncated: parsed.toolResult._truncated === true,
    contentLength: parsed.toolResult.content.length
  }));
});
`,
      'utf8'
    );

    const result = await runHookCommand(
      { type: 'command', command: commandFor(script) },
      baseInput({
        hookEventName: 'PostToolUse',
        toolResult: {
          tool: 'read',
          status: 'ok',
          content: 'x'.repeat(5 * 1024 * 1024),
          meta: {}
        }
      }),
      { cwd: dir }
    );

    assert.equal(result.status, 'ok');
    assert.ok(result.output);
    assert.equal((result.output as { stdinBytes: number }).stdinBytes <= MAX_HOOK_STDIN_BYTES, true);
    assert.equal((result.output as { truncated: boolean }).truncated, true);
    assert.equal((result.output as { contentLength: number }).contentLength < 5 * 1024 * 1024, true);
  });
});

test('parseMatcher trims matcher terms and ignores empty terms', () => {
  assert.deepEqual(parseMatcher(' bash || edit | '), ['bash', 'edit']);
  assert.deepEqual(parseMatcher('bash||edit'), ['bash', 'edit']);
});

test('selectHookCommands matches tool-scoped events by toolName', () => {
  const hooks: HooksConfig = {
    PreToolUse: [
      { matcher: 'read|grep', hooks: [{ type: 'command', command: 'ignored-read' }] },
      { matcher: ' bash | edit ', hooks: [{ type: 'command', command: 'matched-bash' }] },
      { hooks: [{ type: 'command', command: 'always' }] }
    ],
    Stop: [{ matcher: 'bash', hooks: [{ type: 'command', command: 'stop-ignores-tool-matcher' }] }]
  };

  assert.deepEqual(
    selectHookCommands(hooks, baseInput({ hookEventName: 'PreToolUse', toolName: 'bash' })).map(
      (hook) => hook.command
    ),
    ['matched-bash', 'always']
  );
  assert.deepEqual(
    selectHookCommands(hooks, baseInput({ hookEventName: 'Stop', toolName: 'bash' })).map((hook) => hook.command),
    ['stop-ignores-tool-matcher']
  );
});
