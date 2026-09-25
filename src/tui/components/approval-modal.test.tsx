import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import type { ApprovalSubject } from '../../policy/types.js';
import type { UiApprovalDecision } from '../store.js';
import { ApprovalModal } from './approval-modal.js';

const flush = () => new Promise<void>((r) => setImmediate(r));

const toolSubject: Extract<ApprovalSubject, { kind: 'tool' }> = {
  kind: 'tool',
  toolName: 'bash',
  access: 'exec',
  channel: { kind: 'bash', commandHead: 'rm', unsafeForAllow: false },
  action: { bash: 'rm -rf /' },
  display: { title: 'Allow bash command?', command: 'rm -rf /' }
};

const txSubject: Extract<ApprovalSubject, { kind: 'tx-apply' }> = {
  kind: 'tx-apply',
  txId: 'tx_123',
  diffSummary: {
    filesChanged: 2,
    additions: 7,
    deletions: 3,
    creates: [],
    modifies: ['a.ts', 'b.ts'],
    deletes: []
  },
  validators: [
    { name: 'tsc', severity: 'blocking', status: 'fail', durationMs: 12 },
    { name: 'lint', severity: 'advisory', status: 'pass', durationMs: 4 }
  ],
  blockingFailures: ['tsc'],
  artifactRef: 'tx_123'
};

const mcpSubject: Extract<ApprovalSubject, { kind: 'tool' }> = {
  kind: 'tool',
  toolName: 'mcp',
  access: 'exec',
  channel: { kind: 'mcp', server: 'context7', tool: 'search' },
  action: { mcp: { server: 'context7', tool: 'search', arguments: { query: 'typescript' } } },
  display: {
    title: 'Allow MCP tool?',
    server: 'context7',
    tool: 'search',
    detail: '{"mcp":{"server":"context7","tool":"search","arguments":{"query":"typescript"}}}'
  }
};

test('renders the tool subject with command, access, and policy', () => {
  const { lastFrame } = render(
    <ApprovalModal subject={toolSubject} policy="accept-edits" onDecide={() => {}} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /! Approval required/);
  assert.match(frame, /! Risk: command execution/);
  assert.match(frame, /Allow bash command\?/);
  assert.match(frame, /tool: bash/);
  assert.match(frame, /command: rm -rf \//);
  assert.match(frame, /policy: accept-edits/);
  assert.match(frame, /\[a\]llow this turn/);
  assert.match(frame, /✓ \[y\]es allow/);
  assert.match(frame, /✗ \[n\]o deny/);
});

test('renders an MCP tool subject with server and tool target before approval', () => {
  const { lastFrame } = render(
    <ApprovalModal subject={mcpSubject} policy="default" onDecide={() => {}} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /Allow MCP tool\?/);
  assert.match(frame, /tool: mcp/);
  assert.match(frame, /server: context7/);
  assert.match(frame, /mcp tool: search/);
  assert.match(frame, /policy: default/);
});

test('renders the tx-apply subject with diff, validators, and blocking failures', () => {
  const { lastFrame } = render(
    <ApprovalModal subject={txSubject} policy="default" onDecide={() => {}} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /Apply transaction tx_123\?/);
  assert.match(frame, /2 changed \(\+7\/-3\)/);
  assert.match(frame, /blocking 0\/1, advisory 1\/1/);
  assert.match(frame, /blocking failures: ✗ tsc/);
  // tx-apply does not get the allow-turn shortcut.
  assert.doesNotMatch(frame, /\[a\]llow this turn/);
});

test('y allows, n denies, a allows-for-turn (tool only)', async () => {
  const calls: UiApprovalDecision[] = [];
  const decide = (d: UiApprovalDecision) => {
    calls.push(d);
  };

  const allow = render(
    <ApprovalModal subject={toolSubject} policy="accept-edits" onDecide={decide} />
  );
  await flush();
  allow.stdin.write('y');
  await flush();
  assert.deepEqual(calls, ['allow']);

  const deny = render(
    <ApprovalModal subject={toolSubject} policy="accept-edits" onDecide={decide} />
  );
  await flush();
  deny.stdin.write('n');
  await flush();
  assert.deepEqual(calls, ['allow', 'deny']);

  const allowTurn = render(
    <ApprovalModal subject={toolSubject} policy="accept-edits" onDecide={decide} />
  );
  await flush();
  allowTurn.stdin.write('a');
  await flush();
  assert.deepEqual(calls, ['allow', 'deny', 'allow-turn']);
});

test('ignores decision keys until the modal is active after its first render', async () => {
  const calls: UiApprovalDecision[] = [];
  const { stdin } = render(
    <ApprovalModal
      subject={toolSubject}
      policy="accept-edits"
      onDecide={(d) => {
        calls.push(d);
      }}
    />
  );

  stdin.write('y');
  await flush();
  assert.equal(calls.length, 0);

  stdin.write('y');
  await flush();
  assert.deepEqual(calls, ['allow']);
});

test('"a" on a tx-apply subject is a no-op (no allow-turn for tx)', async () => {
  const calls: UiApprovalDecision[] = [];
  const { stdin } = render(
    <ApprovalModal
      subject={txSubject}
      policy="default"
      onDecide={(d) => {
        calls.push(d);
      }}
    />
  );
  await flush();
  stdin.write('a');
  await flush();
  assert.equal(calls.length, 0);
});

test('tool modal renders scoped grants and marks persistent workspace access as risky', () => {
  const { lastFrame } = render(
    <ApprovalModal subject={toolSubject} policy="accept-edits" onDecide={() => {}} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /\[s\]ession/);
  assert.match(frame, /! \[W\]orkspace \(persistent\)/);
});

test('s -> allow-session and W -> allow-workspace on a tool subject', async () => {
  const calls: UiApprovalDecision[] = [];
  const decide = (d: UiApprovalDecision) => {
    calls.push(d);
  };

  const session = render(
    <ApprovalModal subject={toolSubject} policy="accept-edits" onDecide={decide} />
  );
  await flush();
  session.stdin.write('s');
  await flush();
  assert.deepEqual(calls, ['allow-session']);

  // Uppercase W is intentional — see ApprovalModal: lowercase w is reserved
  // so the heaviest "persist forever in this workspace" decision needs a
  // deliberate shift keystroke.
  const workspace = render(
    <ApprovalModal subject={toolSubject} policy="accept-edits" onDecide={decide} />
  );
  await flush();
  workspace.stdin.write('W');
  await flush();
  assert.deepEqual(calls, ['allow-session', 'allow-workspace']);
});

test('lowercase w on a tool subject is a no-op (must be shifted)', async () => {
  const calls: UiApprovalDecision[] = [];
  const { stdin } = render(
    <ApprovalModal
      subject={toolSubject}
      policy="accept-edits"
      onDecide={(d) => calls.push(d)}
    />
  );
  await flush();
  stdin.write('w');
  await flush();
  assert.equal(calls.length, 0);
});

test('tx-apply subject does not render or accept session/workspace hotkeys', async () => {
  const { lastFrame, stdin } = render(
    <ApprovalModal
      subject={txSubject}
      policy="default"
      onDecide={() => {}}
    />
  );
  const frame = lastFrame() ?? '';
  assert.doesNotMatch(frame, /\[s\]ession/);
  assert.doesNotMatch(frame, /\[W\]orkspace/);

  // Keys still get a no-op decision rather than throwing.
  const calls: UiApprovalDecision[] = [];
  const { stdin: stdin2 } = render(
    <ApprovalModal
      subject={txSubject}
      policy="default"
      onDecide={(d) => calls.push(d)}
    />
  );
  await flush();
  stdin2.write('s');
  stdin2.write('W');
  await flush();
  assert.equal(calls.length, 0);
  // Silence "stdin not used" warning from the first render.
  stdin.write('');
});
