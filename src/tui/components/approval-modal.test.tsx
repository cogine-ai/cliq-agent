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
  channel: { kind: 'bash', commandHead: 'rm' },
  action: { bash: 'rm -rf /' } as never,
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

test('renders the tool subject with command, access, and policy', () => {
  const { lastFrame } = render(
    <ApprovalModal subject={toolSubject} policy="confirm-bash" onDecide={() => {}} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /Approval required/);
  assert.match(frame, /Allow bash command\?/);
  assert.match(frame, /tool: bash/);
  assert.match(frame, /command: rm -rf \//);
  assert.match(frame, /policy: confirm-bash/);
  assert.match(frame, /\[a\]llow this turn/);
});

test('renders the tx-apply subject with diff, validators, and blocking failures', () => {
  const { lastFrame } = render(
    <ApprovalModal subject={txSubject} policy="confirm-write" onDecide={() => {}} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /Apply transaction tx_123\?/);
  assert.match(frame, /2 changed \(\+7\/-3\)/);
  assert.match(frame, /blocking 0\/1, advisory 1\/1/);
  assert.match(frame, /blocking failures: tsc/);
  // tx-apply does not get the allow-turn shortcut.
  assert.doesNotMatch(frame, /\[a\]llow this turn/);
});

test('y allows, n denies, a allows-for-turn (tool only)', async () => {
  const calls: UiApprovalDecision[] = [];
  const decide = (d: UiApprovalDecision) => {
    calls.push(d);
  };

  const allow = render(
    <ApprovalModal subject={toolSubject} policy="confirm-bash" onDecide={decide} />
  );
  allow.stdin.write('y');
  await flush();
  assert.deepEqual(calls, ['allow']);

  const deny = render(
    <ApprovalModal subject={toolSubject} policy="confirm-bash" onDecide={decide} />
  );
  deny.stdin.write('n');
  await flush();
  assert.deepEqual(calls, ['allow', 'deny']);

  const allowTurn = render(
    <ApprovalModal subject={toolSubject} policy="confirm-bash" onDecide={decide} />
  );
  allowTurn.stdin.write('a');
  await flush();
  assert.deepEqual(calls, ['allow', 'deny', 'allow-turn']);
});

test('"a" on a tx-apply subject is a no-op (no allow-turn for tx)', async () => {
  const calls: UiApprovalDecision[] = [];
  const { stdin } = render(
    <ApprovalModal
      subject={txSubject}
      policy="confirm-write"
      onDecide={(d) => {
        calls.push(d);
      }}
    />
  );
  stdin.write('a');
  await flush();
  assert.equal(calls.length, 0);
});

test('tool modal renders the [s]ession and dim [W]orkspace hotkeys', () => {
  const { lastFrame } = render(
    <ApprovalModal subject={toolSubject} policy="confirm-bash" onDecide={() => {}} />
  );
  const frame = lastFrame() ?? '';
  // The hotkey row carries both scopes; the workspace label is the only one
  // rendered in dim color, signaling it's the most sticky decision.
  assert.match(frame, /\[s\]ession/);
  assert.match(frame, /\[W\]orkspace/);
});

test('s -> allow-session and W -> allow-workspace on a tool subject', async () => {
  const calls: UiApprovalDecision[] = [];
  const decide = (d: UiApprovalDecision) => {
    calls.push(d);
  };

  const session = render(
    <ApprovalModal subject={toolSubject} policy="confirm-bash" onDecide={decide} />
  );
  session.stdin.write('s');
  await flush();
  assert.deepEqual(calls, ['allow-session']);

  // Uppercase W is intentional — see ApprovalModal: lowercase w is reserved
  // so the heaviest "persist forever in this workspace" decision needs a
  // deliberate shift keystroke.
  const workspace = render(
    <ApprovalModal subject={toolSubject} policy="confirm-bash" onDecide={decide} />
  );
  workspace.stdin.write('W');
  await flush();
  assert.deepEqual(calls, ['allow-session', 'allow-workspace']);
});

test('lowercase w on a tool subject is a no-op (must be shifted)', async () => {
  const calls: UiApprovalDecision[] = [];
  const { stdin } = render(
    <ApprovalModal
      subject={toolSubject}
      policy="confirm-bash"
      onDecide={(d) => calls.push(d)}
    />
  );
  stdin.write('w');
  await flush();
  assert.equal(calls.length, 0);
});

test('tx-apply subject does not render or accept session/workspace hotkeys', async () => {
  const { lastFrame, stdin } = render(
    <ApprovalModal
      subject={txSubject}
      policy="confirm-write"
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
      policy="confirm-write"
      onDecide={(d) => calls.push(d)}
    />
  );
  stdin2.write('s');
  stdin2.write('W');
  await flush();
  assert.equal(calls.length, 0);
  // Silence "stdin not used" warning from the first render.
  stdin.write('');
});
