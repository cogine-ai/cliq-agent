import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { Text } from 'ink';
import { render } from 'ink-testing-library';

import { useKeybindings } from './use-keybindings.js';

const flush = () => new Promise<void>((r) => setImmediate(r));

function Probe({
  onCtrlC,
  onCtrlD,
  onToggleBody,
  onRotatePolicy
}: {
  onCtrlC?: () => void;
  onCtrlD?: () => void;
  onToggleBody?: () => void;
  onRotatePolicy?: () => void;
}) {
  useKeybindings({
    ...(onCtrlC ? { onCtrlC } : {}),
    ...(onCtrlD ? { onCtrlD } : {}),
    ...(onToggleBody ? { onToggleBody } : {}),
    ...(onRotatePolicy ? { onRotatePolicy } : {})
  });
  return <Text>probe</Text>;
}

test('Ctrl+C fires onCtrlC', async () => {
  let calls = 0;
  const { stdin } = render(
    <Probe
      onCtrlC={() => {
        calls += 1;
      }}
    />
  );
  stdin.write('\x03');
  await flush();
  assert.equal(calls, 1);
});

test('Ctrl+D fires onCtrlD', async () => {
  let calls = 0;
  const { stdin } = render(
    <Probe
      onCtrlD={() => {
        calls += 1;
      }}
    />
  );
  stdin.write('\x04');
  await flush();
  assert.equal(calls, 1);
});

test('Ctrl+O fires onToggleBody and plain "o" does not', async () => {
  let calls = 0;
  const { stdin } = render(
    <Probe
      onToggleBody={() => {
        calls += 1;
      }}
    />
  );
  stdin.write('o');
  await flush();
  assert.equal(calls, 0);

  stdin.write('\x0f'); // Ctrl+O
  await flush();
  assert.equal(calls, 1);
});

// Shift+Tab is intentionally not driven through ink-testing-library: the
// CSI Z ↔ key.shift|tab parsing varies by Ink version + ink-testing-library
// stdin shim and we couldn't get a reliable round-trip in this environment.
// The dispatch logic is covered by:
//   - nextPolicyMode + POLICY_ROTATION (policy-rotation.test.ts)
//   - the App-level handler wiring (compile-time)
// and verified manually on a real TTY before each release.
