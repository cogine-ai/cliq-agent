import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { Text } from 'ink';
import { render } from 'ink-testing-library';

import { isShiftTabInput, useKeybindings } from './use-keybindings.js';

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

test('terminal Shift+Tab CSI Z fires onRotatePolicy', async () => {
  let calls = 0;
  const { stdin } = render(
    <Probe
      onRotatePolicy={() => {
        calls += 1;
      }}
    />
  );
  stdin.write('\x1b[Z');
  await flush();
  assert.equal(calls, 1);
});

test('Shift+Tab detection accepts parsed and raw terminal forms', () => {
  assert.equal(isShiftTabInput('', { shift: true, tab: true }), true);
  assert.equal(isShiftTabInput('\x1b[Z', { shift: false, tab: false }), true);
  assert.equal(isShiftTabInput('\x1b\t', { shift: false, tab: false }), true);
  assert.equal(isShiftTabInput('\t', { shift: false, tab: true }), false);
});
