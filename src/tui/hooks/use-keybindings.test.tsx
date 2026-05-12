import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { Text } from 'ink';
import { render } from 'ink-testing-library';

import { useKeybindings } from './use-keybindings.js';

const flush = () => new Promise<void>((r) => setImmediate(r));

function Probe({
  onCtrlC,
  onCtrlD,
  onToggleBody
}: {
  onCtrlC?: () => void;
  onCtrlD?: () => void;
  onToggleBody?: () => void;
}) {
  useKeybindings({
    ...(onCtrlC ? { onCtrlC } : {}),
    ...(onCtrlD ? { onCtrlD } : {}),
    ...(onToggleBody ? { onToggleBody } : {})
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
