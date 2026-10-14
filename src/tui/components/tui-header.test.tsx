import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { TuiHeader } from './tui-header.js';

test('top banner renders mode and risk with text and symbol backups', () => {
  const plan = render(<TuiHeader policy="plan" />).lastFrame() ?? '';
  assert.match(plan, /◆ Plan Mode · safe risk/);

  const yolo = render(<TuiHeader policy="yolo" />).lastFrame() ?? '';
  assert.match(yolo, /! YOLO Mode · danger risk/);
});
