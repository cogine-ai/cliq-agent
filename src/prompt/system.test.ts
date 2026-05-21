import assert from 'node:assert/strict';
import test from 'node:test';

import { BASE_SYSTEM_PROMPT } from './system.js';

test('base prompt tells the model to discover Windows Desktop paths before probing', () => {
  assert.match(BASE_SYSTEM_PROMPT, /os_path/);
  assert.match(BASE_SYSTEM_PROMPT, /Windows Desktop/i);
  assert.match(BASE_SYSTEM_PROMPT, /known-folder/i);
  assert.match(BASE_SYSTEM_PROMPT, /Public Desktop/i);
  assert.match(BASE_SYSTEM_PROMPT, /WSL/i);
  assert.match(BASE_SYSTEM_PROMPT, /Avoid broad recursive scans/i);
});
