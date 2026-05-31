import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildInputHint } from './hints.js';

test('idle hints surface help, mode switching, and current shortcut', () => {
  assert.equal(
    buildInputHint({ kind: 'idle', hasInput: false, hasExpandableTool: true, width: 90 }),
    'Enter send · /help commands · Shift+Tab mode · Ctrl+O output · Ctrl+D exit'
  );
});

test('slash hints focus on slash completion instead of normal prompt actions', () => {
  assert.equal(
    buildInputHint({ kind: 'slash-input', width: 90 }),
    'Slash commands · Tab complete · Enter run'
  );
});

test('active turn hints surface cancellation instead of normal submission', () => {
  assert.equal(
    buildInputHint({ kind: 'active-turn', width: 90 }),
    'Running · Ctrl+C cancel'
  );
});

test('approval hints focus on approval choices', () => {
  assert.equal(
    buildInputHint({ kind: 'approval', allowTurn: true, width: 90 }),
    'Approval: y allow · n deny · a allow turn'
  );
});

test('plan review hints focus on decision choices', () => {
  assert.equal(
    buildInputHint({ kind: 'plan-review', width: 90 }),
    'Plan review: d default · a accept-edits · Y yolo · r reject · c cancel'
  );
});

test('narrow hints stay compact', () => {
  assert.equal(
    buildInputHint({ kind: 'idle', hasInput: true, hasExpandableTool: false, width: 36 }),
    '/help · Shift+Tab · Ctrl+C'
  );
  assert.equal(buildInputHint({ kind: 'active-turn', width: 36 }), 'Ctrl+C cancel');
});
