import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { SEMANTIC_STYLES, semanticTextProps } from './semantic-styles.js';

test('semantic state map keeps risk, progress, result, and metadata meanings stable', () => {
  assert.deepEqual(
    Object.keys(SEMANTIC_STYLES),
    ['safe', 'info', 'active', 'warning', 'danger', 'success', 'error', 'muted']
  );
  assert.equal(SEMANTIC_STYLES.safe.color, 'green');
  assert.equal(SEMANTIC_STYLES.active.marker, '▸');
  assert.equal(SEMANTIC_STYLES.warning.color, 'yellow');
  assert.equal(SEMANTIC_STYLES.danger.marker, '!');
  assert.equal(SEMANTIC_STYLES.success.marker, '✓');
  assert.equal(SEMANTIC_STYLES.error.marker, '✗');
  assert.deepEqual(semanticTextProps('muted'), { color: 'gray' });
});

test('every semantic state has both a named ANSI color and a no-color marker', () => {
  for (const style of Object.values(SEMANTIC_STYLES)) {
    assert.match(style.color, /^[a-z]+$/);
    assert.ok(style.marker.length > 0);
  }
});
