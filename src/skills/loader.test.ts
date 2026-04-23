import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadSkills, mergeSkillNames } from './loader.js';

test('mergeSkillNames preserves order and removes duplicates', () => {
  assert.deepEqual(mergeSkillNames(['reviewer', 'safe-edit'], ['safe-edit', 'planner']), [
    'reviewer',
    'safe-edit',
    'planner'
  ]);
});

test('loadSkills reads SKILL.md from the workspace skill directory', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'reviewer'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'reviewer', 'SKILL.md'),
      `---
name: reviewer
description: inspection-first review mode
---

Prefer read-only inspection before edits.`,
      'utf8'
    );

    const loaded = await loadSkills(cwd, ['reviewer']);
    assert.equal(loaded[0]?.name, 'reviewer');
    assert.match(loaded[0]?.prompt ?? '', /Prefer read-only inspection/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects a skill file with missing name frontmatter', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-invalid-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'broken'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'broken', 'SKILL.md'),
      `---
description: missing name
---

Prompt body.`,
      'utf8'
    );

    await assert.rejects(() => loadSkills(cwd, ['broken']), /must declare a name/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects a skill file with a blank prompt body', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-empty-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'empty'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'empty', 'SKILL.md'),
      `---
name: empty
---
`,
      'utf8'
    );

    await assert.rejects(() => loadSkills(cwd, ['empty']), /prompt body must not be empty/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills accepts CRLF frontmatter and body separators', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-crlf-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'reviewer'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'reviewer', 'SKILL.md'),
      '---\r\nname: reviewer\r\ndescription: windows-style newlines\r\n---\r\n\r\nPrefer read-only inspection.\r\n',
      'utf8'
    );

    const loaded = await loadSkills(cwd, ['reviewer']);
    assert.equal(loaded[0]?.name, 'reviewer');
    assert.match(loaded[0]?.prompt ?? '', /Prefer read-only inspection/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
