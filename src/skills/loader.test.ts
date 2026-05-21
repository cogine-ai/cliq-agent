import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadSkills, mergeSkillNames } from './loader.js';

async function writeSkill(cwd: string, name: string, contents: string) {
  await mkdir(path.join(cwd, '.cliq', 'skills', name), { recursive: true });
  await writeFile(path.join(cwd, '.cliq', 'skills', name, 'SKILL.md'), contents, 'utf8');
}

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
    await writeSkill(
      cwd,
      'reviewer',
      `---
name: reviewer
description: inspection-first review mode
---

Prefer read-only inspection before edits.`
    );

    const loaded = await loadSkills(cwd, ['reviewer']);
    assert.equal(loaded[0]?.name, 'reviewer');
    assert.match(loaded[0]?.prompt ?? '', /Prefer read-only inspection/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills parses quoted Agent Skills frontmatter values containing colons', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-agent-'));
  try {
    await writeSkill(
      cwd,
      'reviewer',
      `---
name: "reviewer"
description: "Review changes: prefer focused, actionable comments"
---

Prefer read-only inspection before edits.`
    );

    const loaded = await loadSkills(cwd, ['reviewer']);
    assert.equal(loaded[0]?.name, 'reviewer');
    assert.equal(loaded[0]?.description, 'Review changes: prefer focused, actionable comments');
    assert.match(loaded[0]?.prompt ?? '', /Prefer read-only inspection/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills keeps optional frontmatter metadata separate from runtime prompt text', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-metadata-'));
  try {
    await writeSkill(
      cwd,
      'metadata-demo',
      `---
name: metadata-demo
description: Metadata fields are parsed without granting tools
license: MIT
compatibility: ">=1.0.0"
allowed-tools:
  - Bash(git status:*)
  - Read
metadata:
  short-description: Tool metadata: not runtime permissions
---

Follow repository instructions.`
    );

    const [skill] = await loadSkills(cwd, ['metadata-demo']);
    assert.deepEqual(skill?.frontmatter, {
      license: 'MIT',
      compatibility: '>=1.0.0',
      allowedTools: ['Bash(git status:*)', 'Read'],
      metadata: {
        'short-description': 'Tool metadata: not runtime permissions'
      }
    });
    assert.equal(Object.hasOwn(skill ?? {}, 'permissions'), false);
    assert.doesNotMatch(skill?.prompt ?? '', /Bash\(git status/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects a skill file with missing name frontmatter', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-invalid-'));
  try {
    await writeSkill(
      cwd,
      'broken',
      `---
description: missing name
---

Prompt body.`
    );

    await assert.rejects(() => loadSkills(cwd, ['broken']), /must declare a name/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects a skill file with missing description frontmatter', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-missing-description-'));
  try {
    await writeSkill(
      cwd,
      'broken',
      `---
name: broken
---

Prompt body.`
    );

    await assert.rejects(() => loadSkills(cwd, ['broken']), /Skill broken: .*declare required field "description"/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects malformed frontmatter lines with scoped diagnostics', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-malformed-'));
  try {
    await writeSkill(
      cwd,
      'broken',
      `---
name: broken
description this line has no colon
---

Prompt body.`
    );

    await assert.rejects(() => loadSkills(cwd, ['broken']), /Skill broken: .*frontmatter line 2/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects a skill file with an unterminated frontmatter block', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-unterminated-'));
  try {
    await writeSkill(
      cwd,
      'broken',
      `---
name: broken
description: missing closing delimiter

Prompt body.`
    );

    await assert.rejects(() => loadSkills(cwd, ['broken']), /Skill broken: .*frontmatter must close with ---/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects a skill file with a blank prompt body', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-empty-'));
  try {
    await writeSkill(
      cwd,
      'empty',
      `---
name: empty
description: empty prompt
---
`
    );

    await assert.rejects(() => loadSkills(cwd, ['empty']), /prompt body must not be empty/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills accepts CRLF frontmatter and body separators', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-crlf-'));
  try {
    await writeSkill(
      cwd,
      'reviewer',
      '---\r\nname: reviewer\r\ndescription: windows-style newlines\r\n---\r\n\r\nPrefer read-only inspection.\r\n'
    );

    const loaded = await loadSkills(cwd, ['reviewer']);
    assert.equal(loaded[0]?.name, 'reviewer');
    assert.match(loaded[0]?.prompt ?? '', /Prefer read-only inspection/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects frontmatter names that do not match the requested skill directory', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-mismatch-'));
  try {
    await writeSkill(
      cwd,
      'reviewer',
      `---
name: planner
description: mismatched skill name
---

Prompt body.`
    );

    await assert.rejects(() => loadSkills(cwd, ['reviewer']), /Skill reviewer: .*expected "reviewer", received "planner"/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects invalid skill names before resolving paths', async () => {
  await assert.rejects(
    () => loadSkills('/tmp/workspace', ['../escape']),
    /Invalid skill name: \.\.\/escape/i
  );
});
