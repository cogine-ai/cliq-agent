import assert from 'node:assert/strict';
import { test } from 'node:test';
import { skillResourceReferences, validateFrozenSkillResourceGraph } from './resources.js';
import { parseFrozenSkillMarkdown } from './markdown.js';
const skill = (body: string) => Buffer.from('---\nname: example\ndescription: Reference closure.\nmetadata:\n  author: "sample"\n---\n' + body);

test('AgentSkills standard links and plain script references require no resources frontmatter', () => {
  const source = skill('See [the reference guide](references/REFERENCE.md) for details.\nRun the extraction script:\nscripts/extract.py\n' +
    'Use `assets/template.txt:12:2` and [the guide][guide].\n[guide]: references/REFERENCE.md "Title"\n' +
    '[External](https://example.org/never-fetch.py) and [this section](#section).\n');
  assert.deepEqual(skillResourceReferences('SKILL.md', source), ['references/REFERENCE.md', 'scripts/extract.py', 'assets/template.txt']);
  const files = new Map([['SKILL.md', source], ['references/REFERENCE.md', Buffer.from('Use [the schema](assets/root.schema.json).\n')],
    ['scripts/extract.py', Buffer.from('print("data only")\n')], ['assets/template.txt', Buffer.from('template')],
    ['assets/root.schema.json', Buffer.from('{"$ref":"types/part.json#/$defs/value"}')], ['assets/types/part.json', Buffer.from('{"$defs":{"value":{"type":"string"}}}')]]);
  assert.doesNotThrow(() => validateFrozenSkillResourceGraph(files, [...files.keys()].filter(name => name !== 'SKILL.md')));
});
test('image, percent encoding, collapsed/shortcut links and code preserve exact root-relative files', () => {
  assert.deepEqual(skillResourceReferences('references/nested.md', Buffer.from('![image](<assets/a%20b.png>)\n[guide][] and [guide]\n[guide]: references/guide.md\n')),
    ['assets/a b.png', 'references/guide.md']);
  assert.deepEqual(skillResourceReferences('SKILL.md', skill('```sh\npython scripts/extract.py\n```\n')), ['scripts/extract.py']);
  assert.deepEqual(skillResourceReferences('SKILL.md', skill('Use `./assets/file.` and `guide.md:12`.')), ['assets/file.', 'guide.md']);
});
test('standard metadata remains only a string map and no custom resources key is required or evaluated', () => {
  const valid = '---\nname: example\ndescription: >\n  A folded description.\nmetadata:\n  author: sample\n  version: "1.0"\nallowed-tools: Read Bash(git:*)\n---\nBody.';
  assert.deepEqual({ ...parseFrozenSkillMarkdown(valid).manifest.metadata }, { author: 'sample', version: '1.0' });
  for (const field of ['metadata:\n  value: true', 'metadata:\n  value: [a, b]', 'metadata:\n  nested:\n    value: text',
    'metadata:\n  value: text\n  value: other', 'resources: [scripts/x.py]', 'name: Example', 'name: example--name'])
    assert.throws(() => parseFrozenSkillMarkdown('---\nname: example\ndescription: Text.\n' + field + '\n---\nBody.'), TypeError, field);
});
test('unsafe or unsupported explicit local declarations refuse rather than silently drop dependencies', () => {
  for (const body of ['[x](../escape.md)', '[x](/etc/passwd)', '[x](file:///etc/passwd)', '[x](safe%2f..%2f..%2fescape.md)',
    '[x](assets/x.md?query=1)', '[x](scripts/*.py)', '[x](assets/x.md', '[x][missing]', '<img src="assets/a.png">',
    '`$ROOT/scripts/x.py`', '`C:\\scripts\\x.py`', '[x](.git/config)', '[x](.GIT/config)', '`guide.md:0`', '`scripts/run:0`', '```sh\nscripts/x.py\n'])
    assert.throws(() => skillResourceReferences('SKILL.md', skill(body)), TypeError, body);
  for (const value of ['{"$ref":"https://example.org/remote.json"}', '{"$id":"https://example.org/base"}', '{"$dynamicRef":"#x"}', '{"$ref":"../../escape.json"}'])
    assert.throws(() => skillResourceReferences('schemas/root.json', Buffer.from(value)), TypeError, value);
});
test('retained graph rejects omitted files, orphan files, cycles and excessive recursive depth', () => {
  const source = skill('Read [a](references/a.md).\n'), files = new Map([['SKILL.md', source], ['references/a.md', Buffer.from('Data.')]]);
  assert.doesNotThrow(() => validateFrozenSkillResourceGraph(files, ['references/a.md']));
  assert.throws(() => validateFrozenSkillResourceGraph(new Map([['SKILL.md', source]]), []));
  assert.throws(() => validateFrozenSkillResourceGraph(new Map([...files, ['unselected.txt', Buffer.from('orphan')]]), ['references/a.md', 'unselected.txt']));
  files.set('references/a.md', Buffer.from('[back](SKILL.md)')); assert.throws(() => validateFrozenSkillResourceGraph(files, ['references/a.md']));
  const chain = new Map<string, Buffer>([['SKILL.md', skill('[next](n0.md)')]]);
  for (let index = 0; index < 33; index++) chain.set(`n${index}.md`, Buffer.from(index === 32 ? 'End' : `[next](n${index + 1}.md)`));
  assert.throws(() => validateFrozenSkillResourceGraph(chain, [...chain.keys()].filter(name => name !== 'SKILL.md')));
});

test('long literal bracket and prose runs preserve real references without suffix rescans or word arrays', () => {
  const body = '['.repeat(65536) + '\n' + 'ordinary '.repeat(65536) + '\n[guide][original]\n[original]: references/guide.md\n';
  assert.deepEqual(skillResourceReferences('SKILL.md', skill(body)), ['references/guide.md']);
  assert.deepEqual(skillResourceReferences('SKILL.md', skill('['.repeat(65536) + '[guide]\n[guide]: references/guide.md')), ['references/guide.md']);
  assert.deepEqual(skillResourceReferences('SKILL.md', skill('Use Node.js to interpret the example. See https://example.org/guide.md for context.')), []);
  assert.deepEqual(skillResourceReferences('SKILL.md', skill('README.md')), ['README.md']);
});
