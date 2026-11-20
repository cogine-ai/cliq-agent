import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const timedFiles = new Set(['src/state/control-list-capacity.test.ts', 'src/state/session-continuity.test.ts']);
function discover(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const filename = `${directory}/${entry.name}`;
    return entry.isDirectory() ? discover(filename) : entry.isFile() && /\.test\.tsx?$/u.test(entry.name) ? [filename] : [];
  });
}
const files = discover('src').sort();
for (const filename of timedFiles) assert(files.includes(filename), `missing isolated timing suite: ${filename}`);
const groups = [
  { concurrency: 2, files: files.filter(filename => !timedFiles.has(filename)) },
  { concurrency: 1, files: files.filter(filename => timedFiles.has(filename)) },
];
if (process.argv[2] === '--list') {
  console.log(JSON.stringify(groups));
} else {
  let status = 0;
  for (const group of groups) {
    if (!group.files.length) continue;
    console.log(`Running ${group.files.length} test files with concurrency ${group.concurrency}.`);
    const child = spawnSync(process.execPath,
      ['--test', ...process.argv.slice(2), `--test-concurrency=${group.concurrency}`, '--import', 'tsx', ...group.files],
      { stdio: 'inherit' });
    if (child.error) throw child.error;
    status ||= child.status ?? 1;
    if (child.signal) break;
  }
  process.exitCode = status;
}
