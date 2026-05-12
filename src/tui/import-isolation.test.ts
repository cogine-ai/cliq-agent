import * as assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, resolve, sep } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

// The TUI is the second consumer of the runtime event stream (the first is
// `src/headless/`). Spec A.13 guards a critical invariant: the runtime,
// protocol, and headless surfaces must never transitively pull in Ink/React
// or any module under `src/tui/`. Otherwise headless users (CI, RPC clients,
// the future stdio JSON-RPC server) would unnecessarily load a UI library.
//
// This test catches violations as a *direct* import on any file under the
// guarded directories — since transitivity bottoms out at the next link in
// the chain, walking each file once and checking its direct imports is
// sufficient: if A → B → tui, then B itself fails the check.

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = resolve(HERE, '..');
const TUI_PATH = resolve(SRC_ROOT, 'tui');

const GUARDED_DIRECTORIES = [
  resolve(SRC_ROOT, 'headless'),
  resolve(SRC_ROOT, 'runtime'),
  resolve(SRC_ROOT, 'protocol')
];

const FORBIDDEN_PACKAGES = new Set(['react', 'ink', 'ink-text-input', 'ink-testing-library']);

const IMPORT_PATTERNS = [
  // import ... from 'X' / import 'X' / import('X')
  /\bimport\s+(?:[^'";]+\s+from\s+)?['"]([^'"]+)['"]/g,
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\bexport\s+(?:[^'";]+\s+from\s+)?['"]([^'"]+)['"]/g
];

async function listSourceFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const name = entry.name;
    if (!name.endsWith('.ts') && !name.endsWith('.tsx')) continue;
    if (name.endsWith('.test.ts') || name.endsWith('.test.tsx')) continue;
    // Recursive readdir gives parentPath in Node 22.
    const parent = (entry as unknown as { parentPath?: string; path?: string }).parentPath
      ?? (entry as unknown as { path?: string }).path
      ?? dir;
    out.push(resolve(parent, name));
  }
  return out;
}

function extractImports(source: string): string[] {
  const specs = new Set<string>();
  for (const pattern of IMPORT_PATTERNS) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(source)) !== null) {
      specs.add(m[1]!);
    }
  }
  return [...specs];
}

function isForbiddenPackage(spec: string): boolean {
  if (FORBIDDEN_PACKAGES.has(spec)) return true;
  // Subpath imports e.g. 'react/jsx-runtime', 'ink/internal/x'.
  for (const pkg of FORBIDDEN_PACKAGES) {
    if (spec.startsWith(`${pkg}/`)) return true;
  }
  return false;
}

function resolvesIntoTui(spec: string, fromFile: string): boolean {
  if (!spec.startsWith('.')) return false;
  const resolved = resolve(dirname(fromFile), spec);
  return resolved === TUI_PATH || resolved.startsWith(`${TUI_PATH}${sep}`);
}

test('runtime / headless / protocol modules never import Ink/React or src/tui/', async () => {
  const violations: string[] = [];

  for (const dir of GUARDED_DIRECTORIES) {
    const files = await listSourceFiles(dir);
    for (const file of files) {
      const source = await readFile(file, 'utf8');
      for (const spec of extractImports(source)) {
        if (isForbiddenPackage(spec)) {
          violations.push(`${file}: imports forbidden package "${spec}"`);
        } else if (resolvesIntoTui(spec, file)) {
          violations.push(`${file}: imports from src/tui/ via "${spec}"`);
        }
      }
    }
  }

  assert.equal(
    violations.length,
    0,
    `import-isolation violations:\n  ${violations.join('\n  ')}`
  );
});

test('the test itself walked at least one file in each guarded directory', async () => {
  // Sanity check: catches a regression where the directory walk silently
  // skips everything (e.g. if rootDir layout changes).
  for (const dir of GUARDED_DIRECTORIES) {
    const files = await listSourceFiles(dir);
    assert.ok(files.length > 0, `expected at least one source file under ${dir}`);
  }
});
