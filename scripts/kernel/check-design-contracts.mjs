#!/usr/bin/env node

// Documentation guard only: no runtime, state root or provider is opened.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import ts from 'typescript';

const root = fileURLToPath(new URL('../../', import.meta.url));
const rfcPath = 'docs/rfcs/2026-08-11-durable-verified-run-kernel.md';
const backlogPath = 'docs/backlog/durable-verified-run-kernel';
const packagePaths = readdirSync(path.join(root, backlogPath))
  .filter((name) => /^0[1-6]-.+\.md$/.test(name))
  .sort()
  .map((name) => `${backlogPath}/${name}`);
const failures = [];

// These definitions have explicit owners outside the RFC. Adding another
// shared owner is a design change, not an automatic exemption from checking.
const packageOwned = new Map([
  ['BrokerRequest', `${backlogPath}/03-trusted-execution-and-workspaces.md`],
  ['RuntimeBundleStructuredArtifactBaseV1', `${backlogPath}/06-ecosystem-surfaces-and-kernel-cutover.md`],
  ['RuntimeBundleStructuredArtifactV1', `${backlogPath}/06-ecosystem-surfaces-and-kernel-cutover.md`],
  ['RuntimeBundleManifest', `${backlogPath}/06-ecosystem-surfaces-and-kernel-cutover.md`],
]);

function shape(node) {
  const children = [];
  ts.forEachChild(node, (child) => { children.push(shape(child)); });
  // TypeOperator.operator and template-fragment text are not child nodes.
  // Omitting them would equate readonly/keyof or distinct template prefixes.
  const value = typeof node.text === 'string' ? node.text : null;
  const operator = typeof node.operator === 'number' ? node.operator : null;
  return [node.kind, operator, value, children];
}

function readDefinitions(relativePath) {
  const markdown = readFileSync(path.join(root, relativePath), 'utf8');
  const definitions = new Map();
  const blocks = /^([ \t]*)```(?:ts|typescript)\r?\n([\s\S]*?)^\1```/gm;
  for (const match of markdown.matchAll(blocks)) {
    const source = ts.createSourceFile(relativePath, match[2], ts.ScriptTarget.Latest, true);
    const firstLine = markdown.slice(0, match.index).split('\n').length + 1;
    for (const diagnostic of source.parseDiagnostics) {
      const localLine = source.getLineAndCharacterOfPosition(diagnostic.start ?? 0).line;
      failures.push(`${relativePath}:${firstLine + localLine}: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ')}`);
    }
    for (const node of source.statements) {
      if (!ts.isTypeAliasDeclaration(node) && !ts.isInterfaceDeclaration(node)) continue;
      const name = node.name.text;
      const line = firstLine + source.getLineAndCharacterOfPosition(node.getStart(source)).line;
      const definition = { shape: JSON.stringify(shape(node)), line };
      const previous = definitions.get(name);
      if (previous && previous.shape !== definition.shape) {
        failures.push(`${relativePath}:${line}: conflicting repeated definition of ${name}`);
      }
      definitions.set(name, definition);
    }
  }
  return definitions;
}

if (packagePaths.length !== 6) failures.push(`Expected six work packages; found ${packagePaths.length}`);
const canonical = readDefinitions(rfcPath);
if (canonical.size === 0) failures.push('No RFC TypeScript definitions found');
const packages = new Map(packagePaths.map((file) => [file, readDefinitions(file)]));
const owners = new Map([...canonical].map(([name, definition]) => [name, { ...definition, file: rfcPath }]));
for (const [name, file] of packageOwned) {
  const definition = packages.get(file)?.get(name);
  if (!definition) {
    failures.push(`${file}: missing package-owned definition ${name}`);
  } else if (owners.has(name)) {
    failures.push(`${name}: declared in the RFC and in the package ownership exception list`);
  } else {
    owners.set(name, { ...definition, file });
  }
}

let sharedCopies = 0;
for (const [file, definitions] of packages) {
  for (const [name, definition] of definitions) {
    const owner = owners.get(name);
    if (!owner) {
      failures.push(`${file}:${definition.line}: ${name} has no declared canonical owner`);
    } else if (owner.file !== file) {
      sharedCopies++;
      if (owner.shape !== definition.shape) {
        failures.push(`${file}:${definition.line}: ${name} differs from ${owner.file}:${owner.line}`);
      }
    }
  }
}

if (failures.length) {
  for (const failure of failures) console.error(failure);
  process.exitCode = 1;
} else {
  console.log(`Kernel design contracts: 6 work packages, ${canonical.size} RFC definitions, ${packageOwned.size} package-owned definitions, ${sharedCopies} shared copies checked; no drift.`);
}
