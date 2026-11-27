// Emit only the public declaration graph after the ordinary full source build.
// Private runtime/StateOwner brands are not a public SDK contract.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
const root = fileURLToPath(new URL('../', import.meta.url));
const sourceRoot = path.join(root, 'src'), outputRoot = path.join(root, 'dist');
const configPath = path.join(root, 'tsconfig.sdk.json');
const config = ts.readConfigFile(configPath, ts.sys.readFile);
if (config.error) throw new Error(ts.flattenDiagnosticMessageText(config.error.messageText, '\n'));
const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
if (parsed.errors.length) throw new Error('invalid public declaration build configuration');
const program = ts.createProgram(parsed.fileNames, parsed.options);
const queue = ['src/sdk/index.ts', 'src/control/v1.ts'], seen = new Set();
const privateClientModules = new Set(['application', 'daily', 'installed-data', 'installed-host', 'model-settings',
  'pending-requests', 'preferences', 'private-files', 'stdio'].map(name => `src/client/${name}.ts`));
const outputs = new Map();
while (queue.length) {
  const relative = queue.shift(); if (seen.has(relative)) continue; seen.add(relative);
  if (!relative.startsWith('src/') || relative.split('/').includes('..') || seen.size > 1000)
    throw new Error('public declaration graph escaped its source bound');
  const file = program.getSourceFile(path.join(root, relative));
  if (!file) throw new Error('public declaration dependency is missing');
  const diagnostics = [...program.getSyntacticDiagnostics(file), ...program.getSemanticDiagnostics(file), ...program.getDeclarationDiagnostics(file)];
  if (diagnostics.length) throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCanonicalFileName: value => value, getCurrentDirectory: () => root, getNewLine: () => '\n' }));
  let declaration;
  const emitted = program.emit(file, (filename, text) => {
    if (!filename.endsWith('.d.ts') || !filename.startsWith(outputRoot + path.sep)) throw new Error('unexpected public declaration output');
    declaration = { filename, text };
  }, undefined, true);
  if (emitted.emitSkipped || emitted.diagnostics.length || !declaration) throw new Error('public declaration emission failed');
  outputs.set(declaration.filename, declaration.text);
  const ast = ts.createSourceFile(relative, declaration.text, ts.ScriptTarget.Latest, true);
  const visit = node => {
    let specifier;
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier))
      specifier = node.moduleSpecifier.text;
    else if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument) && ts.isStringLiteral(node.argument.literal))
      specifier = node.argument.literal.text;
    if (specifier?.startsWith('.')) {
      if (!specifier.endsWith('.js') || specifier.includes('\\')) throw new Error('unexpected public declaration reference');
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(relative), specifier.slice(0, -3) + '.ts'));
      // Public client declarations must not turn private ownership/authority
      // implementation into stable package surface.
      if (target.startsWith('src/state/') || target.startsWith('src/sandbox/') || target.startsWith('src/runtime/'))
        throw new Error(`public declaration leaked a private authority implementation: ${relative} -> ${target}`);
      if (privateClientModules.has(target))
        throw new Error(`public declaration leaked a private client implementation: ${relative} -> ${target}`);
      queue.push(target);
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
}
// Only build-generated declarations in this isolated dist tree are replaced.
for (const item of fs.readdirSync(outputRoot, { recursive: true })) {
  const filename = path.join(outputRoot, item);
  if (filename.endsWith('.d.ts') && !outputs.has(filename)) fs.unlinkSync(filename);
}
for (const [filename, text] of outputs) { fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, text); }
process.stdout.write(`SDK public declarations: ${outputs.size}\n`);
