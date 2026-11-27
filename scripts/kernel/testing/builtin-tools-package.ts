// Fixed signed data asset construction only. Actual execution is the exact
// retained guest Node, and this helper never signs or grants that authority.
import { build } from 'esbuild';
import path from 'node:path';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { BUILTIN_SCRIPT_RECIPE } from '../../../src/sandbox/builtin-tool-data.js';

export async function buildBuiltinToolsAsset(repository: string) {
  const result = await build({ entryPoints: [path.join(repository, 'src/sandbox/builtin-tool-program.ts')],
    bundle: true, write: false, format: 'esm', platform: 'node', target: 'node24.21',
    minify: true, legalComments: 'none', logLevel: 'silent',
    banner: { js: "import { createRequire as __cliqCreateRequire } from 'node:module';const require=__cliqCreateRequire(import.meta.url);" } });
  if (result.outputFiles.length !== 1) throw new TypeError('fixed builtin program must have one complete script asset');
  const bytes = Buffer.from(result.outputFiles[0]!.contents);
  if (!bytes.length || bytes.length > BUILTIN_SCRIPT_RECIPE.scriptBytes) throw new TypeError('fixed builtin script exceeds its native seal bound');
  return { entryId: BUILTIN_SCRIPT_RECIPE.entryId, role: 'tool_adapter' as const, version: BUILTIN_SCRIPT_RECIPE.version,
    relativePath: BUILTIN_SCRIPT_RECIPE.relativePath, executable: false as const,
    digest: sha256Bytes(bytes), byteCount: bytes.length, bytes };
}
