// Fixed signed asset construction only. This is not an executable selector or
// release authority; the containing RuntimeBundle signs these exact bytes.
import { build } from 'esbuild';
import path from 'node:path';
import { sha256Bytes } from '../../../src/kernel/identity.js';

export async function buildSourceGitInspectorAsset(repository: string) {
  const result = await build({ entryPoints: [path.join(repository, 'src/workspace/source-git-inspector.ts')],
    bundle: true, write: false, format: 'esm', platform: 'node', target: 'node24.21',
    minify: true, legalComments: 'none', logLevel: 'silent' });
  if (result.outputFiles.length !== 1) throw new TypeError('fixed source inspector must have one complete script asset');
  const bytes = Buffer.from(result.outputFiles[0]!.contents);
  if (!bytes.length || bytes.length > 1_048_576) throw new TypeError('fixed source inspector script exceeds its native seal bound');
  return { entryId: 'source_git_inspector' as const, role: 'platform_helper' as const, version: '1' as const,
    relativePath: 'helpers/source-git-inspector.mjs' as const, executable: false as const,
    digest: sha256Bytes(bytes), byteCount: bytes.length, bytes };
}
