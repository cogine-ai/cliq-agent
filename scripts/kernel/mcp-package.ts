// Build data only; the original RuntimeBundle publisher signs these bytes.
import { build } from 'esbuild';
import path from 'node:path';
import { sha256Bytes } from '../../src/kernel/identity.js';
import { MCP_ADMIN_HELPER_ENTRY_ID, MCP_ADMIN_HELPER_RELATIVE_PATH } from '../../src/state/mcp-broker-native.js';
export async function buildMcpHttpAdminProbeAsset(repository: string) {
  const output = await build({ entryPoints: [path.join(repository, 'src/workspace/mcp-http-admin-probe.ts')],
    bundle: true, write: false, format: 'esm', platform: 'node', target: 'node24.21',
    minify: true, legalComments: 'none', logLevel: 'silent' });
  if (output.outputFiles.length !== 1) throw new TypeError('fixed MCP Admin helper requires one complete asset');
  const bytes = Buffer.from(output.outputFiles[0]!.contents);
  if (!bytes.length || bytes.length > 1_048_576) throw new TypeError('fixed MCP Admin helper exceeds its signed seal bound');
  return { entryId: MCP_ADMIN_HELPER_ENTRY_ID, relativePath: MCP_ADMIN_HELPER_RELATIVE_PATH,
    role: 'platform_helper' as const, version: '1' as const, executable: false as const,
    bytes, digest: sha256Bytes(bytes), byteCount: bytes.length };
}
