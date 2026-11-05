// Pure retained-byte qualification for the first stdio executable recipe.
// These facts cannot create an image, process, descriptor or launch authority.
import { types } from 'node:util';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';

export const MCP_STDIO_EXECUTION_PATH = '/runtime/mcp-server';
export const MCP_STDIO_EXECUTABLE_BYTES = DEFAULT_SANDBOX_RESOURCES.maxSingleFileBytes;
export function inspectMcpStaticLinuxExecutable(input: Uint8Array) {
  if (types.isProxy(input) || !types.isUint8Array(input) || input.byteLength < 64 || input.byteLength > MCP_STDIO_EXECUTABLE_BYTES)
    throw new TypeError('MCP server exceeds its signed executable recipe');
  const bytes = Buffer.from(input), u16 = (at: number) => bytes.readUInt16LE(at), u32 = (at: number) => bytes.readUInt32LE(at);
  if (!bytes.subarray(0, 7).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1])) ||
      ![0, 3].includes(bytes[7]!) || bytes[8] !== 0 || u16(16) !== 2 || u16(18) !== 62 || u32(20) !== 1 || u32(48) !== 0 || u16(52) !== 64 || u16(54) !== 56)
    throw new TypeError('MCP server requires the complete static Linux x64 ELF profile');
  const entry = bytes.readBigUInt64LE(24), offset = bytes.readBigUInt64LE(32), count = u16(56);
  if (!count || offset < 64n || offset + BigInt(count) * 56n > BigInt(bytes.length)) throw new TypeError('MCP ELF program headers are incomplete');
  let executableEntry = false;
  for (let index = 0; index < count; index++) {
    const at = Number(offset) + index * 56, kind = u32(at), flags = u32(at + 4);
    // A single signed file cannot establish an interpreter, loader or shared
    // library closure. There is no host-path or ambient-loader fallback.
    if (kind === 2 || kind === 3) throw new TypeError('MCP dynamic or interpreted server closure is unsupported');
    if (kind !== 1) continue;
    const fileOffset = bytes.readBigUInt64LE(at + 8), address = bytes.readBigUInt64LE(at + 16);
    const fileBytes = bytes.readBigUInt64LE(at + 32), memoryBytes = bytes.readBigUInt64LE(at + 40), align = bytes.readBigUInt64LE(at + 48);
    if (fileBytes > memoryBytes || fileOffset + fileBytes > BigInt(bytes.length) || address + memoryBytes > 0xffffffffffffffffn ||
        align > 1n && ((align & (align - 1n)) !== 0n || fileOffset % align !== address % align))
      throw new TypeError('MCP ELF load segment is invalid');
    if ((flags & 1) && entry >= address && entry < address + fileBytes) executableEntry = true;
  }
  if (!executableEntry) throw new TypeError('MCP ELF entry has no retained executable segment');
  return Object.freeze({ format: 'cliq-mcp-static-linux-executable-v1' as const, architecture: 'x86_64' as const,
    byteCount: bytes.length, entryAddress: entry.toString(16) });
}
