// Build-time inputs only. The executing Node supplies the SQLite engine/API.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SQLITE_EXTENSION_NODE_VERSION = '24.21.0';
export const SQLITE_EXTENSION_HEADER_PINS = Object.freeze({
  'sqlite3.h': '919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d',
  'sqlite3ext.h': 'ac9645e5c9ff0cf176efdd6e75cb5e98f46295d38e02db5c4d208826a39ab4be',
});
const includes = fileURLToPath(new URL('../../native/vendor/node-sqlite-v24.21.0', import.meta.url));

/** No caller-selected headers, network download, or second SQLite engine. */
export async function verifiedSqliteExtensionIncludes() {
  for (const [name, digest] of Object.entries(SQLITE_EXTENSION_HEADER_PINS)) {
    const bytes = await readFile(path.join(includes, name));
    if (createHash('sha256').update(bytes).digest('hex') !== digest)
      throw new Error(`vendored ${name} checksum mismatch`);
  }
  return includes;
}
