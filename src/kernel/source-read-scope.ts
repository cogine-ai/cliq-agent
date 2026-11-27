/** An inert user consent selector, not a live descriptor/read capability.
 * Git metadata is hard-excluded except this exact independent rule source. */
export function normalizeSourceReadScopePath(value: unknown, scope: unknown): string {
  if (typeof value !== 'string' || (scope !== 'entry' && scope !== 'subtree') || !value ||
      value !== value.normalize('NFC') || Buffer.from(value).toString('utf8') !== value || Buffer.byteLength(value) > 4096 ||
      value.includes('\\') || value.includes('\0') || value.split('/').some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255))
    throw new TypeError('source read scope is not a canonical in-root selector');
  if (value === '.git/info/exclude' && scope === 'entry') return value;
  if (value.split('/').some(part => part.toLowerCase() === '.git')) throw new TypeError('source read scope cannot expose Git metadata');
  return value;
}
