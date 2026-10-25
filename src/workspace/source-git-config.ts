// Fixed inspector implementation, not runtime workspace configuration. The
// Supervisor must never call this on raw repository input before inspection.
import { digestOmitting } from '../kernel/identity.js';
import type { SanitizedGitConfigV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';

const invalid = (): never => { throw new TypeError('source Git configuration is outside the fixed safe grammar'); };
const booleans = new Map<string, 'fileMode' | 'logAllRefUpdates' | 'ignoreCase' | 'precomposeUnicode'>([
  ['filemode', 'fileMode'], ['logallrefupdates', 'logAllRefUpdates'], ['ignorecase', 'ignoreCase'], ['precomposeunicode', 'precomposeUnicode']
]);
function boolean(value: string): boolean {
  if (/^(true|yes|on|1)$/iu.test(value)) return true;
  if (/^(false|no|off|0)$/iu.test(value)) return false;
  return invalid();
}
function literal(input: string): string {
  let output = '', pending = '', quoted = false;
  for (let index = 0; index < input.length; index++) {
    const char = input[index]!;
    if (char === '\\') {
      const escape = input[++index], value = escape === 'n' ? '\n' : escape === 't' ? '\t' : escape === 'b' ? '\b' :
        escape === '"' ? '"' : escape === '\\' ? '\\' : undefined;
      if (value === undefined) return invalid(); output += pending + value; pending = '';
    } else if (char === '"') { if (!quoted) { output += pending; pending = ''; } quoted = !quoted; }
    else if (!quoted && (char === ' ' || char === '\t')) { if (output) pending += char; }
    else { output += pending + char; pending = ''; }
  }
  if (quoted) return invalid(); return output;
}

/** Parses actual bounded Git syntax before classifying keys. Inert clone
 * values are only local parser data and are absent from every returned field.
 * This does not physically erase JS strings or prove native input retirement. */
export function classifySourceGitConfig(bytes: Buffer): Readonly<{
  objectFormat: 'sha1' | 'sha256'; config: SanitizedGitConfigV1; gitConfigUtf8: string;
}> {
  if (!Buffer.isBuffer(bytes) || bytes.length > 1_048_576) return invalid();
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return invalid(); }
  if (text.includes('\0') || text.replace(/\r\n/gu, '').includes('\r')) return invalid();
  const lines: string[] = []; let line = '', quoted = false, escaped = false, comment = false;
  for (const char of text.replace(/\r\n/gu, '\n') + '\n') {
    if (char === '\n') {
      if (escaped && !comment) { line = line.slice(0, -1); escaped = false; continue; }
      if (quoted) return invalid(); lines.push(line); if (lines.length > 4096) return invalid();
      line = ''; comment = false; escaped = false;
    } else if (!comment) {
      if (escaped) { line += char; escaped = false; }
      else if (!quoted && (char === '#' || char === ';')) comment = true;
      else { line += char; if (char === '\\') escaped = true; else if (char === '"') quoted = !quoted; }
      if (line.length > 65_536) return invalid();
    }
  }
  if (line || quoted || escaped) return invalid();
  const core: SanitizedGitConfigV1['core'] = { repositoryFormatVersion: 0, fileMode: true, bare: false };
  let objectFormat: 'sha1' | 'sha256' = 'sha1', section = '';
  for (const line of lines) {
    const current = line.trim(); if (!current) continue;
    if (current.startsWith('[')) {
      const header = /^\[([A-Za-z][A-Za-z0-9.-]*)(?:[ \t]+("(?:[^"\\]|\\["\\])*"))?\]$/u.exec(current);
      if (!header) return invalid(); section = header[1]!.toLowerCase();
      const subsection = header[2] === undefined ? undefined : literal(header[2]);
      if (subsection !== undefined && (!subsection || subsection.length > 1024 || /[\x00-\x1f\x7f]/u.test(subsection))) return invalid();
      if (!['core', 'extensions', 'remote', 'branch', 'user'].includes(section) ||
          ((section === 'remote' || section === 'branch') !== (subsection !== undefined))) return invalid();
      continue;
    }
    const variable = /^([A-Za-z][A-Za-z0-9-]*)(?:[ \t]*=[ \t]*(.*))?$/u.exec(current);
    if (!variable || !section) return invalid();
    const key = variable[1]!.toLowerCase(), value = variable[2] === undefined ? 'true' : literal(variable[2]);
    if (section === 'remote' || section === 'branch' || section === 'user') {
      const allowed = section === 'remote' ? ['url', 'pushurl', 'fetch'] : section === 'branch' ? ['remote', 'merge'] : ['name', 'email'];
      if (!allowed.includes(key) || variable[2] === undefined) return invalid();
      continue;
    }
    if (section === 'extensions') {
      if (key !== 'objectformat' || value !== 'sha1' && value !== 'sha256') return invalid();
      objectFormat = value; continue;
    }
    if (key === 'repositoryformatversion') {
      if (value !== '0' && value !== '1') return invalid(); core.repositoryFormatVersion = Number(value) as 0 | 1;
    } else if (key === 'bare') { if (boolean(value)) return invalid(); }
    else { const field = booleans.get(key); if (!field) return invalid(); core[field] = boolean(value); }
  }
  if (objectFormat === 'sha256' && core.repositoryFormatVersion !== 1) return invalid();
  const config: SanitizedGitConfigV1 = { schemaVersion: 1, format: 'cliq-sanitized-git-config-v1', core,
    ...(core.repositoryFormatVersion === 1 ? { extensions: { objectFormat } } : {}), configDigest: '' };
  config.configDigest = digestOmitting(config, 'configDigest');
  const gitConfigUtf8 = sanitizedGitConfigText(config);
  return immutableSnapshot({ objectFormat, config, gitConfigUtf8 });
}

/** Fixed helper serialization of an already closed-decoded sanitized config.
 * Callers cannot supply raw keys, includes, executable strings or paths. */
export function sanitizedGitConfigText(config: SanitizedGitConfigV1): string {
  const core = config.core;
  let text = `[core]\nrepositoryformatversion = ${core.repositoryFormatVersion}\nfilemode = ${core.fileMode}\nbare = false\n`;
  for (const [name, field] of booleans) if (field !== 'fileMode' && core[field] !== undefined) text += `${name} = ${core[field]}\n`;
  if (config.extensions) text += `[extensions]\nobjectformat = ${config.extensions.objectFormat}\n`;
  return text;
}
