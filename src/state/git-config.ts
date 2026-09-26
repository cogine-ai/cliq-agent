import { digestOmitting } from '../kernel/identity.js';
import type { SanitizedGitConfigV1 } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';

// inspectWorkspaceIdentity reads the same literal file with this bound.
const MAX_GIT_CONFIG_BYTES = 1024 * 1024;
const REQUIRED_CORE_KEYS = ['repositoryFormatVersion', 'fileMode', 'bare'] as const;
const OPTIONAL_CORE_KEYS = ['logAllRefUpdates', 'ignoreCase', 'precomposeUnicode'] as const;
const BOOLEAN_CORE_MEMBERS = new Map<string, string>([
  ['filemode', 'fileMode'], ['bare', 'bare'], ['logallrefupdates', 'logAllRefUpdates'],
  ['ignorecase', 'ignoreCase'], ['precomposeunicode', 'precomposeUnicode']
]);

function mismatch(reason: string): never {
  throw new KernelStorageError('ARTIFACT_MISMATCH', `Git config ${reason}`);
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const keys = Object.keys(value);
  return required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => required.includes(key) || optional.includes(key));
}

/** Recheck the exact typed, non-executable config projection after CAS readback. */
export function decodeSanitizedGitConfig(value: unknown): SanitizedGitConfigV1 {
  if (!record(value) || !exactKeys(value, ['schemaVersion', 'format', 'core', 'configDigest'], ['extensions']) ||
      value.schemaVersion !== 1 || value.format !== 'cliq-sanitized-git-config-v1' || !record(value.core) ||
      !exactKeys(value.core, REQUIRED_CORE_KEYS, OPTIONAL_CORE_KEYS) ||
      (Object.hasOwn(value, 'extensions') && value.extensions === undefined)) {
    mismatch('has an invalid closed schema');
  }
  const core = value.core;
  if ((core.repositoryFormatVersion !== 0 && core.repositoryFormatVersion !== 1) ||
      typeof core.fileMode !== 'boolean' || core.bare !== false ||
      OPTIONAL_CORE_KEYS.some((key) => Object.hasOwn(core, key) && typeof core[key] !== 'boolean')) {
    mismatch('contains an unsupported core value');
  }
  if (value.extensions !== undefined &&
      (!record(value.extensions) || !exactKeys(value.extensions, ['objectFormat']) ||
       (value.extensions.objectFormat !== 'sha1' && value.extensions.objectFormat !== 'sha256') ||
       core.repositoryFormatVersion !== 1)) {
    mismatch('contains an unsupported extension');
  }
  if (typeof value.configDigest !== 'string' || !/^[0-9a-f]{64}$/u.test(value.configDigest) ||
      digestOmitting(value, 'configDigest') !== value.configDigest) {
    mismatch('digest does not rehash');
  }
  return value as SanitizedGitConfigV1;
}

/** Accept only the strict Git config syntax needed for the closed allowlist.
 * No includes, subsections, escapes, implicit booleans, or ambient Git reader. */
export function parseSanitizedGitConfig(bytes: Uint8Array): SanitizedGitConfigV1 {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_GIT_CONFIG_BYTES) {
    mismatch('has invalid raw bytes or exceeds the 1 MiB bound');
  }
  const stableBytes = Buffer.from(bytes);
  if (stableBytes.includes(0) ||
      (stableBytes[0] === 0xef && stableBytes[1] === 0xbb && stableBytes[2] === 0xbf)) {
    mismatch('has invalid raw bytes or exceeds the 1 MiB bound');
  }
  let source: string;
  try { source = new TextDecoder('utf-8', { fatal: true }).decode(stableBytes); }
  catch { mismatch('is not UTF-8'); }
  const core: Record<string, unknown> = {};
  const extensions: Record<string, unknown> = {};
  const seen = new Set<string>();
  let section: 'core' | 'extensions' | undefined;
  for (let cursor = 0; cursor < source.length;) {
    const newline = source.indexOf('\n', cursor);
    let rawLine = newline < 0 ? source.slice(cursor) : source.slice(cursor, newline);
    cursor = newline < 0 ? source.length : newline + 1;
    if (newline >= 0 && rawLine.endsWith('\r')) rawLine = rawLine.slice(0, -1);
    if (rawLine.includes('\r')) mismatch('has a bare carriage return');
    if (/^[ \t]*(?:[#;].*)?$/u.test(rawLine)) continue;
    const header = /^[ \t]*\[([A-Za-z]+)\][ \t]*$/u.exec(rawLine);
    if (header) {
      const name = header[1]!.toLowerCase();
      if (name !== 'core' && name !== 'extensions') mismatch(`has unsupported section ${name}`);
      section = name;
      continue;
    }
    const assignment = /^[ \t]*([A-Za-z][A-Za-z0-9]*)[ \t]*=[ \t]*([A-Za-z0-9]+)[ \t]*$/u.exec(rawLine);
    if (!section || !assignment) mismatch('uses unsupported syntax');
    const key = assignment[1]!.toLowerCase();
    const value = assignment[2]!;
    const identity = `${section}.${key}`;
    if (seen.has(identity)) mismatch(`repeats ${identity}`);
    seen.add(identity);
    if (section === 'core') {
      if (key === 'repositoryformatversion') {
        if (value !== '0' && value !== '1') mismatch('has unsupported repository format version');
        core.repositoryFormatVersion = Number(value);
      } else {
        const member = BOOLEAN_CORE_MEMBERS.get(key);
        if (!member || !/^(?:true|false)$/iu.test(value)) mismatch(`has unsupported core key or value ${key}`);
        core[member] = value.toLowerCase() === 'true';
      }
    } else {
      if (key !== 'objectformat' || (value !== 'sha1' && value !== 'sha256')) {
        mismatch(`has unsupported extension ${key}`);
      }
      extensions.objectFormat = value;
    }
  }
  const artifact = {
    schemaVersion: 1, format: 'cliq-sanitized-git-config-v1', core,
    ...(Object.keys(extensions).length ? { extensions } : {}), configDigest: ''
  };
  artifact.configDigest = digestOmitting(artifact, 'configDigest');
  return decodeSanitizedGitConfig(artifact);
}
