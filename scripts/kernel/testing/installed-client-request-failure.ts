// Fixed inert error observation only. No message, cause, user request or path.
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeInstalledRequestFailure, type InstalledRequestFailure } from '../../../src/state/installed-request-diagnostics.js';

export const INSTALLED_REQUEST_FAILURE_PREFIX = 'CLIQ_INSTALLED_CLIENT_REQUEST_FAILURE_V1:';
export function installedRequestFailureMarker(value: InstalledRequestFailure): Buffer {
  const checked = decodeInstalledRequestFailure(value);
  const bytes = Buffer.concat([Buffer.from(INSTALLED_REQUEST_FAILURE_PREFIX), canonicalJsonBytes(checked), Buffer.from('\n')]);
  if (bytes.length > 512) throw new TypeError('fixed request failure marker exceeds its bound');
  return bytes;
}
export function decodeInstalledRequestFailureMarker(bytes: Buffer): InstalledRequestFailure {
  if (!Buffer.isBuffer(bytes) || bytes.length > 512 || bytes.at(-1) !== 10 ||
      bytes.subarray(0, INSTALLED_REQUEST_FAILURE_PREFIX.length).toString('ascii') !== INSTALLED_REQUEST_FAILURE_PREFIX)
    throw new TypeError('invalid fixed request failure marker');
  const payload = bytes.subarray(INSTALLED_REQUEST_FAILURE_PREFIX.length, -1);
  const checked = decodeInstalledRequestFailure(parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payload)));
  if (!installedRequestFailureMarker(checked).equals(bytes)) throw new TypeError('noncanonical fixed request failure marker');
  return checked;
}
