import { KernelStorageError } from '../state/errors.js';

/** The signed endpoint is literal; an alias would change its authority identity. */
export function assertControlSocketPath(stateRoot: string): void {
  // sockaddr_un.sun_path includes a trailing NUL. Darwin has 104 bytes; Linux has 108.
  const maxPathBytes = process.platform === 'darwin' ? 103 : 107;
  const socketPathBytes = Buffer.byteLength(`${stateRoot}/runtime/control-v1.sock`, 'utf8');
  if (socketPathBytes > maxPathBytes) {
    throw new KernelStorageError('INVALID_REQUEST',
      `StateRoot path is too long for the Unix control socket (${socketPathBytes} > ${maxPathBytes} bytes)`);
  }
}
