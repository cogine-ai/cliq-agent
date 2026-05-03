import type { RuntimeEventEnvelope } from './contract.js';

export function writeJsonlEvent(
  event: RuntimeEventEnvelope,
  write: (chunk: string) => void = (chunk) => {
    process.stdout.write(chunk);
  }
) {
  write(`${JSON.stringify(event)}\n`);
}
