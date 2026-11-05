import { KernelStorageError } from './errors.js';

/** One complete import audit's retained index budget. These counters bound
 * JavaScript records and original UTF-8 text; they are neither a physical
 * receipt nor a heap-size measurement. No per-file/page reset is available. */
export class OwnedImportRetainedDataBudget {
  private records = 0;
  private textBytes = 0;
  reserve(...texts: readonly string[]): void {
    const bytes = texts.reduce((total, text) => total + Buffer.byteLength(text), 0);
    if (++this.records > 65_536 || bytes > 33_554_432 - this.textBytes)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'owned import exceeds its complete retained-index profile');
    this.textBytes += bytes;
  }
}
