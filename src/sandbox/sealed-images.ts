import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';

/** Own actual immutable seals, including their in-flight construction. This
 * retains resources, never validation results or execution authority. The
 * caller must join all borrowers before closing the set. */
export class SealedImages<T extends { close(): void }> {
  private readonly images = new Map<string, Promise<T>>();
  private closing: Promise<void> | undefined;

  get(key: string, create: () => Promise<T>): Promise<T> {
    if (this.closing) throw new KernelStorageError('LEASE_FENCED', 'sealed image owner is closed');
    const existing = this.images.get(key); if (existing) return existing;
    const opening = (async () => create())().catch(error => {
      // Only a construction failure with fully retired resources is retryable.
      // Uncertain retirement remains owned and visible to close().
      if (!(error instanceof ResourceRetirementError) && this.images.get(key) === opening) this.images.delete(key);
      throw error;
    });
    this.images.set(key, opening); return opening;
  }

  close(): Promise<void> {
    return this.closing ??= (async () => {
      const failures: unknown[] = [];
      for (const opening of this.images.values()) {
        let image: T;
        try { image = await opening; }
        catch (error) { if (error instanceof ResourceRetirementError) failures.push(error); continue; }
        try { image.close(); } catch (error) { failures.push(error); }
      }
      this.images.clear();
      if (failures.length) throw new ResourceRetirementError('sealed images did not retire', new AggregateError(failures));
    })();
  }
}
