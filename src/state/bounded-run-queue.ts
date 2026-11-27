import { assertRunConcurrency } from '../kernel/run-scheduling.js';

/** Only driver work is queued here. Retained worker capacity is independently
 * checked from SQLite inside the original preparation transaction. */
export class BoundedRunQueue {
  private active = 0;
  private readonly pending: Array<{ operation: () => Promise<void>; resolve(): void; reject(error: unknown): void }> = [];
  constructor(private readonly concurrency: number) { assertRunConcurrency(concurrency); }

  run(operation: () => Promise<void>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.pending.push({ operation, resolve, reject });
      this.pump();
    });
  }

  private pump(): void {
    while (this.active < this.concurrency && this.pending.length) {
      const task = this.pending.shift()!;
      this.active++;
      void Promise.resolve().then(task.operation).then(task.resolve, task.reject).then(() => {
        this.active--;
        this.pump();
      });
    }
  }
}
