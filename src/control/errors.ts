import type { InstalledControlFeature, InstalledControlResponseFor } from './v1.js';
export class ControlRefusal extends Error {
  constructor(readonly response: Extract<InstalledControlResponseFor<InstalledControlFeature>, { ok: false }>) {
    super('installed Supervisor refused the request'); this.name = 'ControlRefusal';
  }
}
