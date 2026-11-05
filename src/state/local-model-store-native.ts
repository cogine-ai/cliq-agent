/** Private same-image data owner. No descriptor, SQLite URI, executable path,
 * process launch, credential or native evidence factory escapes this shape. */
export type NativeLocalModelPackage = Readonly<{
  readManifest(): Buffer;
  captureInventory(expected: Buffer): Buffer;
  readSignature(reference: string): Buffer;
  /** Exactly one bounded 64 KiB read/copy/hash step of the original object. */
  copyObjectStep(reference: string): boolean;
  finish(): void;
  close(): void;
}>;
export type NativeLocalModelStore = Readonly<{
  assertHeld(): void;
  readSmallObject(reference: string): Buffer;
  publishSmallObject(reference: string, bytes: Buffer): void;
  openPackage(manifestPath: string): NativeLocalModelPackage;
  close(): void;
}>;
