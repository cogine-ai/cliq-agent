/** Fixed native implementation contract. Retained manifest validation and
 * installation selection belong to StateOwner, not to these data types. */
export const GUEST_EXTRACTOR_RECIPE = Object.freeze({
  entryId: 'linux_guest_extractor', version: '1',
  relativePath: 'native/linux-x64/linux-guest-extractor.node',
  maxImageBytes: 268_435_456, maxPinnedExecutables: 32, maxMappedFiles: 32,
} as const);

/** Fixed Node test subset, not an automatic enlargement of caller limits. */
export const LINUX_VERIFIER_RESOURCE_MINIMUMS = Object.freeze({ maxProcesses: 32 } as const);

export type NativeGuestExtractionInput = Readonly<{
  imageDigest: string;
  imageByteCount: number;
  nodePath: string;
  nodeDigest: string;
  architecture: 'x86_64';
  pinnedExecutables: readonly Readonly<{ path: string; digest: string }>[];
}>;

export type GuestToolchainDescription = Readonly<{
  imageDigest: string;
  nodePath: string;
  nodeDigest: string;
  files: readonly Readonly<{ path: string; digest: string; byteCount: number }>[];
}>;

/** N-API-tagged original owner, never a structural file-descriptor list.
 * pollReady is observation only; close first revokes then joins the actual job.
 * A probe may inspect and close this owner but cannot retain execution rights. */
export type NativeGuestToolchain = Readonly<{
  pollReady(): boolean;
  describe(): GuestToolchainDescription;
  close(): Promise<void>;
}>;
declare const sourceGitToolchainBrand: unique symbol;
/** Separate N-API tag. An ordinary Node-only extraction is not this owner. */
export type NativeSourceGitToolchain = Readonly<{
  readonly [sourceGitToolchainBrand]: true;
  pollReady(): boolean;
  describe(): GuestToolchainDescription & Readonly<{ gitPath: string; gitDigest: string }>;
  close(): Promise<void>;
}>;

export type NativeGuestExtractorBinding = Readonly<{
  interfaceVersion: 1;
  /** Acquires its own descriptor synchronously; bounded copy/hash/seal and
   * parsing run inside this same cancellable, joinable native owner. */
  begin(imageFd: number, input: NativeGuestExtractionInput): NativeGuestToolchain;
  /** Fixed Node + /usr/bin/git dual-root extraction, with the same bounds. */
  beginSourceGit?(imageFd: number, input: NativeGuestExtractionInput): NativeSourceGitToolchain;
}>;
