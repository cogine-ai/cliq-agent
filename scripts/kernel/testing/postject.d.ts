// The pinned postject package exports JavaScript without declarations.
declare module 'postject' {
  export function inject(filename: string, resourceName: string, resourceData: Buffer,
    options?: Readonly<{ machoSegmentName?: string; overwrite?: boolean; sentinelFuse?: string }>): Promise<void>;
}
