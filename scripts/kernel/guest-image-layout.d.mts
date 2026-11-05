export const GUEST_IMAGE_MAX_BYTES: 268435456;
export function guestImageLayout(contentBytes: number, kind?: 'compact' | 'qualification_max'): Readonly<{
  profile: 'cliq-guest-image-layout-v1'; kind: 'compact' | 'qualification_max'; contentBytes: number;
  reserveBytes: number; alignmentBytes: number; imageByteCount: number;
}>;
