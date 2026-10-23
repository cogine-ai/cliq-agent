// Publisher construction only. This layout grants no runtime authority.
export const GUEST_IMAGE_MAX_BYTES = 268_435_456;
const reserveBytes = 16_777_216, alignmentBytes = 16_777_216;

/** All measured file bytes remain present. mke2fs must still actually fit
 * their complete tree; this reserve is not permission to omit or grow it.
 * @param {number} contentBytes
 * @param {'compact' | 'qualification_max'} [kind]
 */
export function guestImageLayout(contentBytes, kind = 'compact') {
  if (!Number.isSafeInteger(contentBytes) || contentBytes < 1 || contentBytes > GUEST_IMAGE_MAX_BYTES - reserveBytes ||
      kind !== 'compact' && kind !== 'qualification_max') throw new TypeError('invalid fixed guest image layout');
  const imageByteCount = kind === 'qualification_max' ? GUEST_IMAGE_MAX_BYTES :
    Math.ceil((contentBytes + reserveBytes) / alignmentBytes) * alignmentBytes;
  return Object.freeze({ profile: 'cliq-guest-image-layout-v1', kind, contentBytes, reserveBytes, alignmentBytes, imageByteCount });
}
