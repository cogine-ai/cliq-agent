/** Conservative caseless spelling shared by producers and retained-tree
 * validation. Expanding before lowering also catches sharp-s and final sigma;
 * NFC catches composed spelling aliases. Literal reads remain byte-exact. */
export function sourcePathCollisionKey(value: string): string {
  return value.toUpperCase().toLowerCase().normalize('NFC');
}
