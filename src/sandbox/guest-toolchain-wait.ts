/** Observation only. The caller owns cancellation, native close/join and the
 * complete signed-image checks before and after extraction. */
export async function waitForGuestToolchainReady(poll: () => boolean, assertCurrent: () => void): Promise<void> {
  assertCurrent();
  for (;;) {
    const ready = poll();
    assertCurrent();
    if (ready) return;
    // Match the existing native-controller polling interval. An immediate
    // repeatedly runs synchronous identity checks alongside the producer.
    await new Promise<void>(resolve => setTimeout(resolve, 1));
  }
}
