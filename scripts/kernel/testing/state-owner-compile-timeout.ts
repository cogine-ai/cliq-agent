// Compiling the full StateOwner translation unit under emulation can exceed
// the ordinary host allowance. This bound applies only to qualification builds.
export const STATE_OWNER_QUALIFICATION_COMPILE_TIMEOUT_MS = 8 * 60_000;
