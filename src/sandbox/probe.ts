export type ExecutionBackendFailureCode =
  | 'UNSUPPORTED_PLATFORM'
  | 'UNSUPPORTED_EXECUTION_IDENTITY';

export type ExecutionBackendQualificationFailure = {
  ok: false;
  authorityReady: false;
  observedPlatform: NodeJS.Platform;
  error: {
    code: ExecutionBackendFailureCode;
    message: string;
  };
};

/**
 * The Kernel may only mint an execution capability after the complete real
 * deny/allow, descendant-containment, signed-runtime, and death-evidence probe
 * succeeds. There is deliberately no injectable adapter or success factory in
 * this initial seam: a mock, binary-presence check, or caller assertion must
 * never become production Run authority.
 *
 * The signed macOS microVM helper/guest and Linux namespace+cgroup launcher do
 * not exist in the repository yet, so every supported host currently fails
 * closed. A later implementation must add the native probe and an opaque
 * process-lifetime capability in this module before this result can become a
 * success union.
 */
export async function qualifyExecutionBackend(): Promise<ExecutionBackendQualificationFailure> {
  const observedPlatform = process.platform;
  if (observedPlatform !== 'darwin' && observedPlatform !== 'linux') {
    return {
      ok: false,
      authorityReady: false,
      observedPlatform,
      error: {
        code: 'UNSUPPORTED_PLATFORM',
        message: `Cliq Kernel Run execution is unsupported on ${observedPlatform}.`
      }
    };
  }

  const backend =
    observedPlatform === 'darwin'
      ? 'signed macOS microVM'
      : 'Linux namespace, cgroup v2, and trusted subreaper';
  return {
    ok: false,
    authorityReady: false,
    observedPlatform,
    error: {
      code: 'UNSUPPORTED_EXECUTION_IDENTITY',
      message: `The real ${backend} probe is not implemented; Run authority remains disabled.`
    }
  };
}
