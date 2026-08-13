import process from 'node:process';

import {
  qualifyExecutionBackend,
  type ExecutionBackendQualification
} from '../../src/sandbox/probe.js';

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function printResult(result: ExecutionBackendQualification): void {
  if (!result.ok) {
    process.stderr.write(`${JSON.stringify(result)}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    `${JSON.stringify({
      ok: result.ok,
      authorityReady: result.authorityReady,
      backend: result.backend,
      fingerprint: result.capability.fingerprint,
      observations: result.observations
    })}\n`
  );
}

const backend = process.argv[2];
if (backend === 'macos') {
  printResult(
    await qualifyExecutionBackend({
      backend: 'macos_vm',
      bundlePath: requiredEnvironment('CLIQ_MACOS_PROBE_BUNDLE'),
      expectedManifestDigest: requiredEnvironment('CLIQ_MACOS_PROBE_MANIFEST_DIGEST'),
      scratchRoot: requiredEnvironment('CLIQ_MACOS_PROBE_SCRATCH_ROOT')
    })
  );
} else if (backend === 'linux') {
  printResult(
    await qualifyExecutionBackend({
      backend: 'linux_namespace',
      installationRoot: requiredEnvironment('CLIQ_LINUX_PROBE_INSTALLATION'),
      expectedManifestDigest: requiredEnvironment('CLIQ_LINUX_PROBE_MANIFEST_DIGEST'),
      cgroupParent: requiredEnvironment('CLIQ_LINUX_PROBE_CGROUP_PARENT'),
      scratchRoot: requiredEnvironment('CLIQ_LINUX_PROBE_SCRATCH_ROOT'),
      workspacePath: requiredEnvironment('CLIQ_LINUX_PROBE_WORKSPACE'),
      stateRootPath: requiredEnvironment('CLIQ_LINUX_PROBE_STATE_ROOT'),
      homePath: requiredEnvironment('CLIQ_LINUX_PROBE_HOME')
    })
  );
} else {
  throw new Error('usage: qualify-execution-backend.ts macos|linux');
}
