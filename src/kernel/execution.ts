import type { ArtifactRef } from './types.js';

export type ProcessContainmentRef = ArtifactRef;

// Canonical retained execution artifacts from RFC sections 9.1 and 9.2.
// Their validation is not a substitute for native process or filesystem observation.

export type ProcessContainmentOwner =
  | {
      kind: 'worker_activation'
      runId: string
      intendedLeaseEpoch: number
      workerLaunchId: string
    }
  | {
      kind: 'run_invocation'
      runId: string
      intendedLeaseEpoch: number
      workerLaunchId: string
      opId: string
      attempt: number
      dispatchId: string
    }
  | {
      kind: 'admin_probe'
      adminOperationId: string
      attempt: number
      principalId: string
      method: 'mcp.register' | 'mcp.refresh'
      originalRequestDigest: string
      targetRef: ArtifactRef
      supervisorInstanceId: string
    }
  | {
      kind: 'local_inference_service'
      serviceId: string
      serviceLaunchId: string
      ownerPrincipalId: string
      serviceSpecRef: ArtifactRef
      supervisorInstanceId: string
    }
  | {
      kind: 'source_inspection'
      inspectionId: string
      attempt: 1
      principalId: string
      targetRef: ArtifactRef
      supervisorInstanceId: string
    }

export type SandboxRootImageV1 = {
  schemaVersion: 1
  format: 'cliq-sandbox-root-image-v1'
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  entryId: string
  entryVersion: string
  entryDigest: string
  protocol: 'cliq-fresh-empty-root-v1'
  filesystemKind: 'fresh_ephemeral_tmpfs'
  fixedDirectories: ['/home/cliq', '/tmp', '/work']
  ownerUid: number
  persistent: false
  networkConfiguration: 'none'
  imageDigest: string
}

export type GuestExecutableIdentity = {
  logicalName: string
  canonicalGuestPath: string
  digest: string
  version: string
}

export type GuestToolchainManifest = {
  schemaVersion: 1
  format: 'cliq-guest-toolchain-v1'
  guestImageRef: ArtifactRef
  guestImageDigest: string
  guestImageByteCount: number
  guestImageFormat: 'raw-ext4-v1'
  architecture: 'arm64' | 'x86_64'
  kernelAbi: string
  userspaceAbi: string
  worker: GuestExecutableIdentity
  shell: GuestExecutableIdentity
  git: GuestExecutableIdentity
  node: GuestExecutableIdentity
  packageManager?: GuestExecutableIdentity
  searchTools: readonly GuestExecutableIdentity[]
  verifiers: readonly GuestExecutableIdentity[]
  admittedExecutables: readonly GuestExecutableIdentity[]
  publisherKeyId: string
  manifestDigest: string
  signatureRef: ArtifactRef
}

export type ProcessContainmentPlanV1 = {
  schemaVersion: 1
  format: 'cliq-process-containment-plan-v1'
  owner: ProcessContainmentOwner
  filesystemBinding:
    | { kind: 'run-generation'; generationRef: ArtifactRef }
    | { kind: 'isolated-empty-root'; rootImageRef: ArtifactRef; rootImageDigest: string }
  parentContainmentRef?: ArtifactRef
  launchNonceDigest: string
  backend:
    | {
        kind: 'linux'
        cgroupPath: string
        cgroupNameReservationDigest: string
        pidNamespaceReservationId: string
        subreaperStartToken: string
      }
    | {
        kind: 'macos-vm'
        vmReservationId: string
        guestImageRef: ArtifactRef
        guestImageDigest: string
        guestBootNonceDigest: string
      }
  createdAt: string
  planDigest: string
}

export type SandboxRuntimeBindingV1 = {
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  sandboxBackend: 'linux_namespace' | 'macos_vm'
  toolchain:
    | { kind: 'none' }
    | {
        kind: 'guest_toolchain'
        guestToolchainManifestRef: ArtifactRef
        guestToolchainManifestDigest: string
        guestImageRef: ArtifactRef
        guestImageDigest: string
      }
  launcher: {
    executableId: string
    executableDigest: string
  }
  runtimeDigest: string
}

export type SandboxExecutableIdentityV1 =
  | {
      kind: 'runtime_bundle'
      runtimeBundleRef: ArtifactRef
      runtimeBundleManifestDigest: string
      executableId: string
      role: 'worker' | 'tool_adapter' | 'mcp_server' | 'local_inference' | 'platform_helper'
      executionPath: string
      executableDigest: string
    }
  | {
      kind: 'guest_toolchain'
      guestToolchainManifestRef: ArtifactRef
      guestToolchainManifestDigest: string
      toolId: string
      role: 'worker' | 'shell' | 'tool' | 'verifier' | 'package_manager' | 'search' | 'mcp_server'
      executionPath: string
      executableDigest: string
    }
  | {
      kind: 'workspace_script'
      purpose: 'verifier'
      workspaceIdentityDigest: string
      canonicalRootRelativePath: string
      scriptDigest: string
      interpreterIdentityRef: ArtifactRef
      interpreterIdentityDigest: string
    }

export type SandboxCapturedStdioV1 = {
  stdin: 'closed'
  stdout: 'captured'
  stderr: 'captured'
  extraFileDescriptors: 'authenticated_operation_channel_only'
}

export type SandboxProcessInvocationV1 =
  | {
      kind: 'worker_entrypoint'
      purpose: 'worker_activation'
      recipe: 'cliq-worker-entrypoint-v1'
      runtimeSource: 'launch_runtime'
      executableSource: 'launch_executable'
      argvSource: 'fixed_empty'
      cwdSource: 'generation_root'
      stdio: {
        stdin: 'closed'
        stdout: 'captured'
        stderr: 'captured'
        extraFileDescriptors: 'authenticated_worker_channel_only'
      }
    }
  | {
      kind: 'source_inspection'
      purpose: 'source_inspection'
      recipe: 'cliq-source-git-inspection-v1'
      targetRef: ArtifactRef
      targetDigest: string
      inputRef: ArtifactRef
      inputDigest: string
      argvCwdSource: 'trusted_recipe_decode_of_frozen_source_input'
      stdio: SandboxCapturedStdioV1
    }
  | {
      kind: 'local_inference_entrypoint'
      purpose: 'local_inference_service'
      recipe: 'cliq-local-inference-entrypoint-v1'
      runtimeSource: 'launch_runtime'
      executableSource: 'launch_executable'
      modelManifestSource: 'service_spec'
      argvSource: 'trusted_recipe_decode_of_service_spec'
      cwdSource: 'isolated_root'
      stdio: SandboxCapturedStdioV1
    }
  | ({
      kind: 'run_request'
      requestRef: ArtifactRef
      requestDigest: string
      targetRef: ArtifactRef
      targetDigest: string
      argvCwdSource: 'trusted_recipe_decode_of_request_and_target'
    } & (
      | { purpose: 'tool'; recipe: 'cliq-tool-launch-v1'; stdio: SandboxCapturedStdioV1 }
      | { purpose: 'verifier'; recipe: 'cliq-verifier-command-v1'; stdio: SandboxCapturedStdioV1 }
      | {
          purpose: 'mcp_stdio'
          recipe: 'cliq-mcp-stdio-launch-v1'
          stdio: {
            stdin: 'mcp_framed'
            stdout: 'mcp_framed'
            stderr: 'captured'
            extraFileDescriptors: 'none'
          }
        }
      | { purpose: 'dependency'; recipe: 'cliq-dependency-launch-v1'; stdio: SandboxCapturedStdioV1 }
      | { purpose: 'publication'; recipe: 'cliq-publication-launch-v1'; stdio: SandboxCapturedStdioV1 }
    ))
  | ({
      kind: 'admin_probe'
      targetRef: ArtifactRef
      targetDigest: string
      probePayloadCoreRef: ArtifactRef
      argvCwdSource: 'trusted_recipe_decode_of_admin_target_and_probe_core'
    } & (
      | {
          purpose: 'admin_mcp_stdio_probe'
          recipe: 'cliq-admin-mcp-stdio-probe-v1'
          stdio: {
            stdin: 'mcp_framed'
            stdout: 'mcp_framed'
            stderr: 'captured'
            extraFileDescriptors: 'none'
          }
        }
      | {
          purpose: 'admin_mcp_http_probe'
          recipe: 'cliq-admin-mcp-http-probe-v1'
          stdio: SandboxCapturedStdioV1
        }
    ))

export type SanitizedSandboxEnvironmentV1 = {
  schemaVersion: 1
  format: 'cliq-sanitized-sandbox-environment-v1'
  controlledPath: string[]
  locale: { lang: string; lcAll: string }
  home: string
  tmpdir: string
  variables: Array<{ name: string; value: { kind: 'non_secret_literal'; value: string } }>
  inheritedHostEnvironment: false
  secretMaterial: 'none'
  brokerAccessAtSpawn: 'none'
  networkMode: 'none' | 'broker_ipc_only'
  environmentDigest: string
}

export type SandboxFilesystemV1 =
  | {
      kind: 'run_generation'
      generationRef: ArtifactRef
      access: 'preactivated_readonly' | 'read_only' | 'read_write'
      sourceProjectionRef: ArtifactRef
      independentGit: true
    }
  | {
      kind: 'isolated_empty_root'
      rootImageRef: ArtifactRef
      rootImageDigest: string
      persistentWritableMounts: false
    }

export type SandboxMountV1 =
  | {
      kind: 'cas_artifact'
      artifactRef: ArtifactRef
      artifactDigest: string
      targetPath: string
      access: 'read_only'
      purpose: 'runtime' | 'input' | 'executable'
    }
  | {
      kind: 'source_inspection_input'
      inputRef: ArtifactRef
      inputDigest: string
      targetPath: '/input'
      access: 'read_only'
      purpose: 'input'
    }
  | {
      kind: 'run_generation'
      generationRef: ArtifactRef
      canonicalRootRelativePath: string
      targetPath: string
      access: 'read_only' | 'read_write'
      purpose: 'source' | 'dependency' | 'cache' | 'output'
    }
  | {
      kind: 'private_ephemeral'
      privateRootId: string
      targetPath: string
      access: 'read_write'
      purpose: 'home' | 'tmp' | 'dependency' | 'cache' | 'output'
    }

export type SandboxLaunchBaseV1 = {
  schemaVersion: 1
  format: 'cliq-sandbox-launch-v1'
  runtime: SandboxRuntimeBindingV1
  executable: SandboxExecutableIdentityV1
  environment: SanitizedSandboxEnvironmentV1
  filesystem: SandboxFilesystemV1
  mounts: SandboxMountV1[]
  mountsDigest: string
  sandboxProfileRef: ArtifactRef
  sandboxProfileDigest: string
  resources: SandboxResourceSpec
  resourcesDigest: string
  containmentPlanRef: ArtifactRef
  containmentPlanDigest: string
  createdAt: string
  launchSpecDigest: string
}

export type SandboxLaunchSpecV1 =
  | (SandboxLaunchBaseV1 & {
      owner: Extract<ProcessContainmentOwner, { kind: 'worker_activation' }>
      purpose: 'worker_activation'
      processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'worker_entrypoint' }>
      operationGrantRef?: never
      requestRef?: never
      requestDigest?: never
      targetRef?: never
      targetDigest?: never
      parentWorkerContainmentRef?: never
      adminTargetRef?: never
      adminTargetDigest?: never
      probePayloadCoreRef?: never
    })
  | (SandboxLaunchBaseV1 & {
      owner: Extract<ProcessContainmentOwner, { kind: 'run_invocation' }>
      purpose: 'tool' | 'verifier' | 'mcp_stdio' | 'dependency' | 'publication'
      processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'run_request' }>
      operationGrantRef: ArtifactRef
      requestRef: ArtifactRef
      requestDigest: string
      targetRef: ArtifactRef
      targetDigest: string
      parentWorkerContainmentRef: ArtifactRef
      adminTargetRef?: never
      adminTargetDigest?: never
      probePayloadCoreRef?: never
    })
  | (SandboxLaunchBaseV1 & {
      owner: Extract<ProcessContainmentOwner, { kind: 'admin_probe' }>
      purpose: 'admin_mcp_stdio_probe' | 'admin_mcp_http_probe'
      processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'admin_probe' }>
      adminTargetRef: ArtifactRef
      adminTargetDigest: string
      probePayloadCoreRef: ArtifactRef
      operationGrantRef?: never
      requestRef?: never
      requestDigest?: never
      targetRef?: never
      targetDigest?: never
      parentWorkerContainmentRef?: never
    })
  | (SandboxLaunchBaseV1 & {
      owner: Extract<ProcessContainmentOwner, { kind: 'source_inspection' }>
      purpose: 'source_inspection'
      processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'source_inspection' }>
      sourceInspectionTargetRef: ArtifactRef
      sourceInspectionTargetDigest: string
      sourceInspectionInputRef: ArtifactRef
      sourceInspectionInputDigest: string
      operationGrantRef?: never
      requestRef?: never
      requestDigest?: never
      targetRef?: never
      targetDigest?: never
      parentWorkerContainmentRef?: never
      adminTargetRef?: never
      adminTargetDigest?: never
      probePayloadCoreRef?: never
      serviceSpecRef?: never
      serviceSpecDigest?: never
    })
  | (SandboxLaunchBaseV1 & {
      owner: Extract<ProcessContainmentOwner, { kind: 'local_inference_service' }>
      purpose: 'local_inference_service'
      processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'local_inference_entrypoint' }>
      serviceSpecRef: ArtifactRef
      serviceSpecDigest: string
      operationGrantRef?: never
      requestRef?: never
      requestDigest?: never
      targetRef?: never
      targetDigest?: never
      parentWorkerContainmentRef?: never
      adminTargetRef?: never
      adminTargetDigest?: never
      probePayloadCoreRef?: never
    })

export type ProcessContainment = {
  schemaVersion: 1
  planRef: ArtifactRef
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  owner: ProcessContainmentOwner
  filesystemBinding:
    | { kind: 'run-generation'; generationRef: ArtifactRef }
    | { kind: 'isolated-empty-root'; rootImageRef: ArtifactRef; rootImageDigest: string }
  parentContainmentRef?: ArtifactRef
  launchNonceDigest: string
  backend:
    | {
            kind: 'linux'
            pidNamespaceReservationId: string
            pidNamespaceId: string
        cgroupPath: string
        cgroupId: string
        namespaceInitStartToken: string
        subreaperStartToken: string
      }
    | {
            kind: 'macos-vm'
            vmReservationId: string
            vmInstanceId: string
        vmProcessStartToken: string
        guestBootId: string
        guestImageRef: ArtifactRef
        guestImageDigest: string
      }
  createdAt: string
}

export type ProcessContainmentNoSpawnEvidenceV1 = {
  schemaVersion: 1
  kind: 'containment_plan_quiescent'
  planRef: ArtifactRef
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  owner: ProcessContainmentOwner
  launchNonceDigest: string
  inspectorSupervisorInstanceId: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  backend:
    | {
        kind: 'linux'
        cgroupPath: string
        cgroupObservation:
          | { kind: 'absent' }
          | { kind: 'empty'; cgroupId: string; populated: 0 }
        pidNamespaceObservation:
          | { kind: 'never_created'; pidNamespaceReservationId: string }
          | { kind: 'dead_reaped'; pidNamespaceReservationId: string; namespaceInitStartToken: string }
        subreaperStartToken: string
        matchingLaunchNonceProcessCount: 0
      }
    | {
        kind: 'macos-vm'
        vmReservationId: string
        vmObservation:
          | { kind: 'never_created' }
          | {
              kind: 'stopped_reaped'
              vmInstanceId: string
              vmProcessStartToken: string
              guestBootId?: string
            }
        matchingLaunchNonceProcessCount: 0
      }
  observedAt: string
  evidenceDigest: string
}

export type ProcessContainmentDeathEvidenceV1 = {
  schemaVersion: 1
  kind: 'containment_all_descendants_dead'
  containmentRef: ArtifactRef
  planRef: ArtifactRef
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  owner: ProcessContainmentOwner
  launchNonceDigest: string
  inspectorSupervisorInstanceId: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  backend:
    | {
        kind: 'linux'
        pidNamespaceReservationId: string
        pidNamespaceId: string
        cgroupPath: string
        cgroupId: string
        cgroupPopulated: 0
        namespaceInitStartToken: string
        namespaceInitDeadAndReaped: true
        subreaperStartToken: string
        remainingTrackedDescendants: 0
      }
    | {
        kind: 'macos-vm'
        vmReservationId: string
        vmInstanceId: string
        vmProcessStartToken: string
        vmProcessDeadAndReaped: true
        guestBootId: string
        guestRetired: true
      }
  observedAt: string
  evidenceDigest: string
}

export type SourceInspectionTargetV1 = {
  schemaVersion: 1
  format: 'cliq-source-inspection-target-v1'
  principalId: string
  method: 'run.submit'
  admissionKey: string
  admissionIntentDigest: string
  originalRequestRef: ArtifactRef
  originalRequestDigest: string
  sessionId: string
  expectedContextRevision: number
  workspaceIdentityRef: ArtifactRef
  workspaceIdentityDigest: string
  sourceReadGrantRefs: ArtifactRef[]
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  sandboxProfileRef: ArtifactRef
  sandboxProfileDigest: string
  targetDigest: string
}

export type SourceInspectionInputV1 = {
  schemaVersion: 1
  format: 'cliq-source-inspection-input-v1'
  inspectionId: string
  targetRef: ArtifactRef
  targetDigest: string
  repositoryIdentityDigest: string
  objectFormat: 'sha1' | 'sha256'
  entriesRef: ArtifactRef
  treeDigest: string
  inputDigest: string
}

export type SourceInspectionPlanV1 = {
  launchNonceDigest: string
  containmentPlanRef: ArtifactRef
  containmentPlanDigest: string
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  reservedBackendIdentity:
    | {
        kind: 'linux'
        cgroupPath: string
        cgroupId: string
        deviceId: string
        fileId: string
        ownerUid: number
        pidNamespaceReservationId: string
        subreaperStartToken: string
      }
    | {
        kind: 'macos-vm'
        vmReservationId: string
        guestImageRef: ArtifactRef
        guestImageDigest: string
        guestBootNonceDigest: string
        privateDisk: { deviceId: string; fileId: string; ownerUid: number; mode: 384; linkCount: 1; byteCount: number }
      }
}

export type SourceInspectionRetirementEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-source-inspection-retirement-v1'
  inspectionId: string
  targetRef: ArtifactRef
  stagingNonceDigest: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  captureOwnerClosure:
    | { kind: 'local_resources_joined'; stateOwnerEpoch: number; supervisorInstanceId: string }
    | { kind: 'owning_process_dead'; stateOwnerAcquisitionEvidenceRef: ArtifactRef }
  stagingObservation: 'exact_reserved_root_absent'
  processClosure:
    | { kind: 'not_planned' }
    | { kind: 'plan_quiescent'; noSpawnEvidenceRef: ArtifactRef }
    | { kind: 'all_descendants_dead'; processContainmentRef: ArtifactRef; deathEvidenceRef: ArtifactRef }
  observedAt: string
  evidenceDigest: string
}

export type SourceInspectionAttemptBaseV1 = {
  schemaVersion: 1
  inspectionId: string
  attempt: 1
  principalId: string
  method: 'run.submit'
  admissionKey: string
  admissionIntentDigest: string
  targetRef: ArtifactRef
  targetDigest: string
  workspaceIdentityDigest: string
  stateOwnerEpoch: number
  supervisorInstanceId: string
  stagingNonceDigest: string
  stagingIdentity: { deviceId: string; fileId: string; ownerUid: number; mode: 448 }
  cancelRequested: boolean
  rowVersion: number
  createdAt: string
  deadlineAt: string
  updatedAt: string
  rowDigest: string
}

export type SourceInspectionAttemptV1 = SourceInspectionAttemptBaseV1 & (
  | {
      phase: 'capturing'
      inputRef?: never
      inputDigest?: never
      plan?: never
      processContainmentRef?: never
      retirementEvidenceRef?: never
      retiredAt?: never
      outcome?: never
    }
  | {
      phase: 'prepared'
      inputRef: ArtifactRef
      inputDigest: string
      plan: SourceInspectionPlanV1
      processContainmentRef?: never
      retirementEvidenceRef?: never
      retiredAt?: never
      outcome?: never
    }
  | {
      phase: 'active'
      inputRef: ArtifactRef
      inputDigest: string
      plan: SourceInspectionPlanV1
      processContainmentRef: ArtifactRef
      retirementEvidenceRef?: never
      retiredAt?: never
      outcome?: never
    }
  | ({
      phase: 'retired'
      retirementEvidenceRef: ArtifactRef
      retiredAt: string
      outcome:
        | { kind: 'captured'; sourceManifestRef: ArtifactRef; sourceManifestDigest: string; privateGitStateRef?: ArtifactRef }
        | { kind: 'failed' | 'cancelled'; errorResponseRef: ArtifactRef }
    } & (
      | { inputRef?: never; inputDigest?: never; plan?: never; processContainmentRef?: never }
      | { inputRef: ArtifactRef; inputDigest: string; plan: SourceInspectionPlanV1; processContainmentRef?: never }
      | { inputRef: ArtifactRef; inputDigest: string; plan: SourceInspectionPlanV1; processContainmentRef: ArtifactRef }
    ))
)

export type SandboxResourceSpec = {
  maxProcesses: number       // default 256; range 1..1024
  memoryBytes: number        // default 4 GiB; range 256 MiB..32 GiB, host-clamped
  cpuQuotaMicrosPerSecond: number // default 400000; range 10000..1600000
  maxOpenFiles: number       // default 1024; range 64..8192
  maxSingleFileBytes: number // default 2 GiB; range 1 MiB..16 GiB
  maxGenerationBytes: number // default 20 GiB; range 256 MiB..100 GiB
  maxInvocationOutputBytes: number // default 16 MiB; range 64 KiB..64 MiB
  maxIpcFrameBytes: number   // fixed 16 MiB
  maxQueuedIpcBytes: number  // fixed 64 MiB per Run
}

export type SandboxProfileV1 = {
  schemaVersion: 1
  format: 'cliq-sandbox-profile-v1'
  backend: 'macos_vm' | 'linux_namespace'
  allowedOwners: Array<
    'worker_activation' | 'run_invocation' | 'admin_probe' | 'local_inference_service' | 'source_inspection'
  >
  filesystemPolicy: 'typed_launch_spec_only'
  hostFilesystemReachability: 'none'
  networkAtSpawn: 'none'
  networkAfterRelease: 'typed_broker_only'
  credentialReachability: 'typed_broker_only'
  stateRootReachability: 'none'
  inheritedHostEnvironment: false
  resources: SandboxResourceSpec
  profileDigest: string
}
