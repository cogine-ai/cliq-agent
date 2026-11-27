#ifndef CLIQ_MCP_STDIO_INPUT_BRIDGE_H
#define CLIQ_MCP_STDIO_INPUT_BRIDGE_H
/* Purpose-specific physical custody only. No SQL grant, descriptor number or
 * structurally compatible object can reconstruct these native inputs. */
#include "mcp-http-admin-input-bridge.h"
#include <stddef.h>
#include <sys/types.h>
#define CLIQ_MCP_STDIO_RUN_INPUT_ABI 1u
#define CLIQ_MCP_STDIO_ADMIN_BIRTH_MAGIC UINT32_C(0x43534131)
#define CLIQ_MCP_STDIO_RUN_BIRTH_MAGIC UINT32_C(0x43535231)
#if defined(NAPI_VERSION)
static const napi_type_tag CLIQ_MCP_STDIO_ADMIN_INPUT_TAG = {UINT64_C(0x634c495153414d31), UINT64_C(0x9c586bb904ce7221)};
static const napi_type_tag CLIQ_MCP_STDIO_ADMIN_RETAINED_INPUT_TAG = {UINT64_C(0x634c495153414d32), UINT64_C(0x8e736db562cb4107)};
static const napi_type_tag CLIQ_MCP_STDIO_RUN_INPUT_TAG = {UINT64_C(0x634c495153525531), UINT64_C(0xb3c946d05c712d84)};
static const napi_type_tag CLIQ_MCP_STDIO_RUN_RETAINED_INPUT_TAG = {UINT64_C(0x634c495153525532), UINT64_C(0x819de6017ac943bb)};
static const napi_type_tag CLIQ_MCP_STDIO_RECOVERY_INPUT_TAG = {UINT64_C(0xa993a47d62fe40ad), UINT64_C(0x87be735a23d4c76a)};
static const napi_type_tag CLIQ_MCP_STDIO_RECOVERY_RETAINED_INPUT_TAG = {UINT64_C(0xc2737e1b239b4bc0), UINT64_C(0xb523031c9bc35fac)};
#endif
struct cliq_mcp_stdio_run_identity {
    uint64_t launch_attempt, lifecycle_seq, call_index, lease_epoch, owner_epoch, call_deadline_ms, launch_deadline_ms;
    char run[257], principal[257], launch_op[257], batch_item[257], call[257], worker_launch[257], supervisor[257];
    char nonce[65], registry_ref[65], manifest_digest[65], tool_request_ref[65], tool_request_digest[65];
    char launch_request_ref[65], launch_request_digest[65], target_ref[65], target_digest[65], grant_ref[65], grant_digest[65];
    char plan_ref[65], plan_digest[65], spec_ref[65], spec_digest[65];
};
struct cliq_mcp_stdio_run_birth {
    uint32_t magic, version;
    struct cliq_mcp_admin_directory state_root, runtime, private_parent, birth;
    int64_t supervisor_pid;
    char supervisor_start_token[192];
    struct cliq_mcp_stdio_run_identity identity;
    unsigned char digest[32];
};
_Static_assert(sizeof(struct cliq_mcp_stdio_run_identity) == 2832, "fixed stdio Run identity bytes");
_Static_assert(offsetof(struct cliq_mcp_stdio_run_birth, identity) == 368, "fixed stdio Run physical prefix");
_Static_assert(sizeof(struct cliq_mcp_stdio_run_birth) == 3232, "fixed stdio Run birth bytes");
struct cliq_mcp_stdio_run_input {
    uint32_t abi_version;
    pid_t creator_pid;
    void *environment;
    atomic_bool closed, execution_claimed, execution_joined;
    int birth_fd;
    struct stat birth_identity;
    struct cliq_mcp_stdio_run_birth binding;
    bool (*assert_current)(struct cliq_mcp_stdio_run_input *);
    int (*retire)(struct cliq_mcp_stdio_run_input *);
};
/* Exact closed recovery-inspection binding. No Run or Admin authority. */
#define CLIQ_MCP_STDIO_RECOVERY_INPUT_ABI 1u
#define CLIQ_MCP_STDIO_RECOVERY_BIRTH_MAGIC UINT32_C(0x43535052)
#define CLIQ_MCP_STDIO_RECOVERY_TEXT_FIELDS(X) \
    X(runId, 257) \
    X(principalId, 257) \
    X(probeKind, 15) \
    X(brokerDispatchId, 257) \
    X(inspectorSupervisorInstanceId, 257) \
    X(originalOpId, 257) \
    X(originalDispatchId, 257) \
    X(effectServerToolName, 129) \
    X(adapterExecutableId, 257) \
    X(profileId, 257) \
    X(statusOperationName, 129)
#define CLIQ_MCP_STDIO_RECOVERY_DIGEST_FIELDS(X) \
    X(previousWaitingSubjectRef, 65) \
    X(waitingSubjectRef, 65) \
    X(reconciliationSubjectDigest, 65) \
    X(probeNonceDigest, 65) \
    X(probeDispatchDigest, 65) \
    X(brokerRequestDigest, 65) \
    X(brokerTargetDigest, 65) \
    X(brokerFenceTokenDigest, 65) \
    X(originalInstanceIdentityRef, 65) \
    X(originalInstanceIdentityDigest, 65) \
    X(registryRevisionRef, 65) \
    X(registryManifestDigest, 65) \
    X(adapterRef, 65) \
    X(adapterDigest, 65) \
    X(adapterExecutableDigest, 65) \
    X(profileDigest, 65) \
    X(statusRequestTemplateRef, 65) \
    X(statusRequestTemplateDigest, 65) \
    X(statusRequestDigest, 65) \
    X(plannedContainmentRef, 65) \
    X(plannedContainmentDigest, 65) \
    X(sandboxLaunchSpecRef, 65) \
    X(sandboxLaunchSpecDigest, 65) \
    X(nonce, 65)
#define CLIQ_MCP_STDIO_RECOVERY_NUMBER_FIELDS(X) \
    X(probeOrdinal, 1) \
    X(probeStartedAtMs, 1) \
    X(probeDeadlineAtMs, 1) \
    X(inspectorStateOwnerEpoch, 1) \
    X(originalAttempt, 0) \
    X(originalDispatchJournalSeq, 1)
struct cliq_mcp_stdio_recovery_identity {
#define RECOVERY_DECLARE_TEXT(name, capacity) char name[capacity];
    CLIQ_MCP_STDIO_RECOVERY_TEXT_FIELDS(RECOVERY_DECLARE_TEXT)
    CLIQ_MCP_STDIO_RECOVERY_DIGEST_FIELDS(RECOVERY_DECLARE_TEXT)
#undef RECOVERY_DECLARE_TEXT
#define RECOVERY_DECLARE_NUMBER(name, minimum) uint64_t name;
    CLIQ_MCP_STDIO_RECOVERY_NUMBER_FIELDS(RECOVERY_DECLARE_NUMBER)
#undef RECOVERY_DECLARE_NUMBER
};
struct cliq_mcp_stdio_recovery_birth {
    uint32_t magic, version;
    struct cliq_mcp_admin_directory state_root, runtime, private_parent, birth;
    int64_t supervisor_pid;
    char supervisor_start_token[192];
    struct cliq_mcp_stdio_recovery_identity identity;
    unsigned char digest[32];
};
struct cliq_mcp_stdio_recovery_input {
    uint32_t abi_version;
    pid_t creator_pid;
    void *environment;
    atomic_bool closed, execution_claimed, execution_joined;
    int birth_fd;
    struct stat birth_identity;
    struct cliq_mcp_stdio_recovery_birth binding;
    bool (*assert_current)(struct cliq_mcp_stdio_recovery_input *);
    int (*retire)(struct cliq_mcp_stdio_recovery_input *);
};

#endif
