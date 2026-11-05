#ifndef CLIQ_MCP_HTTP_ADMIN_INPUT_BRIDGE_H
#define CLIQ_MCP_HTTP_ADMIN_INPUT_BRIDGE_H
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#define CLIQ_MCP_ADMIN_INPUT_ABI 2u
#define CLIQ_MCP_ADMIN_BIRTH_MAGIC UINT32_C(0x434d4231)
#if defined(NAPI_VERSION)
static const napi_type_tag CLIQ_MCP_ADMIN_INPUT_TAG = { UINT64_C(0x1890b2da9fec4cd6), UINT64_C(0xadc24a573badf1fe) };
static const napi_type_tag CLIQ_MCP_ADMIN_RETAINED_INPUT_TAG = { UINT64_C(0x7b30bb84d19846ad), UINT64_C(0x815fd934da75cd4a) };
static const napi_type_tag CLIQ_MCP_ADMIN_ABSENT_INPUT_TAG = { UINT64_C(0xf4100084859c4935), UINT64_C(0x83ff35d9823ecc01) };
#endif
struct cliq_mcp_admin_directory { uint64_t device, inode, uid, gid, mode; };
struct cliq_mcp_admin_birth {
    uint32_t magic, version;
    struct cliq_mcp_admin_directory state_root, runtime, admin_parent, birth;
    int64_t supervisor_pid;
    char supervisor_start_token[192], operation[257], principal[257], nonce[65];
    char target_ref[65], target_digest[65], core_ref[65], core_digest[65], plan_ref[65], plan_digest[65], spec_ref[65], spec_digest[65];
    uint64_t attempt;
    unsigned char digest[32];
};
struct cliq_mcp_admin_input {
    uint32_t abi_version; pid_t creator_pid; void *environment;
    atomic_bool closed, execution_claimed, execution_joined;
    int birth_fd; struct stat birth_identity;
    struct cliq_mcp_admin_birth binding;
    bool (*assert_current)(struct cliq_mcp_admin_input *);
    int (*retire)(struct cliq_mcp_admin_input *);
    /* Same original StateOwner only, after actual input close. Reopens and
     * completely compares its original birth; no execution/cleanup power. */
    bool (*assert_retired_snapshot)(struct cliq_mcp_admin_input *, const unsigned char *, size_t);
};
#endif
