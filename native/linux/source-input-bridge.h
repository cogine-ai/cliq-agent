#ifndef CLIQ_SOURCE_INPUT_BRIDGE_H
#define CLIQ_SOURCE_INPUT_BRIDGE_H

/* Same-process private ABI between the signed StateOwner and controller
 * addons. JS never receives a descriptor or a function pointer. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#define CLIQ_SOURCE_INPUT_ABI 2
#define CLIQ_SOURCE_BIRTH_VERSION 2
#define CLIQ_SOURCE_BIRTH_MAGIC UINT32_C(0x43534731)
#define CLIQ_SOURCE_CONTROLLER_MAGIC UINT32_C(0x43534331)
#if defined(NAPI_VERSION)
static const napi_type_tag CLIQ_SOURCE_INPUT_TAG = {
    UINT64_C(0x706d452db9914865), UINT64_C(0x8f18fd940936c6cb)
};
static const napi_type_tag CLIQ_RETAINED_SOURCE_INPUT_TAG = {
    UINT64_C(0xf8c59e3cbab445d5), UINT64_C(0xa7d8f42a9020e3b1)
};
static const napi_type_tag CLIQ_ABSENT_SOURCE_INPUT_TAG = {
    UINT64_C(0x1e65e10406114d4e), UINT64_C(0xb4dc006d8627e85f)
};
#endif

struct cliq_source_directory_identity { uint64_t device, inode, uid, gid, mode; };
struct cliq_source_birth {
    uint32_t magic, version;
    uint64_t staging_device, staging_inode, staging_gid, workspace_device, workspace_inode;
    uint64_t git_device, git_inode, owner_uid, birth_device, birth_inode;
    struct cliq_source_directory_identity state_root, runtime, source_parent;
    int64_t supervisor_pid;
    char supervisor_start_token[128];
    char inspection_id[44], staging_nonce[65], target_ref[65], input_intent_ref[65];
    unsigned char digest[32];
};
/* Same birth file, fixed source-only frame. It is issued by the exact live
 * controller receiver before reserve dispatch, not supplied by JavaScript. */
struct cliq_source_controller_birth {
    uint32_t magic, version;
    struct cliq_source_directory_identity root, parent, leaf;
    int64_t pid;
    char leaf_name[64], process_start_token[192];
    unsigned char source_header_digest[32], digest[32];
};

struct cliq_source_input {
    uint32_t abi_version;
    atomic_bool closed, execution_claimed, execution_joined;
    int root_fd, git_fd, birth_fd;
    struct stat root_identity, git_identity, birth_identity;
    struct cliq_source_birth binding;
    bool (*assert_current)(struct cliq_source_input *);
    int (*retire)(struct cliq_source_input *);
};

#endif
