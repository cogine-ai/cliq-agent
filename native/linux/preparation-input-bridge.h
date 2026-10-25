#ifndef CLIQ_PREPARATION_INPUT_BRIDGE_H
#define CLIQ_PREPARATION_INPUT_BRIDGE_H

/* Same-process friend ABI. These descriptors establish original ownership;
 * no generation/source payload is passed to the fixed CAS-only child. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#define CLIQ_PREPARATION_INPUT_ABI 1
#if defined(NAPI_VERSION)
static const napi_type_tag CLIQ_PREPARATION_INPUT_TAG = {
    UINT64_C(0xba038ea7122542b0), UINT64_C(0xa271fb20354bd1be)
};
static const napi_type_tag CLIQ_RETAINED_PREPARATION_INPUT_TAG = {
    UINT64_C(0x59a29da6d10141cc), UINT64_C(0x91bcfdc14528740d)
};
#endif
struct cliq_preparation_input {
    uint32_t abi_version;
    atomic_bool closed, execution_claimed, execution_joined;
    bool cleanup_only;
    uint64_t supervisor_pid;
    char supervisor_token[128];
    int generation_fd, reservation_fd;
    struct stat generation_identity, reservation_identity;
    char run_id[129], generation_id[44], launch_id[44], spawn_nonce[65], activation_nonce[65], creation_nonce[65], generation_ref[65], input_intent_ref[65];
    bool (*assert_current)(struct cliq_preparation_input *);
    int (*retire)(struct cliq_preparation_input *);
};
#endif
