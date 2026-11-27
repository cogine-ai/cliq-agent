#ifndef CLIQ_DEPENDENCY_OWNER_BRIDGE_H
#define CLIQ_DEPENDENCY_OWNER_BRIDGE_H
/* Same-process purpose-specific friend ABI. Only the two selected native
 * factories write these function tables. JavaScript never supplies a pointer,
 * FD, process observation, callback or completion bit. Check the N-API tag,
 * ABI and creator before reading any remaining layout. All calls are on the
 * original main event thread; the GIO worker never calls WorkerAddon code. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include "worker-protocol.h"
#define CLIQ_DEPENDENCY_OWNER_ABI 1u
#define CLIQ_DEPENDENCY_BINDING_ID_BYTES 257u
#if defined(NAPI_VERSION)
static const napi_type_tag CLIQ_DEPENDENCY_OWNER_TAG = {
    UINT64_C(0x679d81544c8d4164), UINT64_C(0xacba5c19973d408b)
};
#endif
struct cliq_dependency_binding {
    char run[CLIQ_DEPENDENCY_BINDING_ID_BYTES], op[CLIQ_DEPENDENCY_BINDING_ID_BYTES];
    char dispatch[CLIQ_DEPENDENCY_BINDING_ID_BYTES], supervisor[CLIQ_DEPENDENCY_BINDING_ID_BYTES];
    char request_ref[65], request_digest[65], target_ref[65], target_digest[65], grant_ref[65], token_digest[65];
    uint64_t attempt, sequence, owner_epoch, lease_epoch;
};
struct cliq_dependency_process_observation {
    /* death_joined is the original scope's complete containment/reader join.
     * It does not assert retained output FDs have been acknowledged. */
    bool result_available, death_joined, result_acknowledged, result_custody_retired;
    /* 0 none, 1 acknowledged, 2 controller_joined. A local drop does not
     * claim a post-commit ACK or successful SQL consumption. */
    uint32_t result_custody_origin;
    struct cliq_worker_packet packet;
};
struct cliq_dependency_process_peer {
    void *context;
    int (*cancel)(void *); /* 0 pending, 1 request recorded, -1 uncertainty */
    int (*poll_joined)(void *, struct cliq_dependency_process_observation *);
    int (*release_execution)(void *, const struct cliq_dependency_binding *);
    int (*begin_output_ack)(void *);
    int (*poll_output_ack)(void *);
    void (*release)(void *); /* genuine peer borrow only, after real join */
};
struct cliq_dependency_package_inputs { int fd; uint64_t bytes; char digest[65]; };
struct cliq_dependency_owner {
    uint32_t abi_version; pid_t creator_pid; void *environment;
    /* Only owner factory changes these immutable values before publication. */
    struct cliq_dependency_binding binding;
    char plan_digest[65], sandbox_launch_spec_ref[65], descriptor_sequence_digest[65];
    uint32_t package_count;
    atomic_bool closing, unsafe, fence_retained, worker_claimed, worker_joined;
    int (*assert_current)(struct cliq_dependency_owner *);
    int (*acquire_worker)(struct cliq_dependency_owner *, const struct cliq_dependency_binding *,
        const char *plan_digest, const char *sandbox_launch_spec_ref, const struct cliq_dependency_process_peer *);
    int (*borrow_package_inputs)(struct cliq_dependency_owner *, struct cliq_dependency_package_inputs *);
};
#endif
