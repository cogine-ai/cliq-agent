#ifndef CLIQ_WORKER_PROTOCOL_H
#define CLIQ_WORKER_PROTOCOL_H

/* Private, installed-image-pinned descriptor protocol. Not a control wire or
 * durable artifact schema. The trusted TypeScript launcher decodes the exact
 * retained RFC artifacts before constructing one of these closed commands. */
#include <stdint.h>

#define CLIQ_WORKER_MAGIC UINT32_C(0x43575131)
#define CLIQ_WORKER_VERSION UINT32_C(6)
#define CLIQ_WORKER_MAX_SCOPES 16
#define CLIQ_WORKER_MAX_FDS 40
#define CLIQ_WORKER_TOKEN_BYTES 192
#define CLIQ_WORKER_PATH_BYTES 4096
#define CLIQ_WORKER_CHANNEL_FD 3

enum cliq_worker_command {
    CLIQ_CONTROLLER_HELLO = 1,
    CLIQ_CREATE_WORKER = 2,
    CLIQ_ACTIVATE_WORKER = 3,
    CLIQ_CREATE_WRITE = 4,
    CLIQ_RELEASE_WRITE = 5,
    CLIQ_STOP_SCOPE = 6,
    CLIQ_STOP_CONTROLLER = 7,
    CLIQ_WORKER_READY = 8,
    CLIQ_WORKER_ACTIVATED = 9,
    CLIQ_WRITE_RESULT = 10,
    CLIQ_TERMINATE_RETAINED = 11,
    CLIQ_BIND_RESERVATION = 12,
    CLIQ_INSPECT_RESERVATION = 13,
    CLIQ_CREATE_VERIFIER = 14,
    CLIQ_RELEASE_VERIFIER = 15,
    CLIQ_POLL_VERIFIER = 16,
    CLIQ_VERIFIER_RESULT = 17,
    CLIQ_VERIFIER_SETUP = 18,
    CLIQ_SOURCE_RESERVE = 19,
    CLIQ_SOURCE_CREATE_BLOCKED = 20,
    CLIQ_SOURCE_RELEASE_CAPTURE = 21,
    CLIQ_SOURCE_POLL_SEALED = 22,
    CLIQ_SOURCE_SEALED = 23,
    CLIQ_SOURCE_CONTINUE_GIT = 24,
    CLIQ_SOURCE_POLL_RESULT = 25,
    CLIQ_SOURCE_RESULT = 26,
    CLIQ_SOURCE_STOP = 27,
    CLIQ_SOURCE_RETIRE = 28,
    CLIQ_SOURCE_CLEANUP_RETAINED = 29,
    CLIQ_PREPARATION_RESERVE = 30,
    CLIQ_PREPARATION_CLEANUP_RETAINED = 31,
    CLIQ_PREPARATION_FINISH = 32,
    CLIQ_PREPARATION_CANCEL = 33,
    CLIQ_SOURCE_CHECK_REGISTERED_ABSENT = 40
};

/* Private pre-READY diagnosis only. Never process, release, time or death
 * authority; successful replies must retain all-zero diagnostic fields. */
struct cliq_verifier_setup_observation {
    uint32_t stage;
    /* -2 means this wait did not call poll; otherwise its actual return. */
    int32_t poll_result;
    uint32_t poll_revents, poll_errno, elapsed_ms;
};

struct cliq_worker_packet {
    uint32_t magic;
    uint32_t version;
    uint32_t command;
    uint32_t scope;
    uint32_t parent;
    uint32_t status;
    struct cliq_verifier_setup_observation setup;
    uint64_t max_processes;
    uint64_t memory_bytes;
    uint64_t cpu_quota;
    uint64_t max_open_files;
    uint64_t max_file_bytes;
    uint64_t max_generation_bytes;
    uint64_t max_output_bytes;
    uint64_t generation_device;
    uint64_t generation_inode;
    uint64_t cgroup_inode;
    uint64_t cgroup_device;
    uint64_t reservation_device;
    uint64_t reservation_inode;
    uint64_t reservation_uid;
    uint64_t observed_at_ms;
    uint64_t pid_namespace_inode;
    int64_t pid;
    int64_t namespace_init_pid;
    int64_t subreaper_pid;
    int64_t monitor_pid;
    uint32_t exit_status;
    uint32_t populated;
    uint32_t remaining_descendants;
    uint32_t init_reaped;
    uint32_t reservation_observation;
    uint32_t verifier_reason, verifier_signal, verifier_errno;
    uint32_t stdout_truncated, stderr_truncated;
    uint64_t stdout_bytes, stderr_bytes, started_at_ms, duration_ms;
    char nonce[65];
    char activation_nonce[65];
    char start_token[CLIQ_WORKER_TOKEN_BYTES];
    char init_start_token[CLIQ_WORKER_TOKEN_BYTES];
    char init_native_start_token[CLIQ_WORKER_TOKEN_BYTES];
    char subreaper_start_token[CLIQ_WORKER_TOKEN_BYTES];
    char monitor_start_token[CLIQ_WORKER_TOKEN_BYTES];
    char cgroup_name[96];
    char executable_path[256];
    char relative_path[CLIQ_WORKER_PATH_BYTES];
    char plan_ref[65];
    char sandbox_launch_ref[65];
    char sandbox_launch_digest[65];
    char generation_ref[65];
    char pid_namespace_reservation[CLIQ_WORKER_TOKEN_BYTES];
    /* Closed source-attempt family. These are never Run/generation fields. */
    char source_inspection_id[44];
    char source_target_ref[65];
    char source_input_intent_ref[65];
    char source_exclude_grant_digest[65];
    uint32_t source_rule_present;
    uint64_t source_rule_bytes;
    char source_rule_digest[65];
    char source_snapshot_digest[65];
    uint64_t source_byte_count, source_entry_count, source_shard_count;
    uint64_t source_output_bytes[4];
    char source_output_digests[4][65];
    /* Disjoint preparing-owner family, never a source grant or active Run. */
    char preparation_input_intent_ref[65];
};

#endif
