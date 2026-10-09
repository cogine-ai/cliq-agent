#ifndef CLIQ_WORKER_PROTOCOL_H
#define CLIQ_WORKER_PROTOCOL_H

/* Private, installed-image-pinned descriptor protocol. Not a control wire or
 * durable artifact schema. The trusted TypeScript launcher decodes the exact
 * retained RFC artifacts before constructing one of these closed commands. */
#include <stdint.h>

#define CLIQ_WORKER_MAGIC UINT32_C(0x43575131)
#define CLIQ_WORKER_VERSION UINT32_C(1)
#define CLIQ_WORKER_MAX_SCOPES 16
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
    CLIQ_TERMINATE_RETAINED = 11
};

struct cliq_worker_packet {
    uint32_t magic;
    uint32_t version;
    uint32_t command;
    uint32_t scope;
    uint32_t parent;
    uint32_t status;
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
    uint64_t pid_namespace_inode;
    int64_t pid;
    int64_t namespace_init_pid;
    int64_t subreaper_pid;
    int64_t monitor_pid;
    uint32_t exit_status;
    uint32_t populated;
    uint32_t remaining_descendants;
    uint32_t init_reaped;
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
};

#endif
