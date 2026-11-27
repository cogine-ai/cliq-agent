#ifndef CLIQ_SOURCE_GIT_PROTOCOL_H
#define CLIQ_SOURCE_GIT_PROTOCOL_H

#include "worker-protocol.h"
#include "source-input-bridge.h"
#include "worker-sha256.h"
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* A private projection, not durable source authorization. No argv, cwd,
 * environment, source path, numerical host descriptor or parent Run exists. */
#define CLIQ_SOURCE_CONFIG_MAGIC UINT32_C(0x43534732)
#define CLIQ_SOURCE_MAX_FILES 32
#define CLIQ_SOURCE_MAX_SHARDS 16
#define CLIQ_SOURCE_MAX_DEPTH 32
#define CLIQ_SOURCE_MAX_ENTRIES 100000
#define CLIQ_SOURCE_MAX_CONFIG UINT64_C(1048576)
#define CLIQ_SOURCE_PATH_BYTES 4096
#define CLIQ_SOURCE_OUTPUTS 4
#define CLIQ_SOURCE_TRANSFER_OUTPUTS 5
#define CLIQ_SOURCE_HISTORY_MAX_BYTES (sizeof(struct cliq_source_birth) + sizeof(struct cliq_source_controller_birth) + 12 * sizeof(struct cliq_source_birth_record))
#define CLIQ_SOURCE_HEADER_MAGIC UINT32_C(0x43535331)
/* Original signed empty-root profile. /home is the required parent of its
 * /home/cliq leaf; all four remain on the root's read-only mount. */
static const char *const cliq_source_profile_directories[] = { "/home", "/home/cliq", "/tmp", "/work" };

struct cliq_source_config {
    uint32_t magic, version, file_count, reserved;
    uint64_t inspector_bytes, init_bytes;
    char inspector_digest[65];
    char repository_identity_digest[65];
    struct {
        uint64_t byte_count;
        char path[CLIQ_SOURCE_PATH_BYTES];
        char digest[65];
    } files[CLIQ_SOURCE_MAX_FILES];
};
/* Local receive outcomes only, never packet/wire status or peer authority.
 * Distinguish transport refusals without exposing unauthenticated reply data. */
enum cliq_source_reply_outcome {
    CLIQ_SOURCE_REPLY_AUTHENTICATED_FAILURE = -1,
    CLIQ_SOURCE_REPLY_REQUEST_STATE = -2,
    CLIQ_SOURCE_REPLY_RECEIVE_FAILURE = -3,
    CLIQ_SOURCE_REPLY_FOREIGN = -4,
    CLIQ_SOURCE_REPLY_GENERIC_REFUSAL = -5
};
static inline uint32_t cliq_source_reply_failure_guard(int outcome) {
    switch (outcome) {
        case CLIQ_SOURCE_REPLY_REQUEST_STATE: return 4005;
        case CLIQ_SOURCE_REPLY_RECEIVE_FAILURE: return 4006;
        case CLIQ_SOURCE_REPLY_FOREIGN: return 4007;
        case CLIQ_SOURCE_REPLY_GENERIC_REFUSAL: return 4008;
        default: return 0;
    }
}

/* Post-READY failures on the original fixed channel are diagnostics only.
 * These finite values never admit a result/FD, death, time or permission.
 * 2101..2355 and 2401..2464 require a truly joined helper wait status;
 * 2501..2519 additionally require its actual exit70 and fixed exec-pipe int.
 * 2601..2634 name only the original output collector operation that failed;
 * the same zero-FD/request-only/actual-exit70 relay applies to every value. */
enum cliq_source_postready_failure {
    CLIQ_SOURCE_FAIL_INPUT = 2001, CLIQ_SOURCE_FAIL_INPUT_CLOSE = 2002,
    CLIQ_SOURCE_FAIL_SEAL_SEND = 2003, CLIQ_SOURCE_FAIL_CONTINUATION = 2004,
    CLIQ_SOURCE_FAIL_STORAGE = 2005, CLIQ_SOURCE_FAIL_DIRECTORIES = 2006,
    CLIQ_SOURCE_FAIL_MATERIALIZE = 2007, CLIQ_SOURCE_FAIL_METADATA_STORAGE = 2008,
    CLIQ_SOURCE_FAIL_INTENT = 2009, CLIQ_SOURCE_FAIL_HELPER = 2010,
    CLIQ_SOURCE_FAIL_OUTPUTS = 2011, CLIQ_SOURCE_FAIL_OUTPUT_BINDING = 2012,
    CLIQ_SOURCE_FAIL_RESULT_SEND = 2013, CLIQ_SOURCE_FAIL_INPUT_RETIREMENT = 2014,
    CLIQ_SOURCE_FAIL_MONITOR_JOIN = 2015, CLIQ_SOURCE_FAIL_MONITOR_EXIT = 2016,
    CLIQ_SOURCE_FAIL_EXEC = 2090, CLIQ_SOURCE_FAIL_HELPER_JOIN = 2091,
    CLIQ_SOURCE_OUTPUT_DIRECTORY = 2601, CLIQ_SOURCE_OUTPUT_SCAN = 2602,
    CLIQ_SOURCE_OUTPUT_SCAN_STREAM = 2603, CLIQ_SOURCE_OUTPUT_READ_DIRECTORY = 2604,
    CLIQ_SOURCE_OUTPUT_NAME = 2605, CLIQ_SOURCE_OUTPUT_SCAN_CLOSE = 2606,
    CLIQ_SOURCE_OUTPUT_COMPLETE_NAMES = 2607, CLIQ_SOURCE_OUTPUT_CAPACITY_FILE = 2608,
    CLIQ_SOURCE_OUTPUT_CAPACITY = 2609, CLIQ_SOURCE_OUTPUT_RESERVE = 2610,
    CLIQ_SOURCE_OUTPUT_REMOUNT = 2611, CLIQ_SOURCE_OUTPUT_FILESYSTEM = 2612,
    CLIQ_SOURCE_OUTPUT_USED = 2613, CLIQ_SOURCE_OUTPUT_OPEN = 2614,
    CLIQ_SOURCE_OUTPUT_STAT = 2615, CLIQ_SOURCE_OUTPUT_TYPE = 2616,
    CLIQ_SOURCE_OUTPUT_LINKS = 2617, CLIQ_SOURCE_OUTPUT_UID = 2618,
    CLIQ_SOURCE_OUTPUT_SIZE = 2619, CLIQ_SOURCE_OUTPUT_METADATA_SIZE = 2620,
    CLIQ_SOURCE_OUTPUT_TOTAL_SIZE = 2621, CLIQ_SOURCE_OUTPUT_WRITER = 2622,
    CLIQ_SOURCE_OUTPUT_READ = 2623, CLIQ_SOURCE_OUTPUT_WRITE = 2624,
    CLIQ_SOURCE_OUTPUT_EOF = 2625, CLIQ_SOURCE_OUTPUT_AFTER_STAT = 2626,
    CLIQ_SOURCE_OUTPUT_AFTER_IDENTITY = 2627, CLIQ_SOURCE_OUTPUT_NAMED_STAT = 2628,
    CLIQ_SOURCE_OUTPUT_NAMED_IDENTITY = 2629, CLIQ_SOURCE_OUTPUT_FILE_CLOSE = 2630,
    CLIQ_SOURCE_OUTPUT_SEAL = 2631, CLIQ_SOURCE_OUTPUT_WRITER_CLOSE = 2632,
    CLIQ_SOURCE_OUTPUT_DIRECTORY_CLOSE = 2633, CLIQ_SOURCE_OUTPUT_RETIREMENT = 2634
};
static inline bool cliq_source_postready_failure_valid(uint32_t status) {
    return (status >= CLIQ_SOURCE_FAIL_INPUT && status <= CLIQ_SOURCE_FAIL_MONITOR_EXIT) ||
        status == CLIQ_SOURCE_FAIL_EXEC || status == CLIQ_SOURCE_FAIL_HELPER_JOIN ||
        (status >= 2101 && status <= 2355) || (status >= 2401 && status <= 2464) || (status >= 2501 && status <= 2519) ||
        (status >= CLIQ_SOURCE_OUTPUT_DIRECTORY && status <= CLIQ_SOURCE_OUTPUT_RETIREMENT);
}
static inline uint32_t cliq_source_helper_failure(bool joined, int status, ssize_t bytes, int diagnostic) {
    if (!joined) return CLIQ_SOURCE_FAIL_HELPER_JOIN;
    if (bytes == (ssize_t)sizeof(diagnostic) && diagnostic >= -19 && diagnostic <= -1 &&
        WIFEXITED(status) && WEXITSTATUS(status) == 70) return (uint32_t)(2500 - diagnostic);
    if (bytes != 0) return CLIQ_SOURCE_FAIL_EXEC;
    if (WIFSIGNALED(status) && WTERMSIG(status) >= 1 && WTERMSIG(status) <= 64) return (uint32_t)(2400 + WTERMSIG(status));
    if (WIFEXITED(status)) return WEXITSTATUS(status) == 0 ? 0 : (uint32_t)(2100 + WEXITSTATUS(status));
    return CLIQ_SOURCE_FAIL_HELPER_JOIN;
}

/* Exact JCS literals accepted by the measured helper. All interpolated data
 * are already closed unsigned resource integers or a SHA-256 digest. */
static inline int cliq_fixed_git_intent_json(char *json, size_t capacity, const struct cliq_worker_packet *request,
    const struct cliq_source_config *config, bool preparation) {
    return snprintf(json, capacity,
        "{\"recipe\":\"%s\",\"repositoryIdentityDigest\":\"%s\",\"resources\":{"
        "\"cpuQuotaMicrosPerSecond\":%llu,\"maxGenerationBytes\":%llu,\"maxInvocationOutputBytes\":%llu,"
        "\"maxIpcFrameBytes\":16777216,\"maxOpenFiles\":%llu,\"maxProcesses\":%llu,\"maxQueuedIpcBytes\":67108864,"
        "\"maxSingleFileBytes\":%llu,\"memoryBytes\":%llu},\"schemaVersion\":1}",
        preparation ? "cliq-private-git-preparation-v1" : "cliq-source-git-inspection-v1", config->repository_identity_digest,
        (unsigned long long)request->cpu_quota, (unsigned long long)request->max_generation_bytes, (unsigned long long)request->max_output_bytes,
        (unsigned long long)request->max_open_files, (unsigned long long)request->max_processes,
        (unsigned long long)request->max_file_bytes, (unsigned long long)request->memory_bytes);
}

/* Stream framing is binary and paths are validated before use. Raw config
 * has its own kind and is never extracted into the Git input tree. */
enum cliq_source_entry_kind { CLIQ_SOURCE_DIRECTORY = 1, CLIQ_SOURCE_FILE = 2, CLIQ_SOURCE_CONFIG = 3, CLIQ_SOURCE_EXCLUDE = 4 };
struct cliq_source_entry_header {
    uint32_t magic, kind, path_bytes, mode;
    uint64_t byte_count;
};
struct cliq_source_birth_record {
    uint32_t step, kind;
    unsigned char previous[32];
    struct cliq_worker_packet packet;
    unsigned char digest[32];
};

static inline bool cliq_source_digest(const char *value) {
    if (strnlen(value, 65) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
    return true;
}
static inline bool cliq_source_directory_matches(const struct cliq_source_directory_identity *expected, const struct stat *actual) {
    return S_ISDIR(actual->st_mode) && expected->device == (uint64_t)actual->st_dev && expected->inode == (uint64_t)actual->st_ino &&
        expected->uid == (uint64_t)actual->st_uid && expected->gid == (uint64_t)actual->st_gid && expected->mode == (uint64_t)actual->st_mode;
}
static inline bool cliq_source_controller_name(const char *value) {
    if (strnlen(value, 64) != 43 || strncmp(value, "controller-", 11) != 0) return false;
    for (size_t i = 11; i < 43; i++) if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
    return true;
}
static inline bool cliq_source_positive_decimal(const char *value) {
    size_t length = strnlen(value, 21);
    if (!length || length > 20 || value[0] < '1' || value[0] > '9' ||
        (length == 20 && strcmp(value, "18446744073709551615") > 0)) return false;
    for (size_t i = 1; i < length; i++) if (value[i] < '0' || value[i] > '9') return false;
    return true;
}
static inline bool cliq_source_process_token_valid(const char *value) {
    const char prefix[] = "linux-proc-start-ticks:";
    return strncmp(value, prefix, sizeof(prefix) - 1) == 0 && cliq_source_positive_decimal(value + sizeof(prefix) - 1);
}
static inline bool cliq_source_namespace_token_valid(const char *value) {
    char init[11] = {0}, start[21] = {0}, monitor[11] = {0}, monitor_start[21] = {0}; int used = 0;
    return sscanf(value, "linux-namespace-init:%10[0-9]:%20[0-9]:monitor:%10[0-9]:%20[0-9]%n",
        init, start, monitor, monitor_start, &used) == 4 && used > 0 && value[used] == '\0' &&
        cliq_source_positive_decimal(init) && cliq_source_positive_decimal(start) &&
        cliq_source_positive_decimal(monitor) && cliq_source_positive_decimal(monitor_start) &&
        strtoull(init, NULL, 10) <= INT32_MAX && strtoull(monitor, NULL, 10) <= INT32_MAX;
}
static inline bool cliq_source_controller_frame_valid(const struct cliq_source_controller_birth *frame,
    const struct cliq_source_birth *header) {
    const char prefix[] = "linux-proc-start-ticks:";
    if (frame->magic != CLIQ_SOURCE_CONTROLLER_MAGIC || frame->version != 1 || frame->pid <= 0 || frame->pid > INT32_MAX ||
        !cliq_source_controller_name(frame->leaf_name) || strnlen(frame->process_start_token, sizeof(frame->process_start_token)) >= sizeof(frame->process_start_token) ||
        strncmp(frame->process_start_token, prefix, sizeof(prefix) - 1) != 0 || !frame->process_start_token[sizeof(prefix) - 1] ||
        memcmp(frame->source_header_digest, header->digest, 32) != 0) return false;
    for (const char *at = frame->process_start_token + sizeof(prefix) - 1; *at; at++) if (*at < '0' || *at > '9') return false;
    const struct cliq_source_directory_identity *directories[] = { &frame->root, &frame->parent, &frame->leaf };
    for (size_t i = 0; i < 3; i++) if (!directories[i]->device || !directories[i]->inode ||
        directories[i]->uid != header->owner_uid || directories[i]->gid > UINT32_MAX || directories[i]->mode != (S_IFDIR | 0700)) return false;
    unsigned char digest[32]; struct sha256_context hash; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)frame, offsetof(struct cliq_source_controller_birth, digest)); sha256_final(&hash, digest);
    return memcmp(digest, frame->digest, 32) == 0;
}
/* Actual first StateOwner identity is born with the source reservation. A
 * successor may verify these bytes but cannot replace them with today's PID. */
static inline bool cliq_source_birth_origin_valid(const struct cliq_source_birth *header) {
    const char prefix[] = "linux-proc-start-ticks:";
    if (header->magic != CLIQ_SOURCE_BIRTH_MAGIC || header->version != CLIQ_SOURCE_BIRTH_VERSION ||
        header->supervisor_pid <= 0 || header->supervisor_pid > INT32_MAX ||
        strnlen(header->supervisor_start_token, sizeof(header->supervisor_start_token)) >= sizeof(header->supervisor_start_token) ||
        strncmp(header->supervisor_start_token, prefix, sizeof(prefix) - 1) ||
        header->supervisor_start_token[sizeof(prefix) - 1] < '1' || header->supervisor_start_token[sizeof(prefix) - 1] > '9' ||
        !header->staging_inode || header->staging_gid > UINT32_MAX || !header->workspace_device || !header->workspace_inode ||
        !header->git_device || !header->git_inode || !header->birth_device || !header->birth_inode ||
        header->birth_device != header->staging_device) return false;
    if (strnlen(header->inspection_id, sizeof(header->inspection_id)) != 43 ||
        !cliq_source_digest(header->staging_nonce) || !cliq_source_digest(header->target_ref) || !cliq_source_digest(header->input_intent_ref)) return false;
    for (size_t i = 0; i < 43; i++) if (!((header->inspection_id[i] >= 'A' && header->inspection_id[i] <= 'Z') ||
        (header->inspection_id[i] >= 'a' && header->inspection_id[i] <= 'z') || (header->inspection_id[i] >= '0' && header->inspection_id[i] <= '9') ||
        header->inspection_id[i] == '_' || header->inspection_id[i] == '-')) return false;
    for (const char *at = header->supervisor_start_token + sizeof(prefix) - 1; *at; at++) if (*at < '0' || *at > '9') return false;
    const struct cliq_source_directory_identity *directories[] = { &header->state_root, &header->runtime, &header->source_parent };
    for (size_t i = 0; i < 3; i++) if (!directories[i]->device || !directories[i]->inode ||
        directories[i]->device != header->staging_device || directories[i]->uid != header->owner_uid ||
        directories[i]->gid > UINT32_MAX || directories[i]->mode != (S_IFDIR | 0700)) return false;
    struct cliq_source_birth canonical; memset(&canonical, 0, sizeof(canonical));
#define SOURCE_BIRTH_NUMBER(name) canonical.name = header->name
    SOURCE_BIRTH_NUMBER(magic); SOURCE_BIRTH_NUMBER(version); SOURCE_BIRTH_NUMBER(staging_device); SOURCE_BIRTH_NUMBER(staging_inode);
    SOURCE_BIRTH_NUMBER(staging_gid); SOURCE_BIRTH_NUMBER(workspace_device); SOURCE_BIRTH_NUMBER(workspace_inode);
    SOURCE_BIRTH_NUMBER(git_device); SOURCE_BIRTH_NUMBER(git_inode); SOURCE_BIRTH_NUMBER(owner_uid); SOURCE_BIRTH_NUMBER(supervisor_pid);
    SOURCE_BIRTH_NUMBER(birth_device); SOURCE_BIRTH_NUMBER(birth_inode);
    SOURCE_BIRTH_NUMBER(state_root); SOURCE_BIRTH_NUMBER(runtime); SOURCE_BIRTH_NUMBER(source_parent);
#undef SOURCE_BIRTH_NUMBER
#define SOURCE_BIRTH_TEXT(name) do { size_t n = strnlen(header->name, sizeof(header->name)); \
    if (n >= sizeof(header->name)) { return false; } memcpy(canonical.name, header->name, n); } while (0)
    SOURCE_BIRTH_TEXT(supervisor_start_token); SOURCE_BIRTH_TEXT(inspection_id); SOURCE_BIRTH_TEXT(staging_nonce);
    SOURCE_BIRTH_TEXT(target_ref); SOURCE_BIRTH_TEXT(input_intent_ref);
#undef SOURCE_BIRTH_TEXT
    memcpy(canonical.digest, header->digest, 32);
    return memcmp(&canonical, header, sizeof(canonical)) == 0;
}
static inline bool cliq_source_inspection_id(const char *value) {
    if (strnlen(value, 44) != 43) return false;
    for (size_t i = 0; i < 43; i++)
        if (!((value[i] >= 'A' && value[i] <= 'Z') || (value[i] >= 'a' && value[i] <= 'z') ||
            (value[i] >= '0' && value[i] <= '9') || value[i] == '_' || value[i] == '-')) return false;
    return true;
}
static inline bool cliq_source_path(const char *value, uint32_t length) {
    if (length == 0 || length >= CLIQ_SOURCE_PATH_BYTES || value[0] == '/' || value[length - 1] == '/' ||
        memchr(value, '\0', length) || memchr(value, '\\', length)) return false;
    size_t start = 0;
    for (size_t i = 0; i <= length; i++) {
        if (i != length && value[i] != '/') continue;
        size_t bytes = i - start;
        if (bytes == 0 || bytes > 255 || (bytes == 1 && value[start] == '.') ||
            (bytes == 2 && value[start] == '.' && value[start + 1] == '.')) return false;
        for (size_t j = start; j < i; j++) if ((unsigned char)value[j] < 32 || (unsigned char)value[j] == 127) return false;
        start = i + 1;
    }
    return true;
}
static inline bool cliq_source_mapping_path(const char *value) {
    if (strcmp(value, "/usr/bin/node") == 0 || strcmp(value, "/usr/bin/git") == 0 ||
        strcmp(value, "/lib64/ld-linux-x86-64.so.2") == 0) return true;
    const char *prefixes[] = { "/lib/x86_64-linux-gnu/", "/usr/lib/x86_64-linux-gnu/" };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t prefix = strlen(prefixes[i]);
        if (strncmp(value, prefixes[i], prefix) != 0 || !value[prefix]) continue;
        for (const char *at = value + prefix; *at; at++)
            if (!((*at >= 'A' && *at <= 'Z') || (*at >= 'a' && *at <= 'z') || (*at >= '0' && *at <= '9') ||
                *at == '.' || *at == '_' || *at == '-' || *at == '+')) return false;
        return true;
    }
    return false;
}
static inline bool cliq_source_config_valid(const struct cliq_source_config *config) {
    if (config->magic != CLIQ_SOURCE_CONFIG_MAGIC || config->version != 1 || config->reserved != 0 ||
        config->file_count < 2 || config->file_count > CLIQ_SOURCE_MAX_FILES || config->init_bytes == 0 ||
        config->init_bytes > UINT64_C(268435456) || config->inspector_bytes == 0 ||
        config->inspector_bytes > CLIQ_SOURCE_MAX_CONFIG || !cliq_source_digest(config->inspector_digest) ||
        !cliq_source_digest(config->repository_identity_digest)) return false;
    bool node = false, git = false;
    for (uint32_t i = 0; i < config->file_count; i++) {
        size_t length = strnlen(config->files[i].path, CLIQ_SOURCE_PATH_BYTES);
        if (length >= CLIQ_SOURCE_PATH_BYTES || !cliq_source_mapping_path(config->files[i].path) ||
            config->files[i].byte_count == 0 || config->files[i].byte_count > UINT64_C(268435456) ||
            !cliq_source_digest(config->files[i].digest)) return false;
        for (uint32_t j = 0; j < i; j++) if (strcmp(config->files[i].path, config->files[j].path) == 0) return false;
        node = node || strcmp(config->files[i].path, "/usr/bin/node") == 0;
        git = git || strcmp(config->files[i].path, "/usr/bin/git") == 0;
    }
    return node && git;
}
static inline bool cliq_source_page_add(uint64_t *used, uint64_t bytes, uint64_t limit) {
    if (bytes > UINT64_MAX - 4095) return false;
    uint64_t rounded = (bytes + 4095) & ~UINT64_C(4095);
    if (*used > limit || rounded > limit - *used) return false;
    *used += rounded; return true;
}
/* All named runtime copies, both bounded log files, raw-config/intent and
 * fixed root directories count against the original generation ceiling.
 * This reserves capacity, not extra storage, and never enlarges a profile. */
static inline bool cliq_source_storage_reserve(const struct cliq_source_config *config,
    const struct cliq_worker_packet *request, uint64_t *root, uint64_t *total) {
    uint64_t runtime = UINT64_C(1048576);
    for (size_t i = 0; i < sizeof(cliq_source_profile_directories) / sizeof(cliq_source_profile_directories[0]); i++)
        if (!cliq_source_page_add(&runtime, 4096, request->max_generation_bytes)) return false;
    if (!cliq_source_config_valid(config) ||
        !cliq_source_page_add(&runtime, config->init_bytes, request->max_generation_bytes) ||
        !cliq_source_page_add(&runtime, config->inspector_bytes, request->max_generation_bytes)) return false;
    for (uint32_t i = 0; i < config->file_count; i++)
        if (!cliq_source_page_add(&runtime, config->files[i].byte_count, request->max_generation_bytes)) return false;
    uint64_t reserve = runtime;
    uint64_t log = request->max_output_bytes < request->max_file_bytes ? request->max_output_bytes : request->max_file_bytes;
    if (!cliq_source_page_add(&reserve, log, request->max_generation_bytes) ||
        !cliq_source_page_add(&reserve, log, request->max_generation_bytes) ||
        !cliq_source_page_add(&reserve, CLIQ_SOURCE_MAX_CONFIG, request->max_generation_bytes) ||
        !cliq_source_page_add(&reserve, 4096, request->max_generation_bytes) ||
        !cliq_source_page_add(&reserve, sizeof(*config), request->max_generation_bytes) || reserve >= request->max_generation_bytes) return false;
    *root = runtime; *total = reserve; return true;
}
static inline bool cliq_source_request_valid(const struct cliq_worker_packet *request) {
    return request->preparation_input_intent_ref[0] == '\0' && request->parent == 0 && request->generation_device == 0 && request->generation_inode == 0 &&
        cliq_source_inspection_id(request->source_inspection_id) && cliq_source_digest(request->source_target_ref) &&
        cliq_source_digest(request->source_input_intent_ref) && cliq_source_digest(request->nonce) &&
        cliq_source_digest(request->activation_nonce) &&
        (request->source_exclude_grant_digest[0] == '\0' || cliq_source_digest(request->source_exclude_grant_digest));
}
static inline bool cliq_source_rule_result_valid(const struct cliq_worker_packet *packet) {
    if (packet->source_rule_present > 1) return false;
    if (!packet->source_rule_present) return packet->source_rule_bytes == 0 && packet->source_rule_digest[0] == '\0';
    return cliq_source_digest(packet->source_exclude_grant_digest) && cliq_source_digest(packet->source_rule_digest) &&
        packet->source_rule_bytes <= packet->max_file_bytes && packet->source_rule_bytes <= packet->max_output_bytes;
}
static inline bool cliq_source_same_attempt(const struct cliq_worker_packet *left, const struct cliq_worker_packet *right) {
    return left->scope == right->scope && cliq_source_request_valid(left) && cliq_source_request_valid(right) &&
        strcmp(left->source_inspection_id, right->source_inspection_id) == 0 &&
        strcmp(left->source_target_ref, right->source_target_ref) == 0 &&
        strcmp(left->source_input_intent_ref, right->source_input_intent_ref) == 0 &&
        strcmp(left->source_exclude_grant_digest, right->source_exclude_grant_digest) == 0 &&
        strcmp(left->nonce, right->nonce) == 0 && strcmp(left->activation_nonce, right->activation_nonce) == 0 &&
        left->max_processes == right->max_processes && left->memory_bytes == right->memory_bytes && left->cpu_quota == right->cpu_quota &&
        left->max_open_files == right->max_open_files && left->max_file_bytes == right->max_file_bytes &&
        left->max_generation_bytes == right->max_generation_bytes && left->max_output_bytes == right->max_output_bytes;
}
static inline bool cliq_source_same_prepared(const struct cliq_worker_packet *left, const struct cliq_worker_packet *right) {
    return cliq_source_same_attempt(left, right) && cliq_source_digest(left->plan_ref) &&
        cliq_source_digest(left->sandbox_launch_ref) && cliq_source_digest(left->sandbox_launch_digest) &&
        strcmp(left->plan_ref, right->plan_ref) == 0 && strcmp(left->sandbox_launch_ref, right->sandbox_launch_ref) == 0 &&
        strcmp(left->sandbox_launch_digest, right->sandbox_launch_digest) == 0 && !left->generation_ref[0] && !right->generation_ref[0];
}
#endif
