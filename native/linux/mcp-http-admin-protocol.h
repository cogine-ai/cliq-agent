#ifndef CLIQ_MCP_HTTP_ADMIN_PROTOCOL_H
#define CLIQ_MCP_HTTP_ADMIN_PROTOCOL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "worker-protocol.h"
#include "verifier-protocol.h"
#include "mcp-http-admin-input-bridge.h"
#include "mcp-http-owner-bridge.h"
#include "worker-sha256.h"
#define CLIQ_MCP_ADMIN_CONFIG_MAGIC UINT32_C(0x434d4331)
#define CLIQ_MCP_ADMIN_CHANNEL_MAGIC UINT32_C(0x434d4131)
#define CLIQ_MCP_ADMIN_PROGRESS_MAGIC UINT32_C(0x434d5031)
#define CLIQ_MCP_ADMIN_SCRIPT_PATH "/runtime/cliq-mcp-http-admin-probe.mjs"
#define CLIQ_MCP_ADMIN_MAX_MESSAGE 1048576u
#define CLIQ_MCP_ADMIN_MAX_CONFIG (3u * CLIQ_MCP_ADMIN_MAX_MESSAGE + 4096u)
enum cliq_mcp_phase {
CLIQ_MCP_INITIALIZE = 0, CLIQ_MCP_INITIALIZED = 1, CLIQ_MCP_TOOLS_LIST = 2, CLIQ_MCP_TOOLS_CALL = 3};
enum cliq_mcp_admin_channel_kind {
CLIQ_MCP_CONFIG = 1, CLIQ_MCP_STAGE = 2, CLIQ_MCP_MESSAGE = 3, CLIQ_MCP_COMPLETE = 4, CLIQ_MCP_REFUSED = 5};
/*
 * Explicit LE encoding on the authenticated socket, never a native struct dump. Payload is bounded UTF-8 JSON. No
 * endpoint/key/header/FD is a field.
 */
struct cliq_mcp_admin_channel_header {
    uint32_t        magic, version, kind, bytes;
};
struct cliq_mcp_admin_config {
    uint32_t        magic, version, file_count, maximum_response_bytes;
    uint64_t        init_bytes, script_bytes, recipe_bytes;
    char            init_digest[65], script_digest[65], recipe_digest[65];
    struct {
        char            path[CLIQ_VERIFIER_PATH_BYTES];
        char            digest[65];
        uint64_t        byte_count;
    }               files[CLIQ_VERIFIER_MAX_FILES];
};
/*
 * Append-only original physical birth. Each frame includes the complete original packet and previous hash.
 * Partial/replaced frames never mean absent.
 */
struct cliq_mcp_admin_progress {
    uint32_t        magic, version, kind, ordinal;
    struct cliq_worker_packet packet;
    struct cliq_mcp_admin_directory controller_root, controller_parent, controller_leaf;
    int64_t         controller_pid;
    char            controller_start_token[192], controller_leaf_name[64];
    unsigned char   previous[32], digest[32];
};
struct cliq_mcp_admin_history {
    struct cliq_mcp_admin_birth header;
    struct cliq_mcp_admin_progress first, last, ready;
    uint32_t        count;
};
static inline bool cliq_mcp_admin_digest(const char *text);
static inline bool
cliq_mcp_admin_packet_closed(const struct cliq_worker_packet *packet)
{
    if (packet->magic != CLIQ_WORKER_MAGIC || (packet->version != UINT32_C(8) && packet->version != UINT32_C(9)) || packet->status || packet->command < CLIQ_MCP_ADMIN_RESERVE || packet->command > CLIQ_MCP_ADMIN_CLEANUP_RETAINED || packet->scope || packet->parent)
        return false;
    struct cliq_worker_packet canonical = {0};
#define MCP_ADMIN_NUMBER(name) canonical.name=packet->name
    MCP_ADMIN_NUMBER(magic);
    MCP_ADMIN_NUMBER(version);
    MCP_ADMIN_NUMBER(command);
    MCP_ADMIN_NUMBER(status);
    MCP_ADMIN_NUMBER(max_processes);
    MCP_ADMIN_NUMBER(memory_bytes);
    MCP_ADMIN_NUMBER(cpu_quota);
    MCP_ADMIN_NUMBER(max_open_files);
    MCP_ADMIN_NUMBER(max_file_bytes);
    MCP_ADMIN_NUMBER(max_generation_bytes);
    MCP_ADMIN_NUMBER(max_output_bytes);
    MCP_ADMIN_NUMBER(cgroup_inode);
    MCP_ADMIN_NUMBER(cgroup_device);
    MCP_ADMIN_NUMBER(observed_at_ms);
    MCP_ADMIN_NUMBER(pid_namespace_inode);
    MCP_ADMIN_NUMBER(pid);
    MCP_ADMIN_NUMBER(namespace_init_pid);
    MCP_ADMIN_NUMBER(subreaper_pid);
    MCP_ADMIN_NUMBER(monitor_pid);
    MCP_ADMIN_NUMBER(exit_status);
    MCP_ADMIN_NUMBER(populated);
    MCP_ADMIN_NUMBER(remaining_descendants);
    MCP_ADMIN_NUMBER(init_reaped);
    MCP_ADMIN_NUMBER(reservation_observation);
    MCP_ADMIN_NUMBER(admin_attempt);
    MCP_ADMIN_NUMBER(admin_deadline_ms);
    MCP_ADMIN_NUMBER(admin_phase);
    MCP_ADMIN_NUMBER(admin_protocol_complete);
    MCP_ADMIN_NUMBER(admin_checker_owner_epoch);
    MCP_ADMIN_NUMBER(admin_checker_supervisor_pid);
#undef MCP_ADMIN_NUMBER
#define MCP_ADMIN_TEXT(name) do{size_t count=strnlen(packet->name,sizeof(packet->name));if(count>=sizeof(packet->name))return false;memcpy(canonical.name,packet->name,count);}while(0)
    MCP_ADMIN_TEXT(nonce);
    MCP_ADMIN_TEXT(start_token);
    MCP_ADMIN_TEXT(init_start_token);
    MCP_ADMIN_TEXT(init_native_start_token);
    MCP_ADMIN_TEXT(subreaper_start_token);
    MCP_ADMIN_TEXT(monitor_start_token);
    MCP_ADMIN_TEXT(cgroup_name);
    MCP_ADMIN_TEXT(plan_ref);
    MCP_ADMIN_TEXT(sandbox_launch_ref);
    MCP_ADMIN_TEXT(sandbox_launch_digest);
    MCP_ADMIN_TEXT(pid_namespace_reservation);
    MCP_ADMIN_TEXT(admin_operation_id);
    MCP_ADMIN_TEXT(admin_principal_id);
    MCP_ADMIN_TEXT(admin_target_ref);
    MCP_ADMIN_TEXT(admin_target_digest);
    MCP_ADMIN_TEXT(admin_core_ref);
    MCP_ADMIN_TEXT(admin_core_digest);
    MCP_ADMIN_TEXT(admin_plan_digest);
    MCP_ADMIN_TEXT(admin_checker_supervisor_id);
    MCP_ADMIN_TEXT(admin_checker_supervisor_token);
    MCP_ADMIN_TEXT(admin_original_birth_digest);
#undef MCP_ADMIN_TEXT
    return !memcmp(&canonical, packet, sizeof(canonical));
}
static inline bool
cliq_mcp_admin_read_exact(int fd, void *bytes, size_t size, off_t at)
{
    size_t          offset = 0;
    while (offset < size) {
        ssize_t         n = pread(fd, (unsigned char *)bytes + offset, size - offset, at + (off_t) offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        offset += (size_t) n;
    } return true;
}
static inline void
cliq_mcp_admin_hash(const void *bytes, size_t size, unsigned char digest[32])
{
    struct sha256_context hash;
    sha256_init(&hash);
    sha256_update(&hash, bytes, size);
    sha256_final(&hash, digest);
}
static inline bool
cliq_mcp_admin_history_bytes(const unsigned char *bytes, size_t size, struct cliq_mcp_admin_history *history)
{
    memset(history, 0, sizeof(*history));
    if (size < sizeof(history->header) || (size - sizeof(history->header)) % sizeof(history->last))
        return false;
    memcpy(&history->header, bytes, sizeof(history->header));
    unsigned char   digest[32];
    cliq_mcp_admin_hash(&history->header, offsetof(struct cliq_mcp_admin_birth, digest), digest);
    if (history->header.magic != CLIQ_MCP_ADMIN_BIRTH_MAGIC || history->header.version != 1 || memcmp(digest, history->header.digest, 32) || history->header.supervisor_pid <= 0 || history->header.supervisor_pid > INT32_MAX ||
        !history->header.operation[0] || strnlen(history->header.operation, sizeof(history->header.operation)) == sizeof(history->header.operation) ||
        !history->header.principal[0] || strnlen(history->header.principal, sizeof(history->header.principal)) == sizeof(history->header.principal) ||
        strnlen(history->header.supervisor_start_token, sizeof(history->header.supervisor_start_token)) == sizeof(history->header.supervisor_start_token) ||
        !cliq_mcp_admin_digest(history->header.nonce) || !cliq_mcp_admin_digest(history->header.target_ref) || !cliq_mcp_admin_digest(history->header.target_digest) ||
        !cliq_mcp_admin_digest(history->header.core_ref) || !cliq_mcp_admin_digest(history->header.core_digest) || !cliq_mcp_admin_digest(history->header.plan_ref) ||
        !cliq_mcp_admin_digest(history->header.plan_digest) || !cliq_mcp_admin_digest(history->header.spec_ref) || !cliq_mcp_admin_digest(history->header.spec_digest))
        return false;
    size_t          count = (size - sizeof(history->header)) / sizeof(history->last);
    if (count > 32)
        return false;
    for (size_t i = 0; i < count; i++) {
        struct cliq_mcp_admin_progress frame;
        memcpy(&frame, bytes + sizeof(history->header) + i * sizeof(frame), sizeof(frame));
        cliq_mcp_admin_hash(&frame, offsetof(struct cliq_mcp_admin_progress, digest), digest);
        if (strnlen(frame.packet.admin_operation_id, sizeof(frame.packet.admin_operation_id)) == sizeof(frame.packet.admin_operation_id) ||
            strnlen(frame.packet.admin_principal_id, sizeof(frame.packet.admin_principal_id)) == sizeof(frame.packet.admin_principal_id) ||
            strnlen(frame.controller_start_token, sizeof(frame.controller_start_token)) == sizeof(frame.controller_start_token) ||
            strnlen(frame.controller_leaf_name, sizeof(frame.controller_leaf_name)) == sizeof(frame.controller_leaf_name) ||
            strnlen(frame.packet.cgroup_name, sizeof(frame.packet.cgroup_name)) == sizeof(frame.packet.cgroup_name) ||
            strnlen(frame.packet.start_token, sizeof(frame.packet.start_token)) == sizeof(frame.packet.start_token) ||
            strnlen(frame.packet.init_start_token, sizeof(frame.packet.init_start_token)) == sizeof(frame.packet.init_start_token) ||
            !cliq_mcp_admin_digest(frame.packet.nonce))
            return false;
        if (frame.magic != CLIQ_MCP_ADMIN_PROGRESS_MAGIC || frame.version != 1 || frame.ordinal != i + 1 || frame.kind < 1 || frame.kind > 9 || !cliq_mcp_admin_packet_closed(&frame.packet) ||
            (i && frame.kind < history->last.kind) || memcmp(frame.digest, digest, 32) || memcmp(frame.previous, i ? history->last.digest : history->header.digest, 32) ||
            strcmp(frame.packet.admin_operation_id, history->header.operation) || frame.packet.admin_attempt != history->header.attempt || strcmp(frame.packet.nonce, history->header.nonce))
            return false;
        if (frame.controller_pid <= 0 || frame.controller_pid > INT32_MAX || frame.packet.pid < 0 || frame.packet.pid > INT32_MAX || frame.packet.namespace_init_pid < 0 || frame.packet.namespace_init_pid > INT32_MAX || frame.packet.monitor_pid < 0 || frame.packet.monitor_pid > INT32_MAX ||
            frame.packet.admin_checker_owner_epoch || frame.packet.admin_checker_supervisor_pid || frame.packet.admin_checker_supervisor_id[0] || frame.packet.admin_checker_supervisor_token[0] || frame.packet.admin_original_birth_digest[0] ||
            strcmp(frame.packet.admin_principal_id, history->header.principal) || strcmp(frame.packet.admin_target_ref, history->header.target_ref) || strcmp(frame.packet.admin_target_digest, history->header.target_digest) ||
            strcmp(frame.packet.admin_core_ref, history->header.core_ref) || strcmp(frame.packet.admin_core_digest, history->header.core_digest) || strcmp(frame.packet.plan_ref, history->header.plan_ref) ||
            strcmp(frame.packet.admin_plan_digest, history->header.plan_digest) || strcmp(frame.packet.sandbox_launch_ref, history->header.spec_ref) || strcmp(frame.packet.sandbox_launch_digest, history->header.spec_digest))
            return false;
        unsigned        previous = history->last.kind;
        bool            transition = !i ? frame.kind == 1 : previous == 1 ? frame.kind == 2 : previous == 2 ? frame.kind == 3 : previous == 3 ? (frame.kind == 4 || frame.kind == 8) : previous == 4 ? (frame.kind == 4 || frame.kind == 5 || frame.kind == 8) : previous == 5 ? (frame.kind == 6 || frame.kind == 8) : previous == 6 ? (frame.kind == 7 || frame.kind == 8) : previous == 7 ? frame.kind == 8 : previous == 8 ? frame.kind == 9 : false;
        if (!transition || (i && (frame.packet.version != history->first.packet.version || frame.controller_pid != history->first.controller_pid || strcmp(frame.controller_start_token, history->first.controller_start_token) || strcmp(frame.controller_leaf_name, history->first.controller_leaf_name) ||
                                  memcmp(&frame.controller_root, &history->first.controller_root, sizeof(frame.controller_root)) || memcmp(&frame.controller_parent, &history->first.controller_parent, sizeof(frame.controller_parent)) || memcmp(&frame.controller_leaf, &history->first.controller_leaf, sizeof(frame.controller_leaf)))))
            return false;
        if (frame.kind == 3 && (!frame.packet.cgroup_device || !frame.packet.cgroup_inode))
            return false;
        if (frame.kind == 5 && (frame.packet.pid <= 0 || frame.packet.namespace_init_pid <= 0 || frame.packet.pid == frame.packet.namespace_init_pid || !frame.packet.pid_namespace_inode || !frame.packet.start_token[0] || !frame.packet.init_native_start_token[0]))
            return false;
        if (frame.kind == 7 && frame.packet.admin_protocol_complete != 1)
            return false;
        if (frame.kind >= 8 && (frame.packet.populated || frame.packet.remaining_descendants || (history->ready.kind && frame.packet.init_reaped != 1)))
            return false;
        if (!i)
            history->first = frame;
        history->last = frame;
        if (frame.kind == 5)
            history->ready = frame;
        history->count++;
    }
    return true;
}
static inline bool
cliq_mcp_admin_read_history(int fd, struct cliq_mcp_admin_history *history, unsigned char **snapshot, size_t * size)
{
    struct stat     file;
    if (fstat(fd, &file) || !S_ISREG(file.st_mode) || file.st_size < (off_t) sizeof(history->header) ||
        (uint64_t) file.st_size > sizeof(history->header) + UINT64_C(32) * sizeof(history->last))
        return false;
    unsigned char  *bytes = malloc((size_t) file.st_size);
    if (!bytes)
        return false;
    bool            valid = cliq_mcp_admin_read_exact(fd, bytes, (size_t) file.st_size, 0) && cliq_mcp_admin_history_bytes(bytes, (size_t) file.st_size, history);
    if (valid && snapshot) {
        *snapshot = bytes;
        *size = (size_t) file.st_size;
    } else
        free(bytes);
    return valid;
}
static inline bool
cliq_mcp_admin_append(int fd, uint32_t kind, const struct cliq_mcp_admin_progress *template)
{
    struct cliq_mcp_admin_history history;
    if (!cliq_mcp_admin_read_history(fd, &history, NULL, NULL) || history.count >= 32 || kind < 1 || kind > 9 || (history.count && kind < history.last.kind))
        return false;
    struct cliq_mcp_admin_progress frame = *template;
    frame.magic = CLIQ_MCP_ADMIN_PROGRESS_MAGIC;
    frame.version = 1;
    frame.kind = kind;
    frame.ordinal = history.count + 1;
    memcpy(frame.previous, history.count ? history.last.digest : history.header.digest, 32);
    cliq_mcp_admin_hash(&frame, offsetof(struct cliq_mcp_admin_progress, digest), frame.digest);
    size_t          original_size = sizeof(history.header) + (size_t) history.count * sizeof(frame), candidate_size = original_size + sizeof(frame);
    unsigned char  *candidate = malloc(candidate_size);
    if (!candidate)
        return false;
    bool            valid = cliq_mcp_admin_read_exact(fd, candidate, original_size, 0);
    if (valid) {
        memcpy(candidate + original_size, &frame, sizeof(frame));
        struct cliq_mcp_admin_history checked;
        valid = cliq_mcp_admin_history_bytes(candidate, candidate_size, &checked);
    } free(candidate);
    if (!valid)
        return false;
    size_t          offset = 0;
    off_t           at = (off_t) sizeof(history.header) + (off_t) history.count * sizeof(frame);
    while (offset < sizeof(frame)) {
        ssize_t         n = pwrite(fd, (unsigned char *)&frame + offset, sizeof(frame) - offset, at + (off_t) offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        offset += (size_t) n;
    }
    return fsync(fd) == 0;
}
static inline bool
cliq_mcp_admin_digest(const char *text)
{
    if (strnlen(text, 65) != 64)
        return false;
    for (size_t i = 0; i < 64; i++)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f')))
            return false;
    return true;
}
static inline bool
cliq_mcp_admin_config_valid(const struct cliq_mcp_admin_config *config)
{
    if (config->magic != CLIQ_MCP_ADMIN_CONFIG_MAGIC || config->version != 1 || config->file_count < 1 ||
        config->file_count > CLIQ_VERIFIER_MAX_FILES || config->maximum_response_bytes < 65536 || config->maximum_response_bytes > CLIQ_MCP_ADMIN_MAX_MESSAGE ||
        config->init_bytes < 1 || config->init_bytes > UINT64_C(268435456) || config->script_bytes < 1 || config->script_bytes > CLIQ_MCP_ADMIN_MAX_MESSAGE ||
        !cliq_mcp_admin_digest(config->init_digest) || !cliq_mcp_admin_digest(config->script_digest) ||
        !cliq_mcp_admin_digest(config->recipe_digest))
        return false;
    bool            node = false;
    for (uint32_t i = 0; i < config->file_count; i++) {
        if (!cliq_verifier_mapping_path(config->files[i].path) || !cliq_mcp_admin_digest(config->files[i].digest) || !config->files[i].byte_count || config->files[i].byte_count > UINT64_C(268435456))
            return false;
        for (uint32_t j = 0; j < i; j++)
            if (!strcmp(config->files[i].path, config->files[j].path))
                return false;
        if (!strcmp(config->files[i].path, "/usr/bin/node"))
            node = true;
    }
    return node;
}
static inline bool
cliq_mcp_admin_packet_same(const struct cliq_worker_packet *left, const struct cliq_worker_packet *right)
{
    return !strcmp(left->admin_operation_id, right->admin_operation_id) && left->admin_attempt == right->admin_attempt &&
        !strcmp(left->admin_principal_id, right->admin_principal_id) && !strcmp(left->nonce, right->nonce) &&
        !strcmp(left->admin_target_ref, right->admin_target_ref) && !strcmp(left->admin_target_digest, right->admin_target_digest) &&
        !strcmp(left->admin_core_ref, right->admin_core_ref) && !strcmp(left->admin_core_digest, right->admin_core_digest) &&
        !strcmp(left->plan_ref, right->plan_ref) && !strcmp(left->admin_plan_digest, right->admin_plan_digest) &&
        !strcmp(left->sandbox_launch_ref, right->sandbox_launch_ref) && !strcmp(left->sandbox_launch_digest, right->sandbox_launch_digest);
}
#endif
