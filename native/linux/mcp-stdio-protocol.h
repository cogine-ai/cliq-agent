#ifndef CLIQ_MCP_STDIO_PROTOCOL_H
#define CLIQ_MCP_STDIO_PROTOCOL_H
/* Closed stdio data/framing. These bytes never create a live input, recipe,
 * signed executable, SQL permission, current cleanup or process-death proof. */
#include "mcp-http-admin-protocol.h"
#include "mcp-stdio-input-bridge.h"
#include "mcp-stdio-executable.h"
#include <stdio.h>
#define CLIQ_MCP_STDIO_RECIPE_MAGIC UINT32_C(0x43535243)
#define CLIQ_MCP_STDIO_PROGRESS_MAGIC UINT32_C(0x43535031)
#define CLIQ_MCP_STDIO_CHANNEL_MAGIC UINT32_C(0x43534331)
#define CLIQ_MCP_STDIO_LIMITS_MAGIC UINT32_C(0x43534c31)
#define CLIQ_MCP_STDIO_MAX_MESSAGE UINT32_C(1048576)
#define CLIQ_MCP_STDIO_MAX_ARGS UINT32_C(128)
#define CLIQ_MCP_STDIO_ARG_BYTES UINT32_C(8192)
#define CLIQ_MCP_STDIO_MAX_STRINGS (CLIQ_MCP_STDIO_MAX_ARGS * (CLIQ_MCP_STDIO_ARG_BYTES + 1))
#define CLIQ_MCP_STDIO_MAX_PROGRESS UINT32_C(32)
#define CLIQ_MCP_STDIO_CHUNK_BYTES UINT32_C(65536)
enum cliq_mcp_stdio_purpose { CLIQ_MCP_STDIO_ADMIN = 1, CLIQ_MCP_STDIO_RUN = 2, CLIQ_MCP_STDIO_RECOVERY = 3 };
enum cliq_mcp_stdio_channel_kind {
    CLIQ_MCP_STDIO_FRAME = 1, CLIQ_MCP_STDIO_FRAME_WRITTEN = 2,
    CLIQ_MCP_STDIO_STDOUT = 3, CLIQ_MCP_STDIO_STDERR = 4,
    CLIQ_MCP_STDIO_CHUNK_ACK = 5, CLIQ_MCP_STDIO_OUTPUT_EOF = 6,
    CLIQ_MCP_STDIO_PING_REPLY = 7, CLIQ_MCP_STDIO_PROTOCOL_DONE = 8,
    CLIQ_MCP_STDIO_CANCEL = 9, CLIQ_MCP_STDIO_CLIENT_JOINED = 10
};
struct cliq_mcp_stdio_limits {
    uint32_t magic, version, purpose, reserved;
    uint64_t max_processes, memory_bytes, cpu_quota, max_open_files, max_file_bytes, max_generation_bytes, max_output_bytes;
    uint64_t launch_deadline_ms, call_deadline_ms;
};
_Static_assert(sizeof(struct cliq_mcp_stdio_limits) == 88, "fixed stdio resource data bytes");
static inline bool cliq_mcp_stdio_limits_valid(const struct cliq_mcp_stdio_limits *limits) {
    return limits->magic == CLIQ_MCP_STDIO_LIMITS_MAGIC && limits->version == 1 && !limits->reserved &&
        (limits->purpose == CLIQ_MCP_STDIO_ADMIN || limits->purpose == CLIQ_MCP_STDIO_RUN || limits->purpose == CLIQ_MCP_STDIO_RECOVERY) &&
        limits->max_processes >= 1 && limits->max_processes <= 1024 && limits->memory_bytes >= UINT64_C(268435456) && limits->memory_bytes <= UINT64_C(34359738368) &&
        limits->cpu_quota >= 10000 && limits->cpu_quota <= 1600000 && limits->max_open_files >= 64 && limits->max_open_files <= 8192 &&
        limits->max_file_bytes >= UINT64_C(1048576) && limits->max_file_bytes <= UINT64_C(17179869184) &&
        limits->max_generation_bytes >= UINT64_C(268435456) && limits->max_generation_bytes <= UINT64_C(107374182400) &&
        limits->max_output_bytes >= 65536 && limits->max_output_bytes <= UINT64_C(67108864) && limits->launch_deadline_ms &&
        limits->launch_deadline_ms <= limits->call_deadline_ms && limits->call_deadline_ms <= UINT64_C(9007199254740991);
}
struct cliq_mcp_stdio_recipe_header {
    uint32_t magic, version, purpose, argument_count, string_bytes, phase_count, maximum_response_bytes, reserved;
    uint64_t maximum_output_bytes, server_bytes;
    char server_digest[65];
    uint32_t arguments[CLIQ_MCP_STDIO_MAX_ARGS];
    struct { uint64_t offset, bytes; char digest[65]; } frames[4];
};
_Static_assert(sizeof(struct cliq_mcp_stdio_recipe_header) == 984, "fixed stdio recipe header bytes");
_Static_assert(offsetof(struct cliq_mcp_stdio_recipe_header, arguments) == 116, "fixed stdio argv offsets");
_Static_assert(offsetof(struct cliq_mcp_stdio_recipe_header, frames) == 632, "fixed stdio frame offsets");
#define CLIQ_MCP_STDIO_MAX_RECIPE (sizeof(struct cliq_mcp_stdio_recipe_header) + CLIQ_MCP_STDIO_MAX_STRINGS + UINT64_C(4) * CLIQ_MCP_STDIO_MAX_MESSAGE)
struct cliq_mcp_stdio_progress {
    uint32_t magic, version, kind, ordinal;
    struct cliq_worker_packet packet;
    struct cliq_mcp_admin_directory controller_root, controller_parent, controller_leaf;
    int64_t controller_pid;
    char controller_start_token[192], controller_leaf_name[64];
    unsigned char previous[32], digest[32];
};
struct cliq_mcp_stdio_history {
    unsigned purpose;
    size_t header_size;
    union { struct cliq_mcp_admin_birth admin; struct cliq_mcp_stdio_run_birth run; struct cliq_mcp_stdio_recovery_birth recovery; } header;
    struct cliq_mcp_stdio_progress first, last, ready;
    uint32_t count;
    bool exec_released, spawn_attempted;
};
static inline bool cliq_mcp_stdio_text(const char *text, size_t capacity) {
    return text[0] && strnlen(text, capacity) < capacity;
}
static inline bool cliq_mcp_stdio_recovery_identity_valid(const struct cliq_mcp_stdio_recovery_identity *id) {
#define RECOVERY_VALIDATE_TEXT(name, capacity) if (!cliq_mcp_stdio_text(id->name, capacity)) return false;
    CLIQ_MCP_STDIO_RECOVERY_TEXT_FIELDS(RECOVERY_VALIDATE_TEXT)
#undef RECOVERY_VALIDATE_TEXT
#define RECOVERY_VALIDATE_DIGEST(name, capacity) if (!cliq_mcp_admin_digest(id->name)) return false;
    CLIQ_MCP_STDIO_RECOVERY_DIGEST_FIELDS(RECOVERY_VALIDATE_DIGEST)
#undef RECOVERY_VALIDATE_DIGEST
#define RECOVERY_VALIDATE_NUMBER(name, minimum) if (id->name - (uint64_t)(minimum) > UINT64_C(9007199254740991) - (uint64_t)(minimum)) return false;
    CLIQ_MCP_STDIO_RECOVERY_NUMBER_FIELDS(RECOVERY_VALIDATE_NUMBER)
#undef RECOVERY_VALIDATE_NUMBER
    return (!strcmp(id->probeKind, "automatic") || !strcmp(id->probeKind, "user_requested")) &&
        id->probeStartedAtMs <= UINT64_C(9007199254710991) && id->probeDeadlineAtMs == id->probeStartedAtMs + 30000 &&
        strcmp(id->effectServerToolName, id->statusOperationName) && strcmp(id->previousWaitingSubjectRef, id->waitingSubjectRef);
}
static inline bool cliq_mcp_stdio_recipe_valid(const unsigned char *bytes, size_t size, struct cliq_mcp_stdio_recipe_header *header) {
    if (size < sizeof(*header) || size > CLIQ_MCP_STDIO_MAX_RECIPE) return false;
    memcpy(header, bytes, sizeof(*header));
    if (header->magic != CLIQ_MCP_STDIO_RECIPE_MAGIC || header->version != 1 ||
        (header->purpose != CLIQ_MCP_STDIO_ADMIN && header->purpose != CLIQ_MCP_STDIO_RUN && header->purpose != CLIQ_MCP_STDIO_RECOVERY) ||
        header->argument_count > CLIQ_MCP_STDIO_MAX_ARGS || header->string_bytes > CLIQ_MCP_STDIO_MAX_STRINGS ||
        header->phase_count != (header->purpose == CLIQ_MCP_STDIO_ADMIN ? 3u : 4u) || header->reserved ||
        header->maximum_response_bytes < 65536 || header->maximum_response_bytes > CLIQ_MCP_STDIO_MAX_MESSAGE ||
        header->maximum_output_bytes < 65536 || header->maximum_output_bytes > UINT64_C(67108864) || !header->server_bytes || header->server_bytes > CLIQ_MCP_STDIO_EXECUTABLE_CAP ||
        !cliq_mcp_admin_digest(header->server_digest) || header->string_bytes > size - sizeof(*header)) return false;
    struct cliq_mcp_stdio_recipe_header canonical = {0};
    canonical.magic = header->magic; canonical.version = header->version; canonical.purpose = header->purpose;
    canonical.argument_count = header->argument_count; canonical.string_bytes = header->string_bytes; canonical.phase_count = header->phase_count;
    canonical.maximum_response_bytes = header->maximum_response_bytes; canonical.maximum_output_bytes = header->maximum_output_bytes;
    canonical.server_bytes = header->server_bytes; memcpy(canonical.server_digest, header->server_digest, 65);
    size_t at = 0;
    const char *strings = (const char *)bytes + sizeof(*header);
    for (uint32_t i = 0; i < header->argument_count; i++) {
        if (header->arguments[i] != at || at >= header->string_bytes) return false;
        size_t length = strnlen(strings + at, header->string_bytes - at);
        if (length > CLIQ_MCP_STDIO_ARG_BYTES || length == header->string_bytes - at) return false;
        canonical.arguments[i] = header->arguments[i]; at += length + 1;
    }
    if (at != header->string_bytes) return false;
    at += sizeof(*header);
    for (uint32_t i = 0; i < header->phase_count; i++) {
        if (header->frames[i].offset != at || !header->frames[i].bytes || header->frames[i].bytes > CLIQ_MCP_STDIO_MAX_MESSAGE ||
            header->frames[i].bytes > size - at || !cliq_mcp_admin_digest(header->frames[i].digest) ||
            memchr(bytes + at, '\n', (size_t)header->frames[i].bytes) || memchr(bytes + at, '\r', (size_t)header->frames[i].bytes)) return false;
        unsigned char hash[32]; char digest[65];
        cliq_mcp_admin_hash(bytes + at, (size_t)header->frames[i].bytes, hash);
        for (size_t n = 0; n < 32; n++) snprintf(digest + n * 2, 3, "%02x", hash[n]);
        if (strcmp(digest, header->frames[i].digest)) return false;
        canonical.frames[i].offset = header->frames[i].offset; canonical.frames[i].bytes = header->frames[i].bytes;
        memcpy(canonical.frames[i].digest, header->frames[i].digest, 65); at += (size_t)header->frames[i].bytes;
    }
    return at == size && !memcmp(&canonical, header, sizeof(canonical));
}
static inline bool cliq_mcp_stdio_packet_closed(const struct cliq_worker_packet *packet) {
    if (packet->magic != CLIQ_WORKER_MAGIC || packet->version != 9 || packet->status ||
        packet->command < CLIQ_MCP_STDIO_RESERVE || packet->command > CLIQ_MCP_STDIO_CLEANUP_RETAINED || packet->scope || packet->parent ||
        (packet->stdio_purpose != CLIQ_MCP_STDIO_ADMIN && packet->stdio_purpose != CLIQ_MCP_STDIO_RUN && packet->stdio_purpose != CLIQ_MCP_STDIO_RECOVERY) ||
        packet->stdio_operation_released > 1 || (packet->stdio_purpose == CLIQ_MCP_STDIO_ADMIN && packet->stdio_operation_released) ||
        packet->pid < 0 || packet->pid > INT32_MAX || packet->namespace_init_pid < 0 || packet->namespace_init_pid > INT32_MAX ||
        packet->monitor_pid < 0 || packet->monitor_pid > INT32_MAX || packet->subreaper_pid < 0 || packet->subreaper_pid > INT32_MAX) return false;
    const uint64_t numbers[] = {packet->max_processes, packet->memory_bytes, packet->cpu_quota, packet->max_open_files, packet->max_file_bytes,
        packet->max_generation_bytes, packet->max_output_bytes, packet->observed_at_ms, packet->stdio_launch_deadline_ms, packet->stdio_call_deadline_ms,
        packet->stdio_recipe_bytes, packet->stdio_server_bytes, packet->stdio_checker_owner_epoch};
    for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++) if (numbers[i] > UINT64_C(9007199254740991)) return false;
    struct cliq_worker_packet canonical = {0};
#define STDIO_NUM(name) canonical.name = packet->name
    STDIO_NUM(magic); STDIO_NUM(version); STDIO_NUM(command); STDIO_NUM(max_processes); STDIO_NUM(memory_bytes);
    STDIO_NUM(cpu_quota); STDIO_NUM(max_open_files); STDIO_NUM(max_file_bytes); STDIO_NUM(max_generation_bytes); STDIO_NUM(max_output_bytes);
    STDIO_NUM(cgroup_inode); STDIO_NUM(cgroup_device); STDIO_NUM(observed_at_ms); STDIO_NUM(pid_namespace_inode); STDIO_NUM(pid);
    STDIO_NUM(namespace_init_pid); STDIO_NUM(subreaper_pid); STDIO_NUM(monitor_pid); STDIO_NUM(exit_status); STDIO_NUM(populated);
    STDIO_NUM(remaining_descendants); STDIO_NUM(init_reaped); STDIO_NUM(reservation_observation);
    STDIO_NUM(stdio_purpose); STDIO_NUM(stdio_phase); STDIO_NUM(stdio_protocol_complete); STDIO_NUM(stdio_operation_released);
    STDIO_NUM(stdio_response_refused); STDIO_NUM(stdio_owner_drained);
    STDIO_NUM(stdio_launch_deadline_ms); STDIO_NUM(stdio_call_deadline_ms); STDIO_NUM(stdio_recipe_bytes); STDIO_NUM(stdio_server_bytes);
    STDIO_NUM(stdio_init_bytes); STDIO_NUM(stdio_bwrap_bytes);
    STDIO_NUM(stdio_checker_owner_epoch); STDIO_NUM(stdio_checker_supervisor_pid);
#undef STDIO_NUM
#define STDIO_TEXT(name) do { size_t n = strnlen(packet->name, sizeof(packet->name)); if (n == sizeof(packet->name)) return false; memcpy(canonical.name, packet->name, n); } while (0)
    STDIO_TEXT(nonce); STDIO_TEXT(start_token); STDIO_TEXT(init_start_token); STDIO_TEXT(init_native_start_token); STDIO_TEXT(subreaper_start_token);
    STDIO_TEXT(monitor_start_token); STDIO_TEXT(cgroup_name); STDIO_TEXT(plan_ref); STDIO_TEXT(sandbox_launch_ref); STDIO_TEXT(sandbox_launch_digest);
    STDIO_TEXT(pid_namespace_reservation); STDIO_TEXT(stdio_input_digest); STDIO_TEXT(stdio_recipe_digest); STDIO_TEXT(stdio_server_digest);
    STDIO_TEXT(stdio_init_digest); STDIO_TEXT(stdio_bwrap_digest);
    STDIO_TEXT(stdio_checker_supervisor_id); STDIO_TEXT(stdio_checker_supervisor_token); STDIO_TEXT(stdio_original_birth_digest);
#undef STDIO_TEXT
    return !memcmp(&canonical, packet, sizeof(canonical));
}
static inline bool cliq_mcp_stdio_packet_same(const struct cliq_worker_packet *left, const struct cliq_worker_packet *right) {
    return left->stdio_purpose == right->stdio_purpose && left->stdio_launch_deadline_ms == right->stdio_launch_deadline_ms &&
        left->stdio_call_deadline_ms == right->stdio_call_deadline_ms && left->stdio_recipe_bytes == right->stdio_recipe_bytes &&
        left->stdio_server_bytes == right->stdio_server_bytes && !strcmp(left->nonce, right->nonce) &&
        left->stdio_init_bytes == right->stdio_init_bytes && left->stdio_bwrap_bytes == right->stdio_bwrap_bytes &&
        !strcmp(left->stdio_input_digest, right->stdio_input_digest) && !strcmp(left->stdio_recipe_digest, right->stdio_recipe_digest) &&
        !strcmp(left->stdio_server_digest, right->stdio_server_digest) && !strcmp(left->stdio_init_digest, right->stdio_init_digest) &&
        !strcmp(left->stdio_bwrap_digest, right->stdio_bwrap_digest) && !strcmp(left->plan_ref, right->plan_ref) &&
        !strcmp(left->cgroup_name, right->cgroup_name) && !strcmp(left->pid_namespace_reservation, right->pid_namespace_reservation) &&
        !strcmp(left->sandbox_launch_ref, right->sandbox_launch_ref) && !strcmp(left->sandbox_launch_digest, right->sandbox_launch_digest);
}
static inline bool cliq_mcp_stdio_input_header(const unsigned char *bytes, size_t size, struct cliq_mcp_stdio_history *history) {
    if (size < sizeof(uint32_t)) return false;
    uint32_t magic; memcpy(&magic, bytes, sizeof(magic));
    if (magic == CLIQ_MCP_STDIO_ADMIN_BIRTH_MAGIC) {
        history->purpose = CLIQ_MCP_STDIO_ADMIN; history->header_size = sizeof(history->header.admin);
        if (size < history->header_size) return false;
        memcpy(&history->header.admin, bytes, history->header_size);
        struct cliq_mcp_admin_birth *h = &history->header.admin;
        if (h->version != 1 || h->supervisor_pid <= 0 || h->supervisor_pid > INT32_MAX || h->attempt > UINT64_C(9007199254740991) ||
            !cliq_mcp_stdio_text(h->supervisor_start_token, sizeof(h->supervisor_start_token)) || !cliq_mcp_stdio_text(h->operation, sizeof(h->operation)) ||
            !cliq_mcp_stdio_text(h->principal, sizeof(h->principal)) || !cliq_mcp_admin_digest(h->nonce) || !cliq_mcp_admin_digest(h->target_ref) ||
            !cliq_mcp_admin_digest(h->target_digest) || !cliq_mcp_admin_digest(h->core_ref) || !cliq_mcp_admin_digest(h->core_digest) ||
            !cliq_mcp_admin_digest(h->plan_ref) || !cliq_mcp_admin_digest(h->plan_digest) || !cliq_mcp_admin_digest(h->spec_ref) || !cliq_mcp_admin_digest(h->spec_digest)) return false;
        unsigned char digest[32]; cliq_mcp_admin_hash(h, offsetof(struct cliq_mcp_admin_birth, digest), digest);
        return !memcmp(digest, h->digest, 32);
    }
    if (magic == CLIQ_MCP_STDIO_RECOVERY_BIRTH_MAGIC) {
        history->purpose = CLIQ_MCP_STDIO_RECOVERY; history->header_size = sizeof(history->header.recovery);
        if (size < history->header_size) return false;
        memcpy(&history->header.recovery, bytes, history->header_size);
        struct cliq_mcp_stdio_recovery_birth *h = &history->header.recovery;
        if (h->version != 1 || h->supervisor_pid <= 0 || h->supervisor_pid > INT32_MAX ||
            !cliq_mcp_stdio_text(h->supervisor_start_token, sizeof(h->supervisor_start_token)) ||
            !cliq_mcp_stdio_recovery_identity_valid(&h->identity)) return false;
        unsigned char digest[32]; cliq_mcp_admin_hash(h, offsetof(struct cliq_mcp_stdio_recovery_birth, digest), digest);
        return !memcmp(digest, h->digest, 32);
    }
    if (magic != CLIQ_MCP_STDIO_RUN_BIRTH_MAGIC) return false;
    history->purpose = CLIQ_MCP_STDIO_RUN; history->header_size = sizeof(history->header.run);
    if (size < history->header_size) return false;
    memcpy(&history->header.run, bytes, history->header_size);
    struct cliq_mcp_stdio_run_birth *h = &history->header.run;
    const struct cliq_mcp_stdio_run_identity *id = &h->identity;
    if (h->version != 1 || h->supervisor_pid <= 0 || h->supervisor_pid > INT32_MAX || !cliq_mcp_stdio_text(h->supervisor_start_token, sizeof(h->supervisor_start_token)) ||
        !id->owner_epoch || !id->lease_epoch || !id->launch_deadline_ms || id->launch_deadline_ms > id->call_deadline_ms ||
        id->launch_attempt > UINT64_C(9007199254740991) || id->lifecycle_seq > UINT64_C(9007199254740991) || id->call_index > UINT64_C(9007199254740991) ||
        id->lease_epoch > UINT64_C(9007199254740991) || id->owner_epoch > UINT64_C(9007199254740991) || id->call_deadline_ms > UINT64_C(9007199254740991)) return false;
#define STDIO_ID_TEXT(name) if (!cliq_mcp_stdio_text(id->name, sizeof(id->name))) return false
    STDIO_ID_TEXT(run); STDIO_ID_TEXT(principal); STDIO_ID_TEXT(launch_op); STDIO_ID_TEXT(batch_item); STDIO_ID_TEXT(call); STDIO_ID_TEXT(worker_launch); STDIO_ID_TEXT(supervisor);
#undef STDIO_ID_TEXT
#define STDIO_ID_DIGEST(name) if (!cliq_mcp_admin_digest(id->name)) return false
    STDIO_ID_DIGEST(nonce); STDIO_ID_DIGEST(registry_ref); STDIO_ID_DIGEST(manifest_digest); STDIO_ID_DIGEST(tool_request_ref); STDIO_ID_DIGEST(tool_request_digest);
    STDIO_ID_DIGEST(launch_request_ref); STDIO_ID_DIGEST(launch_request_digest); STDIO_ID_DIGEST(target_ref); STDIO_ID_DIGEST(target_digest); STDIO_ID_DIGEST(grant_ref);
    STDIO_ID_DIGEST(grant_digest); STDIO_ID_DIGEST(plan_ref); STDIO_ID_DIGEST(plan_digest); STDIO_ID_DIGEST(spec_ref); STDIO_ID_DIGEST(spec_digest);
#undef STDIO_ID_DIGEST
    unsigned char digest[32]; cliq_mcp_admin_hash(h, offsetof(struct cliq_mcp_stdio_run_birth, digest), digest);
    return !memcmp(digest, h->digest, 32);
}
static inline bool cliq_mcp_stdio_recovery_program_matches(const struct cliq_worker_packet *packet,
    const struct cliq_mcp_stdio_recovery_identity *identity) {
    return packet->stdio_purpose == CLIQ_MCP_STDIO_RECOVERY &&
        !strcmp(packet->stdio_server_digest, identity->adapterExecutableDigest) &&
        strcmp(packet->stdio_init_digest, identity->adapterExecutableDigest);
}
static inline const unsigned char *cliq_mcp_stdio_header_digest(const struct cliq_mcp_stdio_history *h) {
    return h->purpose == CLIQ_MCP_STDIO_ADMIN ? h->header.admin.digest : h->purpose == CLIQ_MCP_STDIO_RECOVERY ? h->header.recovery.digest : h->header.run.digest;
}
static inline bool cliq_mcp_stdio_history_bytes(const unsigned char *bytes, size_t size, struct cliq_mcp_stdio_history *history) {
    memset(history, 0, sizeof(*history));
    if (!cliq_mcp_stdio_input_header(bytes, size, history) || (size - history->header_size) % sizeof(history->last)) return false;
    size_t count = (size - history->header_size) / sizeof(history->last);
    if (count > CLIQ_MCP_STDIO_MAX_PROGRESS) return false;
    const char *nonce = history->purpose == CLIQ_MCP_STDIO_ADMIN ? history->header.admin.nonce : history->purpose == CLIQ_MCP_STDIO_RECOVERY ? history->header.recovery.identity.nonce : history->header.run.identity.nonce;
    const char *plan = history->purpose == CLIQ_MCP_STDIO_ADMIN ? history->header.admin.plan_ref : history->purpose == CLIQ_MCP_STDIO_RECOVERY ? history->header.recovery.identity.plannedContainmentRef : history->header.run.identity.plan_ref;
    const char *spec = history->purpose == CLIQ_MCP_STDIO_ADMIN ? history->header.admin.spec_ref : history->purpose == CLIQ_MCP_STDIO_RECOVERY ? history->header.recovery.identity.sandboxLaunchSpecRef : history->header.run.identity.spec_ref;
    const char *spec_digest = history->purpose == CLIQ_MCP_STDIO_ADMIN ? history->header.admin.spec_digest : history->purpose == CLIQ_MCP_STDIO_RECOVERY ? history->header.recovery.identity.sandboxLaunchSpecDigest : history->header.run.identity.spec_digest;
    char input_digest[65]; const unsigned char *header_digest = cliq_mcp_stdio_header_digest(history);
    for (size_t i = 0; i < 32; i++) snprintf(input_digest + i * 2, 3, "%02x", header_digest[i]);
    for (size_t i = 0; i < count; i++) {
        struct cliq_mcp_stdio_progress frame; memcpy(&frame, bytes + history->header_size + i * sizeof(frame), sizeof(frame));
        unsigned char digest[32]; cliq_mcp_admin_hash(&frame, offsetof(struct cliq_mcp_stdio_progress, digest), digest);
        unsigned previous = history->last.kind;
        bool transition = !i ? frame.kind == 1 : previous == 1 ? frame.kind == 2 : previous == 2 ? frame.kind == 3 :
            previous == 3 ? (frame.kind == 4 || frame.kind == 8) : previous == 4 ? (frame.kind == 4 || frame.kind == 5 || frame.kind == 8) :
            previous == 5 ? (frame.kind == 6 || frame.kind == 8) : previous == 6 ? (frame.kind == 7 || frame.kind == 8) :
            previous == 7 ? frame.kind == 8 : previous == 8 ? frame.kind == 9 : false;
        if (frame.magic != CLIQ_MCP_STDIO_PROGRESS_MAGIC || frame.version != 1 || frame.ordinal != i + 1 || !transition ||
            !cliq_mcp_stdio_packet_closed(&frame.packet) || frame.packet.stdio_purpose != history->purpose ||
            memcmp(digest, frame.digest, 32) || memcmp(frame.previous, i ? history->last.digest : header_digest, 32) ||
            strcmp(frame.packet.nonce, nonce) || strcmp(frame.packet.plan_ref, plan) || strcmp(frame.packet.sandbox_launch_ref, spec) ||
            strcmp(frame.packet.sandbox_launch_digest, spec_digest) || strcmp(frame.packet.stdio_input_digest, input_digest) ||
            !cliq_mcp_admin_digest(frame.packet.stdio_recipe_digest) || !cliq_mcp_admin_digest(frame.packet.stdio_server_digest) ||
            !cliq_mcp_admin_digest(frame.packet.stdio_init_digest) || !cliq_mcp_admin_digest(frame.packet.stdio_bwrap_digest) ||
            !frame.packet.stdio_init_bytes || frame.packet.stdio_init_bytes > CLIQ_MCP_STDIO_EXECUTABLE_CAP ||
            !frame.packet.stdio_bwrap_bytes || frame.packet.stdio_bwrap_bytes > CLIQ_MCP_STDIO_EXECUTABLE_CAP ||
            frame.packet.stdio_recipe_bytes < sizeof(struct cliq_mcp_stdio_recipe_header) || frame.packet.stdio_recipe_bytes > CLIQ_MCP_STDIO_MAX_RECIPE ||
            !frame.packet.stdio_server_bytes || frame.packet.stdio_server_bytes > CLIQ_MCP_STDIO_EXECUTABLE_CAP ||
            !frame.packet.stdio_launch_deadline_ms || frame.packet.stdio_launch_deadline_ms > frame.packet.stdio_call_deadline_ms ||
            frame.packet.stdio_checker_owner_epoch || frame.packet.stdio_checker_supervisor_pid || frame.packet.stdio_checker_supervisor_id[0] ||
            frame.packet.stdio_checker_supervisor_token[0] || frame.packet.stdio_original_birth_digest[0] ||
            frame.controller_pid <= 0 || frame.controller_pid > INT32_MAX || !cliq_mcp_stdio_text(frame.controller_start_token, sizeof(frame.controller_start_token)) ||
            !cliq_mcp_stdio_text(frame.controller_leaf_name, sizeof(frame.controller_leaf_name))) return false;
        if (history->purpose == CLIQ_MCP_STDIO_RUN && (frame.packet.stdio_launch_deadline_ms != history->header.run.identity.launch_deadline_ms ||
            frame.packet.stdio_call_deadline_ms != history->header.run.identity.call_deadline_ms)) return false;
        if (history->purpose == CLIQ_MCP_STDIO_RECOVERY &&
            (frame.packet.stdio_launch_deadline_ms != history->header.recovery.identity.probeDeadlineAtMs ||
             frame.packet.stdio_call_deadline_ms != history->header.recovery.identity.probeDeadlineAtMs ||
             !cliq_mcp_stdio_recovery_program_matches(&frame.packet, &history->header.recovery.identity))) return false;
        if (i && (!cliq_mcp_stdio_packet_same(&history->first.packet, &frame.packet) || frame.controller_pid != history->first.controller_pid ||
            strcmp(frame.controller_start_token, history->first.controller_start_token) || strcmp(frame.controller_leaf_name, history->first.controller_leaf_name) ||
            memcmp(&frame.controller_root, &history->first.controller_root, sizeof(frame.controller_root)) ||
            memcmp(&frame.controller_parent, &history->first.controller_parent, sizeof(frame.controller_parent)) || memcmp(&frame.controller_leaf, &history->first.controller_leaf, sizeof(frame.controller_leaf)))) return false;
        if (frame.packet.stdio_phase > (history->purpose == CLIQ_MCP_STDIO_ADMIN ? 3u : 4u) || frame.packet.stdio_protocol_complete > 1 || frame.packet.stdio_operation_released > 1 ||
            frame.packet.stdio_response_refused > 1 || frame.packet.stdio_owner_drained > 1 ||
            (history->purpose == CLIQ_MCP_STDIO_ADMIN && frame.packet.stdio_operation_released) ||
            (i && (frame.packet.stdio_phase < history->last.packet.stdio_phase || frame.packet.stdio_operation_released < history->last.packet.stdio_operation_released ||
                   frame.packet.stdio_protocol_complete < history->last.packet.stdio_protocol_complete || frame.packet.stdio_response_refused < history->last.packet.stdio_response_refused ||
                   frame.packet.stdio_owner_drained < history->last.packet.stdio_owner_drained))) return false;
        if ((frame.kind == 3 && (!frame.packet.cgroup_device || !frame.packet.cgroup_inode)) ||
            (frame.kind == 5 && (frame.packet.pid <= 0 || frame.packet.pid > INT32_MAX || frame.packet.namespace_init_pid <= 0 || frame.packet.namespace_init_pid > INT32_MAX ||
              frame.packet.pid == frame.packet.namespace_init_pid || !frame.packet.pid_namespace_inode || !cliq_mcp_stdio_text(frame.packet.start_token, sizeof(frame.packet.start_token)) ||
              !cliq_mcp_stdio_text(frame.packet.init_native_start_token, sizeof(frame.packet.init_native_start_token)))) ||
            (frame.kind == 7 && frame.packet.stdio_protocol_complete != 1) ||
            (frame.kind >= 8 && (frame.packet.populated || frame.packet.remaining_descendants || (history->ready.kind && frame.packet.init_reaped != 1)))) return false;
        if (!i) history->first = frame;
        if (frame.kind == 5) history->ready = frame;
        if (frame.kind == 4) history->spawn_attempted = true;
        if (frame.kind == 6) history->exec_released = true;
        history->last = frame; history->count++;
    }
    return true;
}
static inline bool cliq_mcp_stdio_read_history(int fd, struct cliq_mcp_stdio_history *history, unsigned char **snapshot, size_t *size) {
    struct stat file;
    if (fstat(fd, &file) || !S_ISREG(file.st_mode) || file.st_size < (off_t)sizeof(struct cliq_mcp_admin_birth) ||
        (uint64_t)file.st_size > sizeof(history->header) + UINT64_C(32) * sizeof(history->last)) return false;
    unsigned char *bytes = malloc((size_t)file.st_size);
    if (!bytes) return false;
    bool valid = cliq_mcp_admin_read_exact(fd, bytes, (size_t)file.st_size, 0) && cliq_mcp_stdio_history_bytes(bytes, (size_t)file.st_size, history);
    if (valid && snapshot) { *snapshot = bytes; *size = (size_t)file.st_size; } else free(bytes);
    return valid;
}
static inline bool cliq_mcp_stdio_append(int fd, uint32_t kind, const struct cliq_mcp_stdio_progress *source) {
    struct cliq_mcp_stdio_history history;
    if (!cliq_mcp_stdio_read_history(fd, &history, NULL, NULL) || history.count >= CLIQ_MCP_STDIO_MAX_PROGRESS) return false;
    struct cliq_mcp_stdio_progress frame = *source;
    frame.magic = CLIQ_MCP_STDIO_PROGRESS_MAGIC; frame.version = 1; frame.kind = kind; frame.ordinal = history.count + 1;
    memcpy(frame.previous, history.count ? history.last.digest : cliq_mcp_stdio_header_digest(&history), 32);
    cliq_mcp_admin_hash(&frame, offsetof(struct cliq_mcp_stdio_progress, digest), frame.digest);
    size_t original = history.header_size + (size_t)history.count * sizeof(frame), total = original + sizeof(frame);
    unsigned char *candidate = malloc(total);
    if (!candidate) return false;
    bool valid = cliq_mcp_admin_read_exact(fd, candidate, original, 0);
    if (valid) { struct cliq_mcp_stdio_history checked; memcpy(candidate + original, &frame, sizeof(frame)); valid = cliq_mcp_stdio_history_bytes(candidate, total, &checked); }
    free(candidate);
    if (!valid) return false;
    for (size_t at = 0; at < sizeof(frame);) {
        ssize_t n = pwrite(fd, (unsigned char *)&frame + at, sizeof(frame) - at, (off_t)(original + at));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        at += (size_t)n;
    }
    return !fsync(fd);
}
#define CLIQ_MCP_STDIO_CLEANUP_MAGIC UINT32_C(0x43534350)
struct cliq_mcp_stdio_cleanup_header {
    uint32_t magic, version;
    uint64_t original_bytes, checker_owner_epoch;
    int64_t checker_supervisor_pid, checker_controller_pid;
    char checker_supervisor[257], checker_supervisor_token[192], checker_controller_token[192];
    struct cliq_worker_packet retirement;
    unsigned char digest[32];
};
static inline bool cliq_mcp_stdio_cleanup_bytes(const unsigned char *bytes, size_t size,
    struct cliq_mcp_stdio_cleanup_header *header, struct cliq_mcp_stdio_history *original) {
    if (size < sizeof(*header) || size > sizeof(*header) + sizeof(original->header) +
        CLIQ_MCP_STDIO_MAX_PROGRESS * sizeof(original->last)) return false;
    memcpy(header, bytes, sizeof(*header));
    if (header->magic != CLIQ_MCP_STDIO_CLEANUP_MAGIC || header->version != 1 ||
        header->original_bytes != size - sizeof(*header) || !header->checker_owner_epoch ||
        header->checker_owner_epoch > UINT64_C(9007199254740991) || header->checker_supervisor_pid <= 0 ||
        header->checker_supervisor_pid > INT32_MAX || header->checker_controller_pid <= 0 || header->checker_controller_pid > INT32_MAX ||
        !cliq_mcp_stdio_text(header->checker_supervisor, sizeof(header->checker_supervisor)) ||
        !cliq_mcp_stdio_text(header->checker_supervisor_token, sizeof(header->checker_supervisor_token)) ||
        !cliq_mcp_stdio_text(header->checker_controller_token, sizeof(header->checker_controller_token)) ||
        !cliq_mcp_stdio_history_bytes(bytes + sizeof(*header), (size_t)header->original_bytes, original) || !original->count ||
        !cliq_mcp_stdio_packet_closed(&header->retirement) || header->retirement.command != CLIQ_MCP_STDIO_CLEANUP_RETAINED ||
        !cliq_mcp_stdio_packet_same(&header->retirement, &original->first.packet) ||
        header->retirement.cgroup_device != original->last.packet.cgroup_device ||
        header->retirement.cgroup_inode != original->last.packet.cgroup_inode ||
        header->retirement.pid != original->last.packet.pid ||
        header->retirement.namespace_init_pid != original->last.packet.namespace_init_pid ||
        header->retirement.pid_namespace_inode != original->last.packet.pid_namespace_inode ||
        strcmp(header->retirement.start_token, original->last.packet.start_token) ||
        strcmp(header->retirement.init_start_token, original->last.packet.init_start_token) ||
        strcmp(header->retirement.init_native_start_token, original->last.packet.init_native_start_token) ||
        header->retirement.stdio_checker_owner_epoch != header->checker_owner_epoch ||
        header->retirement.stdio_checker_supervisor_pid != header->checker_supervisor_pid ||
        strcmp(header->retirement.stdio_checker_supervisor_id, header->checker_supervisor) ||
        strcmp(header->retirement.stdio_checker_supervisor_token, header->checker_supervisor_token) ||
        header->retirement.populated || header->retirement.remaining_descendants ||
        header->retirement.reservation_observation != original->last.kind ||
        header->retirement.init_reaped != (original->ready.kind == 5 ? 1u : 0u) ||
        !header->retirement.observed_at_ms || header->checker_controller_pid == original->first.controller_pid) return false;
    if (original->purpose == CLIQ_MCP_STDIO_RECOVERY &&
        (header->checker_owner_epoch <= original->header.recovery.identity.inspectorStateOwnerEpoch ||
         !strcmp(header->checker_supervisor, original->header.recovery.identity.inspectorSupervisorInstanceId) ||
         header->checker_supervisor_pid == original->header.recovery.supervisor_pid)) return false;
    struct cliq_mcp_stdio_cleanup_header canonical = {0};
    canonical.magic = header->magic; canonical.version = header->version; canonical.original_bytes = header->original_bytes;
    canonical.checker_owner_epoch = header->checker_owner_epoch; canonical.checker_supervisor_pid = header->checker_supervisor_pid;
    canonical.checker_controller_pid = header->checker_controller_pid; canonical.retirement = header->retirement;
    memcpy(canonical.checker_supervisor, header->checker_supervisor, strlen(header->checker_supervisor));
    memcpy(canonical.checker_supervisor_token, header->checker_supervisor_token, strlen(header->checker_supervisor_token));
    memcpy(canonical.checker_controller_token, header->checker_controller_token, strlen(header->checker_controller_token));
    memcpy(canonical.digest, header->digest, 32);
    if (memcmp(&canonical, header, sizeof(canonical))) return false;
    unsigned char hash[32]; char digest[65];
    cliq_mcp_admin_hash(bytes + sizeof(*header), (size_t)header->original_bytes, hash);
    for (size_t i = 0; i < 32; i++) snprintf(digest + i * 2, 3, "%02x", hash[i]);
    if (strcmp(digest, header->retirement.stdio_original_birth_digest)) return false;
    struct sha256_context context; sha256_init(&context);
    sha256_update(&context, (const unsigned char *)header, offsetof(struct cliq_mcp_stdio_cleanup_header, digest));
    sha256_update(&context, bytes + sizeof(*header), (size_t)header->original_bytes); sha256_final(&context, hash);
    return !memcmp(hash, header->digest, 32);
}
#endif
