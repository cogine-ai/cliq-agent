#ifndef CLIQ_SOURCE_GIT_HISTORY_DATA_H
#define CLIQ_SOURCE_GIT_HISTORY_DATA_H

#include "source-git-protocol.h"
#include <errno.h>
#include <unistd.h>
_Static_assert(CLIQ_SOURCE_HISTORY_MAX_BYTES <= 1048576, "source lifecycle snapshot must stay within its fixed byte ceiling");

/* One bounded original birth chain. Decoding this data does not establish
 * process death, cgroup ownership/currentness or a replacement execution. */
struct cliq_source_history {
    struct cliq_source_birth header;
    struct cliq_source_controller_birth creator;
    struct cliq_worker_packet first, last, born, blocked, monitor, ready, sealed;
    uint32_t count, kind;
    bool released, continued;
    unsigned char digest[32];
};
/* Fixed data projection of a completely decoded birth. Both original-owner
 * join and successor cleanup use the same original facts. This data does not
 * assert join/currentness; the native scope must establish those separately. */
struct cliq_source_retirement_data {
    uint32_t last_kind;
    bool reserved, blocked, released, continued, sealed;
    int64_t controller_pid, monitor_pid, worker_pid;
    uint64_t cgroup_device, cgroup_inode;
    const char *controller_token, *launch_nonce, *plan_ref, *sandbox_launch_ref, *sandbox_launch_digest;
    const struct cliq_worker_packet *containment, *snapshot;
};
static inline bool cliq_source_recovery_prefix_complete(const struct cliq_source_history *history) {
    /* 1: mkdir may have happened but no inode was retained. 3: fork may
     * have happened but no monitor PID/token was retained. Do not infer it. */
    return history->kind != 1 && history->kind != 3;
}
static inline bool cliq_source_retirement_project(const struct cliq_source_history *history,
    struct cliq_source_retirement_data *result) {
    if (!cliq_source_recovery_prefix_complete(history)) return false;
    memset(result, 0, sizeof(*result));
    result->last_kind = history->kind; result->controller_pid = history->creator.pid;
    result->controller_token = history->creator.process_start_token;
    result->monitor_pid = history->monitor.monitor_pid; result->worker_pid = history->ready.pid;
    result->reserved = history->born.cgroup_inode != 0; result->blocked = history->ready.pid != 0;
    result->released = history->released; result->continued = history->continued;
    result->cgroup_device = history->born.cgroup_device; result->cgroup_inode = history->born.cgroup_inode;
    result->launch_nonce = result->reserved ? history->first.activation_nonce : NULL;
    result->plan_ref = history->blocked.plan_ref[0] ? history->blocked.plan_ref : NULL;
    result->sandbox_launch_ref = result->plan_ref ? history->blocked.sandbox_launch_ref : NULL;
    result->sandbox_launch_digest = result->plan_ref ? history->blocked.sandbox_launch_digest : NULL;
    result->containment = result->blocked ? &history->ready : NULL;
    result->sealed = history->sealed.source_snapshot_digest[0] != '\0';
    result->snapshot = result->sealed ? &history->sealed : NULL;
    return true;
}
static inline bool cliq_source_history_packet(const struct cliq_worker_packet *packet) {
    /* Only fixed source fields can enter the retained binary snapshot. This
     * also rejects nonzero struct padding and hidden bytes after string NULs. */
    struct cliq_worker_packet canonical;
    memset(&canonical, 0, sizeof(canonical));
#define SOURCE_NUMBER(name) canonical.name = packet->name
    SOURCE_NUMBER(magic); SOURCE_NUMBER(version); SOURCE_NUMBER(command); SOURCE_NUMBER(scope); SOURCE_NUMBER(status);
    SOURCE_NUMBER(max_processes); SOURCE_NUMBER(memory_bytes); SOURCE_NUMBER(cpu_quota); SOURCE_NUMBER(max_open_files);
    SOURCE_NUMBER(max_file_bytes); SOURCE_NUMBER(max_generation_bytes); SOURCE_NUMBER(max_output_bytes);
    SOURCE_NUMBER(cgroup_inode); SOURCE_NUMBER(cgroup_device); SOURCE_NUMBER(observed_at_ms); SOURCE_NUMBER(pid_namespace_inode);
    SOURCE_NUMBER(pid); SOURCE_NUMBER(namespace_init_pid); SOURCE_NUMBER(subreaper_pid); SOURCE_NUMBER(monitor_pid);
    SOURCE_NUMBER(exit_status); SOURCE_NUMBER(populated); SOURCE_NUMBER(remaining_descendants); SOURCE_NUMBER(init_reaped);
    SOURCE_NUMBER(source_rule_present); SOURCE_NUMBER(source_rule_bytes); SOURCE_NUMBER(source_byte_count);
    SOURCE_NUMBER(source_entry_count); SOURCE_NUMBER(source_shard_count);
#undef SOURCE_NUMBER
#define SOURCE_TEXT(name) do { size_t n = strnlen(packet->name, sizeof(packet->name)); \
    if (n >= sizeof(packet->name)) { return false; } memcpy(canonical.name, packet->name, n); } while (0)
    SOURCE_TEXT(nonce); SOURCE_TEXT(activation_nonce); SOURCE_TEXT(start_token); SOURCE_TEXT(init_start_token);
    SOURCE_TEXT(init_native_start_token); SOURCE_TEXT(subreaper_start_token); SOURCE_TEXT(monitor_start_token);
    SOURCE_TEXT(cgroup_name); SOURCE_TEXT(plan_ref); SOURCE_TEXT(sandbox_launch_ref); SOURCE_TEXT(sandbox_launch_digest);
    SOURCE_TEXT(source_inspection_id); SOURCE_TEXT(source_target_ref); SOURCE_TEXT(source_input_intent_ref);
    SOURCE_TEXT(source_exclude_grant_digest); SOURCE_TEXT(source_rule_digest); SOURCE_TEXT(source_snapshot_digest);
#undef SOURCE_TEXT
    for (size_t i = 0; i < CLIQ_SOURCE_OUTPUTS; i++) {
        size_t n = strnlen(packet->source_output_digests[i], sizeof(packet->source_output_digests[i]));
        if (n >= sizeof(packet->source_output_digests[i])) return false;
        memcpy(canonical.source_output_digests[i], packet->source_output_digests[i], n);
        canonical.source_output_bytes[i] = packet->source_output_bytes[i];
    }
    if (memcmp(&canonical, packet, sizeof(canonical))) return false;
    const char *strings[] = { packet->start_token, packet->init_start_token, packet->init_native_start_token,
        packet->monitor_start_token, packet->subreaper_start_token };
    for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++)
        if (strnlen(strings[i], CLIQ_WORKER_TOKEN_BYTES) >= CLIQ_WORKER_TOKEN_BYTES) return false;
    const char *process_tokens[] = { packet->start_token, packet->init_native_start_token,
        packet->subreaper_start_token, packet->monitor_start_token };
    for (size_t i = 0; i < sizeof(process_tokens) / sizeof(process_tokens[0]); i++)
        if (*process_tokens[i] && !cliq_source_process_token_valid(process_tokens[i])) return false;
    if (*packet->init_start_token && !cliq_source_namespace_token_valid(packet->init_start_token)) return false;
    const char *digests[] = { packet->plan_ref, packet->sandbox_launch_ref, packet->sandbox_launch_digest,
        packet->source_snapshot_digest, packet->source_rule_digest };
    for (size_t i = 0; i < sizeof(digests) / sizeof(digests[0]); i++) if (*digests[i] && !cliq_source_digest(digests[i])) return false;
    if (packet->magic != CLIQ_WORKER_MAGIC || packet->version != CLIQ_WORKER_VERSION || packet->status != 0 ||
        packet->scope == 0 || packet->scope >= CLIQ_WORKER_MAX_SCOPES || !cliq_source_request_valid(packet) ||
        strnlen(packet->cgroup_name, sizeof(packet->cgroup_name)) != 76 || strncmp(packet->cgroup_name, "cliq-source-", 12) != 0 ||
        strcmp(packet->cgroup_name + 12, packet->nonce) != 0 ||
        strnlen(packet->plan_ref, 65) >= 65 || strnlen(packet->sandbox_launch_ref, 65) >= 65 ||
        strnlen(packet->sandbox_launch_digest, 65) >= 65 || strnlen(packet->generation_ref, 65) >= 65 || packet->generation_ref[0] ||
        strnlen(packet->source_snapshot_digest, 65) >= 65 || strnlen(packet->source_rule_digest, 65) >= 65 ||
        packet->max_processes < 3 || packet->max_processes > 1024 ||
        packet->memory_bytes < UINT64_C(268435456) || packet->memory_bytes > UINT64_C(34359738368) ||
        packet->cpu_quota < 10000 || packet->cpu_quota > 1600000 || packet->max_open_files < 64 || packet->max_open_files > 8192 ||
        packet->max_file_bytes < UINT64_C(1048576) || packet->max_file_bytes > UINT64_C(17179869184) ||
        packet->max_generation_bytes < UINT64_C(268435456) || packet->max_generation_bytes > UINT64_C(107374182400) ||
        packet->max_output_bytes < 65536 || packet->max_output_bytes > UINT64_C(67108864)) return false;
    for (size_t i = 0; i < CLIQ_SOURCE_OUTPUTS; i++) if (strnlen(packet->source_output_digests[i], 65) >= 65 ||
        (*packet->source_output_digests[i] && !cliq_source_digest(packet->source_output_digests[i]))) return false;
    return true;
}
static inline bool cliq_source_history_decode(const unsigned char *bytes, size_t length,
    const struct cliq_source_birth *expected, struct cliq_source_history *history) {
    memset(history, 0, sizeof(*history));
    const size_t prefix = sizeof(history->header) + sizeof(history->creator);
    if (!bytes || length < prefix || length > CLIQ_SOURCE_HISTORY_MAX_BYTES ||
        (length - prefix) % sizeof(struct cliq_source_birth_record)) return false;
    memcpy(&history->header, bytes, sizeof(history->header));
    memcpy(&history->creator, bytes + sizeof(history->header), sizeof(history->creator));
    if (memcmp(&history->header, expected, sizeof(*expected)) ||
        !cliq_source_controller_frame_valid(&history->creator, &history->header)) return false;
    struct cliq_source_controller_birth creator;
    memset(&creator, 0, sizeof(creator)); creator.magic = history->creator.magic; creator.version = history->creator.version;
    creator.root = history->creator.root; creator.parent = history->creator.parent; creator.leaf = history->creator.leaf; creator.pid = history->creator.pid;
    memcpy(creator.leaf_name, history->creator.leaf_name, strlen(history->creator.leaf_name));
    memcpy(creator.process_start_token, history->creator.process_start_token, strlen(history->creator.process_start_token));
    memcpy(creator.source_header_digest, history->creator.source_header_digest, 32); memcpy(creator.digest, history->creator.digest, 32);
    if (memcmp(&creator, &history->creator, sizeof(creator))) return false;
    struct sha256_context hash; unsigned char digest[32]; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)expected, offsetof(struct cliq_source_birth, digest)); sha256_final(&hash, digest);
    if (!cliq_source_birth_origin_valid(expected) || expected->owner_uid != (uint64_t)geteuid() ||
        memcmp(digest, expected->digest, 32) != 0) return false;
    memcpy(history->digest, history->creator.digest, 32);
    uint32_t count = (uint32_t)((length - prefix) / sizeof(struct cliq_source_birth_record));
    for (uint32_t i = 0; i < count; i++) {
        struct cliq_source_birth_record record;
        memcpy(&record, bytes + prefix + (size_t)i * sizeof(record), sizeof(record));
        struct cliq_source_birth_record canonical;
        memset(&canonical, 0, sizeof(canonical)); canonical.step = record.step; canonical.kind = record.kind;
        memcpy(canonical.previous, record.previous, 32); canonical.packet = record.packet; memcpy(canonical.digest, record.digest, 32);
        if (memcmp(&canonical, &record, sizeof(canonical))) return false;
        sha256_init(&hash); sha256_update(&hash, (const unsigned char *)&record, offsetof(struct cliq_source_birth_record, digest)); sha256_final(&hash, digest);
        if (record.step != i + 1 || memcmp(record.previous, history->digest, 32) != 0 || memcmp(record.digest, digest, 32) != 0 ||
            !cliq_source_history_packet(&record.packet) ||
            !(record.kind == history->kind + 1 || (record.kind == 11 && history->kind >= 2 && history->kind <= 9)) ||
            record.kind > 12 || record.kind == 10 ||
            strcmp(record.packet.source_inspection_id, expected->inspection_id) != 0 || strcmp(record.packet.nonce, expected->staging_nonce) != 0 ||
            strcmp(record.packet.source_target_ref, expected->target_ref) != 0 || strcmp(record.packet.source_input_intent_ref, expected->input_intent_ref) != 0 ||
            record.packet.subreaper_pid != history->creator.pid || strcmp(record.packet.subreaper_start_token, history->creator.process_start_token) != 0) return false;
        if (record.kind == 9 ? !cliq_source_rule_result_valid(&record.packet) :
            record.packet.source_rule_present || record.packet.source_rule_bytes || record.packet.source_rule_digest[0]) return false;
        if (i == 0) history->first = record.packet;
        else if (!cliq_source_same_attempt(&history->first, &record.packet)) return false;
        if (record.kind == 2) history->born = record.packet;
        if (record.kind >= 2 && (record.packet.cgroup_device == 0 || record.packet.cgroup_inode == 0 ||
            record.packet.cgroup_device != history->born.cgroup_device || record.packet.cgroup_inode != history->born.cgroup_inode)) return false;
        if (record.kind == 1 && (record.packet.cgroup_device || record.packet.cgroup_inode || record.packet.pid ||
            record.packet.namespace_init_pid || record.packet.monitor_pid || record.packet.plan_ref[0])) return false;
        if (record.kind == 2 && (record.packet.pid || record.packet.namespace_init_pid || record.packet.monitor_pid || record.packet.plan_ref[0])) return false;
        if (record.kind == 3) history->blocked = record.packet;
        if (record.kind == 3 && (!cliq_source_same_prepared(&record.packet, &record.packet) || record.packet.pid ||
            record.packet.namespace_init_pid || record.packet.monitor_pid)) return false;
        if (record.kind >= 3 && history->blocked.plan_ref[0] && !cliq_source_same_prepared(&history->blocked, &record.packet)) return false;
        if (record.kind == 7) history->sealed = record.packet;
        if (record.kind == 6) history->released = true;
        if (record.kind == 8) history->continued = true;
        if (record.kind == 7 && (!cliq_source_digest(record.packet.source_snapshot_digest) || !record.packet.source_byte_count ||
            record.packet.source_byte_count > record.packet.max_generation_bytes || !record.packet.source_entry_count ||
            record.packet.source_entry_count > CLIQ_SOURCE_MAX_ENTRIES || !record.packet.source_shard_count ||
            record.packet.source_shard_count > CLIQ_SOURCE_MAX_SHARDS)) return false;
        if (record.kind == 4 && (record.packet.monitor_pid <= 0 || !record.packet.monitor_start_token[0])) return false;
        if (record.kind == 4) history->monitor = record.packet;
        if (history->monitor.monitor_pid && (record.packet.monitor_pid != history->monitor.monitor_pid ||
            strcmp(record.packet.monitor_start_token, history->monitor.monitor_start_token) != 0)) return false;
        if (record.kind == 5 && (record.packet.pid <= 0 || record.packet.namespace_init_pid <= 0 || !record.packet.start_token[0] ||
            !record.packet.init_native_start_token[0] || !record.packet.pid_namespace_inode)) return false;
        if (record.kind == 5) history->ready = record.packet;
        if (history->ready.pid && (record.packet.pid != history->ready.pid || record.packet.namespace_init_pid != history->ready.namespace_init_pid ||
            record.packet.pid_namespace_inode != history->ready.pid_namespace_inode || strcmp(record.packet.start_token, history->ready.start_token) != 0 ||
            strcmp(record.packet.init_native_start_token, history->ready.init_native_start_token) != 0)) return false;
        if (!history->ready.pid && (record.packet.pid || record.packet.namespace_init_pid || record.packet.pid_namespace_inode)) return false;
        history->last = record.packet; history->count++; history->kind = record.kind; memcpy(history->digest, digest, 32);
    }
    return true;
}
#endif
