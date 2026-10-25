/* Versioned preparation prefix on the ORIGINAL WorkerReservation file.
 * Parsing these bytes grants no execution, promotion, cleanup or death proof.
 * Native callers must separately own/recheck the original physical lifetime. */
#ifndef CLIQ_WORKER_PREPARATION_RESERVATION_H
#define CLIQ_WORKER_PREPARATION_RESERVATION_H

#include "worker-reservation.h"

enum cliq_preparation_phase {
    CLIQ_PREPARATION_ORIGIN = 0, CLIQ_PREPARATION_CREATE_INTENT = 1, CLIQ_PREPARATION_CGROUP = 2,
    CLIQ_PREPARATION_FORK_INTENT = 3, CLIQ_PREPARATION_MONITOR = 4, CLIQ_PREPARATION_BLOCKED = 5,
    CLIQ_PREPARATION_INPUT_SEALED = 6, CLIQ_PREPARATION_RESULT = 7, CLIQ_PREPARATION_CONSUMERS_JOINED = 8,
    CLIQ_PREPARATION_RESOURCES_CLOSED = 9, CLIQ_PREPARATION_SCOPE_REMOVED = 10
};
#define CLIQ_PREPARATION_FACT_BASE 100U
#define CLIQ_PREPARATION_MAX_FRAMES 11U
#define CLIQ_PREPARATION_FRAME_BYTES (CLIQ_RESERVATION_BODY + CLIQ_RESERVATION_FOOTER)
struct cliq_preparation_directory { uint64_t device, inode, uid, gid, mode; };
struct cliq_preparation_origin {
    uint64_t owner_epoch, controller_pid, supervisor_pid, reservation_device, reservation_inode, reservation_uid, generation_device, generation_inode;
    uint64_t max_processes, memory_bytes, cpu_quota, max_open_files, max_file_bytes, max_generation_bytes,
        max_output_bytes, max_ipc_frame_bytes, max_queued_ipc_bytes;
    struct cliq_preparation_directory root, parent, leaf;
    char session_id[129], run_id[129], launch_id[44], checkpoint_id[129], supervisor_id[129];
    char state_owner_digest[65], generation_ref[65], source_workspace_ref[65], repository_digest[65], input_intent_ref[65],
        creation_nonce[65], spawn_nonce[65], activation_nonce[65];
    char controller_leaf[64], controller_token[CLIQ_WORKER_TOKEN_BYTES], supervisor_token[128];
};
_Static_assert(16U + 17U * 8U + 3U * 5U * 8U + 4U * 129U + 44U + 8U * 65U + 64U + CLIQ_WORKER_TOKEN_BYTES + 128U <= CLIQ_RESERVATION_BODY,
    "fixed preparation origin must fit the original bounded reservation frame");
static inline bool preparation_id(const char value[44]) {
    if (strnlen(value, 44) != 43) return false;
    for (size_t i = 0; i < 43; i++) if (!((value[i] >= 'A' && value[i] <= 'Z') || (value[i] >= 'a' && value[i] <= 'z') ||
        (value[i] >= '0' && value[i] <= '9') || value[i] == '-' || value[i] == '_')) return false;
    return true;
}
static inline bool preparation_owner_id(const char value[129]) {
    size_t length = strnlen(value, 129); if (length < 1 || length > 128) return false;
    for (size_t i = 0; i < length; i++) if (!((value[i] >= 'A' && value[i] <= 'Z') || (value[i] >= 'a' && value[i] <= 'z') ||
        (value[i] >= '0' && value[i] <= '9') || value[i] == '-' || value[i] == '_')) return false;
    return true;
}
static inline bool preparation_process_token(const char value[CLIQ_WORKER_TOKEN_BYTES]) {
    const char prefix[] = "linux-proc-start-ticks:"; size_t length = strnlen(value, CLIQ_WORKER_TOKEN_BYTES);
    if (length <= sizeof(prefix) - 1 || length > sizeof(prefix) - 1 + 20 || memcmp(value, prefix, sizeof(prefix) - 1) != 0) return false;
    if (value[sizeof(prefix) - 1] == '0' && length > sizeof(prefix)) return false;
    for (size_t i = sizeof(prefix) - 1; i < length; i++) if (value[i] < '0' || value[i] > '9') return false;
    return true;
}
static inline bool preparation_origin_valid(const struct cliq_preparation_origin *origin) {
    if (!origin->owner_epoch || origin->owner_epoch > UINT64_C(9007199254740991) || !origin->controller_pid || origin->controller_pid > INT32_MAX ||
        !origin->reservation_device || !origin->reservation_inode || origin->reservation_uid != (uint64_t)geteuid() ||
        !origin->generation_device || !origin->generation_inode || !preparation_process_token(origin->controller_token) ||
        !origin->supervisor_pid || origin->supervisor_pid > INT32_MAX || origin->supervisor_pid == origin->controller_pid ||
        strnlen(origin->controller_leaf, sizeof(origin->controller_leaf)) != 43 || memcmp(origin->controller_leaf, "controller-", 11) != 0) return false;
    char supervisor_token[CLIQ_WORKER_TOKEN_BYTES] = {0}; memcpy(supervisor_token, origin->supervisor_token, sizeof(origin->supervisor_token));
    if (!preparation_process_token(supervisor_token)) return false;
    for (size_t i = 11; i < 43; i++) if (!((origin->controller_leaf[i] >= 'a' && origin->controller_leaf[i] <= 'f') ||
        (origin->controller_leaf[i] >= '0' && origin->controller_leaf[i] <= '9'))) return false;
    const struct cliq_preparation_directory *directories[] = { &origin->root, &origin->parent, &origin->leaf };
    for (size_t i = 0; i < 3; i++) if (!directories[i]->device || !directories[i]->inode || directories[i]->uid != (uint64_t)geteuid() ||
        directories[i]->gid > UINT32_MAX || directories[i]->mode != (S_IFDIR | 0700)) return false;
    if (!preparation_owner_id(origin->session_id) || !preparation_owner_id(origin->run_id) || !preparation_id(origin->launch_id) ||
        !preparation_owner_id(origin->checkpoint_id) || !preparation_owner_id(origin->supervisor_id)) return false;
    const char *digests[] = { origin->state_owner_digest, origin->generation_ref, origin->source_workspace_ref, origin->repository_digest,
        origin->input_intent_ref, origin->creation_nonce, origin->spawn_nonce, origin->activation_nonce };
    for (size_t i = 0; i < sizeof(digests) / sizeof(digests[0]); i++) if (!cliq_hex_digest(digests[i])) return false;
    return origin->max_processes >= 3 && origin->max_processes <= 1024 && origin->memory_bytes >= UINT64_C(268435456) &&
        origin->memory_bytes <= UINT64_C(34359738368) && origin->cpu_quota >= 10000 && origin->cpu_quota <= 1600000 &&
        origin->max_open_files >= 64 && origin->max_open_files <= 8192 && origin->max_file_bytes >= UINT64_C(1048576) &&
        origin->max_file_bytes <= UINT64_C(17179869184) && origin->max_generation_bytes >= UINT64_C(268435456) &&
        origin->max_generation_bytes <= UINT64_C(107374182400) && origin->max_output_bytes >= 65536 && origin->max_output_bytes <= UINT64_C(67108864) &&
        origin->max_ipc_frame_bytes == UINT64_C(16777216) && origin->max_queued_ipc_bytes == UINT64_C(67108864);
}
static inline void preparation_origin_encode(unsigned char body[CLIQ_RESERVATION_BODY], const struct cliq_preparation_origin *origin) {
    memset(body, 0, CLIQ_RESERVATION_BODY); memcpy(body, "CLIQWPG2", 8); unsigned char *cursor = body + 16;
#define P_NUMBER(name) reservation_u64(&cursor, origin->name)
    P_NUMBER(owner_epoch); P_NUMBER(controller_pid); P_NUMBER(supervisor_pid); P_NUMBER(reservation_device); P_NUMBER(reservation_inode); P_NUMBER(reservation_uid);
    P_NUMBER(generation_device); P_NUMBER(generation_inode); P_NUMBER(max_processes); P_NUMBER(memory_bytes); P_NUMBER(cpu_quota);
    P_NUMBER(max_open_files); P_NUMBER(max_file_bytes); P_NUMBER(max_generation_bytes); P_NUMBER(max_output_bytes);
    P_NUMBER(max_ipc_frame_bytes); P_NUMBER(max_queued_ipc_bytes);
#undef P_NUMBER
    const struct cliq_preparation_directory *directories[] = { &origin->root, &origin->parent, &origin->leaf };
    for (size_t i = 0; i < 3; i++) { reservation_u64(&cursor, directories[i]->device); reservation_u64(&cursor, directories[i]->inode);
        reservation_u64(&cursor, directories[i]->uid); reservation_u64(&cursor, directories[i]->gid); reservation_u64(&cursor, directories[i]->mode); }
#define P_TEXT(name) reservation_text(&cursor, origin->name, sizeof(origin->name))
    P_TEXT(session_id); P_TEXT(run_id); P_TEXT(launch_id); P_TEXT(checkpoint_id); P_TEXT(supervisor_id); P_TEXT(state_owner_digest);
    P_TEXT(generation_ref); P_TEXT(source_workspace_ref); P_TEXT(repository_digest); P_TEXT(input_intent_ref); P_TEXT(creation_nonce);
    P_TEXT(spawn_nonce); P_TEXT(activation_nonce); P_TEXT(controller_leaf); P_TEXT(controller_token); P_TEXT(supervisor_token);
#undef P_TEXT
}
static inline bool preparation_origin_decode(const unsigned char body[CLIQ_RESERVATION_BODY], struct cliq_preparation_origin *origin) {
    memset(origin, 0, sizeof(*origin)); const unsigned char *cursor = body + 16;
#define P_NUMBER(name) origin->name = reservation_read_u64(&cursor)
    P_NUMBER(owner_epoch); P_NUMBER(controller_pid); P_NUMBER(supervisor_pid); P_NUMBER(reservation_device); P_NUMBER(reservation_inode); P_NUMBER(reservation_uid);
    P_NUMBER(generation_device); P_NUMBER(generation_inode); P_NUMBER(max_processes); P_NUMBER(memory_bytes); P_NUMBER(cpu_quota);
    P_NUMBER(max_open_files); P_NUMBER(max_file_bytes); P_NUMBER(max_generation_bytes); P_NUMBER(max_output_bytes);
    P_NUMBER(max_ipc_frame_bytes); P_NUMBER(max_queued_ipc_bytes);
#undef P_NUMBER
    struct cliq_preparation_directory *directories[] = { &origin->root, &origin->parent, &origin->leaf };
    for (size_t i = 0; i < 3; i++) { directories[i]->device = reservation_read_u64(&cursor); directories[i]->inode = reservation_read_u64(&cursor);
        directories[i]->uid = reservation_read_u64(&cursor); directories[i]->gid = reservation_read_u64(&cursor); directories[i]->mode = reservation_read_u64(&cursor); }
#define P_TEXT(name) if (!reservation_read_text(&cursor, origin->name, sizeof(origin->name))) return false
    P_TEXT(session_id); P_TEXT(run_id); P_TEXT(launch_id); P_TEXT(checkpoint_id); P_TEXT(supervisor_id); P_TEXT(state_owner_digest);
    P_TEXT(generation_ref); P_TEXT(source_workspace_ref); P_TEXT(repository_digest); P_TEXT(input_intent_ref); P_TEXT(creation_nonce);
    P_TEXT(spawn_nonce); P_TEXT(activation_nonce); P_TEXT(controller_leaf); P_TEXT(controller_token); P_TEXT(supervisor_token);
#undef P_TEXT
    unsigned char canonical[CLIQ_RESERVATION_BODY]; preparation_origin_encode(canonical, origin);
    return memcmp(body, canonical, CLIQ_RESERVATION_BODY) == 0 && preparation_origin_valid(origin);
}
static inline bool preparation_origin_same(const struct cliq_preparation_origin *left, const struct cliq_preparation_origin *right) {
    unsigned char a[CLIQ_RESERVATION_BODY], b[CLIQ_RESERVATION_BODY]; preparation_origin_encode(a, left); preparation_origin_encode(b, right);
    return memcmp(a, b, CLIQ_RESERVATION_BODY) == 0;
}
struct cliq_preparation_history {
    struct cliq_preparation_origin origin;
    enum cliq_preparation_phase phase;
    size_t bytes, frames;
    unsigned char digest[32], origin_digest[32];
    struct cliq_preparation_progress {
        uint64_t cgroup_device, cgroup_inode, monitor_pid, worker_pid, init_pid, pid_namespace_inode;
        uint64_t input_bytes, input_entries, input_shards, exit_status, populated, remaining_descendants, init_reaped;
        char monitor_token[CLIQ_WORKER_TOKEN_BYTES], worker_token[CLIQ_WORKER_TOKEN_BYTES],
            init_token[CLIQ_WORKER_TOKEN_BYTES], init_native_token[CLIQ_WORKER_TOKEN_BYTES], input_digest[65];
        struct { uint64_t byte_count; char digest[65]; } outputs[4];
    } progress;
};
_Static_assert(96U + 13U * 8U + 4U * CLIQ_WORKER_TOKEN_BYTES + 65U + 4U * 73U <= CLIQ_RESERVATION_BODY,
    "fixed preparation progress must fit the original bounded reservation frame");
static inline bool preparation_transition(enum cliq_preparation_phase previous, enum cliq_preparation_phase next) {
    return (previous < CLIQ_PREPARATION_SCOPE_REMOVED && next == previous + 1) ||
        (next == CLIQ_PREPARATION_RESOURCES_CLOSED && (previous == CLIQ_PREPARATION_CGROUP || previous == CLIQ_PREPARATION_MONITOR ||
            previous == CLIQ_PREPARATION_BLOCKED || previous == CLIQ_PREPARATION_INPUT_SEALED));
}
static inline void preparation_progress_encode(unsigned char body[CLIQ_RESERVATION_BODY], enum cliq_preparation_phase phase, uint64_t step,
    const unsigned char origin_digest[32], const unsigned char previous_digest[32], const struct cliq_preparation_progress *progress) {
    memset(body, 0, CLIQ_RESERVATION_BODY); memcpy(body, "CLIQWPF2", 8); unsigned char *cursor = body + 16;
    reservation_u64(&cursor, phase); reservation_u64(&cursor, step);
    memcpy(cursor, origin_digest, 32); cursor += 32; memcpy(cursor, previous_digest, 32); cursor += 32;
#define P_NUMBER(name) reservation_u64(&cursor, progress->name)
    P_NUMBER(cgroup_device); P_NUMBER(cgroup_inode); P_NUMBER(monitor_pid); P_NUMBER(worker_pid); P_NUMBER(init_pid); P_NUMBER(pid_namespace_inode);
    P_NUMBER(input_bytes); P_NUMBER(input_entries); P_NUMBER(input_shards); P_NUMBER(exit_status); P_NUMBER(populated); P_NUMBER(remaining_descendants); P_NUMBER(init_reaped);
#undef P_NUMBER
#define P_TEXT(name) reservation_text(&cursor, progress->name, sizeof(progress->name))
    P_TEXT(monitor_token); P_TEXT(worker_token); P_TEXT(init_token); P_TEXT(init_native_token); P_TEXT(input_digest);
#undef P_TEXT
    for (size_t i = 0; i < 4; i++) { reservation_u64(&cursor, progress->outputs[i].byte_count);
        reservation_text(&cursor, progress->outputs[i].digest, sizeof(progress->outputs[i].digest)); }
}
static inline bool preparation_progress_decode(const unsigned char body[CLIQ_RESERVATION_BODY], const struct cliq_preparation_history *history,
    enum cliq_preparation_phase *phase, struct cliq_preparation_progress *progress) {
    memset(progress, 0, sizeof(*progress)); const unsigned char *cursor = body + 16;
    uint64_t raw_phase = reservation_read_u64(&cursor), step = reservation_read_u64(&cursor);
    if (raw_phase > CLIQ_PREPARATION_SCOPE_REMOVED || step != history->frames || memcmp(cursor, history->origin_digest, 32) != 0 ||
        memcmp(cursor + 32, history->digest, 32) != 0) return false;
    *phase = (enum cliq_preparation_phase)raw_phase; cursor += 64;
#define P_NUMBER(name) progress->name = reservation_read_u64(&cursor)
    P_NUMBER(cgroup_device); P_NUMBER(cgroup_inode); P_NUMBER(monitor_pid); P_NUMBER(worker_pid); P_NUMBER(init_pid); P_NUMBER(pid_namespace_inode);
    P_NUMBER(input_bytes); P_NUMBER(input_entries); P_NUMBER(input_shards); P_NUMBER(exit_status); P_NUMBER(populated); P_NUMBER(remaining_descendants); P_NUMBER(init_reaped);
#undef P_NUMBER
#define P_TEXT(name) if (!reservation_read_text(&cursor, progress->name, sizeof(progress->name))) return false
    P_TEXT(monitor_token); P_TEXT(worker_token); P_TEXT(init_token); P_TEXT(init_native_token); P_TEXT(input_digest);
#undef P_TEXT
    for (size_t i = 0; i < 4; i++) { progress->outputs[i].byte_count = reservation_read_u64(&cursor);
        if (!reservation_read_text(&cursor, progress->outputs[i].digest, sizeof(progress->outputs[i].digest))) return false; }
    unsigned char canonical[CLIQ_RESERVATION_BODY];
    preparation_progress_encode(canonical, *phase, step, history->origin_digest, history->digest, progress);
    return memcmp(body, canonical, CLIQ_RESERVATION_BODY) == 0;
}
static inline bool preparation_progress_valid(const struct cliq_preparation_history *history, enum cliq_preparation_phase phase,
    const struct cliq_preparation_progress *progress) {
    if (!preparation_transition(history->phase, phase)) return false;
    const char *tokens[] = { progress->monitor_token, progress->worker_token, progress->init_token, progress->init_native_token };
    for (size_t i = 0; i < 4; i++) if (strnlen(tokens[i], CLIQ_WORKER_TOKEN_BYTES) >= CLIQ_WORKER_TOKEN_BYTES) return false;
    struct cliq_preparation_progress expected = history->progress;
    if (phase == CLIQ_PREPARATION_CGROUP) {
        if (!progress->cgroup_device || !progress->cgroup_inode) return false;
        expected.cgroup_device = progress->cgroup_device; expected.cgroup_inode = progress->cgroup_inode;
    } else if (phase == CLIQ_PREPARATION_MONITOR) {
        if (!progress->monitor_pid || progress->monitor_pid > INT32_MAX || !preparation_process_token(progress->monitor_token)) return false;
        expected.monitor_pid = progress->monitor_pid; memcpy(expected.monitor_token, progress->monitor_token, sizeof(expected.monitor_token));
    } else if (phase == CLIQ_PREPARATION_BLOCKED) {
        if (!progress->worker_pid || progress->worker_pid > INT32_MAX || !progress->init_pid || progress->init_pid > INT32_MAX ||
            progress->worker_pid == progress->init_pid || !progress->pid_namespace_inode || !preparation_process_token(progress->worker_token) ||
            !preparation_process_token(progress->init_native_token)) return false;
        char init_token[CLIQ_WORKER_TOKEN_BYTES]; int length = snprintf(init_token, sizeof(init_token), "linux-namespace-init:%llu:%s:monitor:%llu:%s",
            (unsigned long long)progress->init_pid, progress->init_native_token + strlen("linux-proc-start-ticks:"),
            (unsigned long long)expected.monitor_pid, expected.monitor_token + strlen("linux-proc-start-ticks:"));
        if (length <= 0 || (size_t)length >= sizeof(init_token) || strcmp(init_token, progress->init_token) != 0) return false;
        expected.worker_pid = progress->worker_pid; expected.init_pid = progress->init_pid; expected.pid_namespace_inode = progress->pid_namespace_inode;
        memcpy(expected.worker_token, progress->worker_token, sizeof(expected.worker_token)); memcpy(expected.init_token, progress->init_token, sizeof(expected.init_token));
        memcpy(expected.init_native_token, progress->init_native_token, sizeof(expected.init_native_token)); expected.populated = 1;
    } else if (phase == CLIQ_PREPARATION_INPUT_SEALED) {
        if (!cliq_hex_digest(progress->input_digest) || !progress->input_bytes || progress->input_bytes > history->origin.max_generation_bytes ||
            !progress->input_entries || progress->input_entries > 100000 || !progress->input_shards || progress->input_shards > 16 ||
            progress->input_shards + 12 >= history->origin.max_open_files) return false;
        expected.input_bytes = progress->input_bytes; expected.input_entries = progress->input_entries; expected.input_shards = progress->input_shards;
        memcpy(expected.input_digest, progress->input_digest, sizeof(expected.input_digest));
    } else if (phase == CLIQ_PREPARATION_RESULT) {
        uint64_t total = 0;
        for (size_t i = 0; i < 4; i++) {
            if (!cliq_hex_digest(progress->outputs[i].digest) || progress->outputs[i].byte_count > history->origin.max_file_bytes ||
                (i == 0 && progress->outputs[i].byte_count > history->origin.max_output_bytes) || total > history->origin.max_generation_bytes ||
                progress->outputs[i].byte_count > history->origin.max_generation_bytes - total) return false;
            total += progress->outputs[i].byte_count; expected.outputs[i] = progress->outputs[i];
        }
        if (progress->exit_status != 0) return false;
        expected.exit_status = progress->exit_status; expected.populated = 0; expected.init_reaped = 1;
    } else if (phase == CLIQ_PREPARATION_RESOURCES_CLOSED) {
        expected.populated = 0; expected.init_reaped = expected.worker_pid ? 1 : 0;
    }
    unsigned char actual_bytes[CLIQ_RESERVATION_BODY], expected_bytes[CLIQ_RESERVATION_BODY];
    preparation_progress_encode(actual_bytes, phase, history->frames, history->origin_digest, history->digest, progress);
    preparation_progress_encode(expected_bytes, phase, history->frames, history->origin_digest, history->digest, &expected);
    return memcmp(actual_bytes, expected_bytes, sizeof(actual_bytes)) == 0;
}
static inline bool preparation_prefix_complete(const struct cliq_preparation_history *history) {
    /* Durable intent without its actual inode or monitor token is uncertain. */
    return history->phase != CLIQ_PREPARATION_CREATE_INTENT && history->phase != CLIQ_PREPARATION_FORK_INTENT;
}
static inline struct cliq_worker_packet preparation_reservation_binding(const struct cliq_preparation_origin *origin) {
    struct cliq_worker_packet binding = cliq_packet(CLIQ_BIND_RESERVATION);
    binding.reservation_device = origin->reservation_device; binding.reservation_inode = origin->reservation_inode;
    binding.reservation_uid = origin->reservation_uid; return binding;
}
static inline bool preparation_history_begin(int fd, const struct cliq_preparation_origin *origin) {
    struct cliq_reservation writer = { .fd = fd, .binding = preparation_reservation_binding(origin), .bytes = 0 };
    struct stat file; unsigned char body[CLIQ_RESERVATION_BODY];
    if (!preparation_origin_valid(origin) || !reservation_file(fd, &writer.binding, &file) || file.st_size != 0 ||
        flock(fd, LOCK_EX | LOCK_NB) != 0 || lseek(fd, 0, SEEK_SET) != 0) return false;
    preparation_origin_encode(body, origin);
    return reservation_append(&writer, CLIQ_PREPARATION_FACT_BASE + CLIQ_PREPARATION_ORIGIN, body, sizeof(body));
}
static inline bool preparation_history_read_prefix(int fd, const struct cliq_preparation_origin *expected, size_t prefix_bytes,
    struct cliq_preparation_history *history) {
    struct stat before, after; struct cliq_worker_packet binding = preparation_reservation_binding(expected);
    unsigned char body[CLIQ_RESERVATION_BODY]; size_t offset = 0; memset(history, 0, sizeof(*history));
    if (!preparation_origin_valid(expected) || !reservation_file(fd, &binding, &before) || before.st_size < (off_t)prefix_bytes ||
        prefix_bytes < CLIQ_PREPARATION_FRAME_BYTES || prefix_bytes > CLIQ_PREPARATION_MAX_FRAMES * CLIQ_PREPARATION_FRAME_BYTES ||
        prefix_bytes % CLIQ_PREPARATION_FRAME_BYTES != 0 ||
        !reservation_frame(fd, &offset, CLIQ_PREPARATION_FACT_BASE + CLIQ_PREPARATION_ORIGIN, body, sizeof(body)) ||
        !preparation_origin_decode(body, &history->origin) || !preparation_origin_same(expected, &history->origin)) return false;
    struct sha256_context hash; sha256_init(&hash); sha256_update(&hash, body, sizeof(body)); sha256_final(&hash, history->digest);
    memcpy(history->origin_digest, history->digest, 32); history->frames = 1; history->phase = CLIQ_PREPARATION_ORIGIN;
    while (offset < prefix_bytes) {
        struct cliq_preparation_progress progress; enum cliq_preparation_phase phase;
        if (!reservation_pread_all(fd, body, sizeof(body), (off_t)offset) || !preparation_progress_decode(body, history, &phase, &progress) ||
            !preparation_progress_valid(history, phase, &progress) ||
            !reservation_frame(fd, &offset, CLIQ_PREPARATION_FACT_BASE + phase, body, sizeof(body))) return false;
        sha256_init(&hash); sha256_update(&hash, body, sizeof(body)); sha256_final(&hash, history->digest);
        history->frames++; history->phase = phase; history->progress = progress;
    }
    if (!reservation_file(fd, &binding, &after) || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) return false;
    history->bytes = offset; return true;
}
static inline bool preparation_history_read(int fd, const struct cliq_preparation_origin *expected, struct cliq_preparation_history *history) {
    struct stat file, after;
    return fstat(fd, &file) == 0 && file.st_size >= 0 && preparation_history_read_prefix(fd, expected, (size_t)file.st_size, history) &&
        fstat(fd, &after) == 0 && after.st_size == file.st_size;
}
static inline bool preparation_history_append(int fd, const struct cliq_preparation_origin *origin, enum cliq_preparation_phase phase,
    const struct cliq_preparation_progress *progress) {
    struct cliq_preparation_history history;
    if (!preparation_history_read(fd, origin, &history) || history.frames >= CLIQ_PREPARATION_MAX_FRAMES ||
        !preparation_progress_valid(&history, phase, progress) || flock(fd, LOCK_EX | LOCK_NB) != 0 ||
        lseek(fd, (off_t)history.bytes, SEEK_SET) != (off_t)history.bytes) return false;
    unsigned char body[CLIQ_RESERVATION_BODY];
    preparation_progress_encode(body, phase, history.frames, history.origin_digest, history.digest, progress);
    struct cliq_reservation writer = { .fd = fd, .binding = preparation_reservation_binding(origin), .bytes = history.bytes };
    return reservation_append(&writer, CLIQ_PREPARATION_FACT_BASE + phase, body, sizeof(body));
}
#endif
