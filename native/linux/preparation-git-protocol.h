#ifndef CLIQ_PREPARATION_GIT_PROTOCOL_H
#define CLIQ_PREPARATION_GIT_PROTOCOL_H

#include "source-git-protocol.h"
#include "worker-preparation-reservation.h"

static inline bool cliq_preparation_request_valid(const struct cliq_worker_packet *request) {
    return request->parent == 0 && request->generation_device && request->generation_inode && request->reservation_device &&
        request->reservation_inode && request->reservation_uid == (uint64_t)geteuid() && request->subreaper_pid > 0 && request->subreaper_pid <= INT32_MAX &&
        preparation_process_token(request->subreaper_start_token) && cliq_hex_digest(request->preparation_input_intent_ref) &&
        cliq_hex_digest(request->generation_ref) && cliq_hex_digest(request->nonce) && cliq_hex_digest(request->activation_nonce) &&
        !request->source_inspection_id[0] && !request->source_target_ref[0] && !request->source_input_intent_ref[0] && !request->source_exclude_grant_digest[0] &&
        !request->plan_ref[0] && !request->sandbox_launch_ref[0] && !request->sandbox_launch_digest[0];
}
static inline bool cliq_preparation_same_attempt(const struct cliq_worker_packet *left, const struct cliq_worker_packet *right) {
    return cliq_preparation_request_valid(left) && cliq_preparation_request_valid(right) && left->scope == right->scope &&
        left->generation_device == right->generation_device && left->generation_inode == right->generation_inode &&
        left->reservation_device == right->reservation_device && left->reservation_inode == right->reservation_inode && left->reservation_uid == right->reservation_uid &&
        left->subreaper_pid == right->subreaper_pid && strcmp(left->subreaper_start_token, right->subreaper_start_token) == 0 &&
        strcmp(left->preparation_input_intent_ref, right->preparation_input_intent_ref) == 0 && strcmp(left->generation_ref, right->generation_ref) == 0 &&
        strcmp(left->nonce, right->nonce) == 0 && strcmp(left->activation_nonce, right->activation_nonce) == 0 && strcmp(left->cgroup_name, right->cgroup_name) == 0 &&
        left->max_processes == right->max_processes && left->memory_bytes == right->memory_bytes && left->cpu_quota == right->cpu_quota &&
        left->max_open_files == right->max_open_files && left->max_file_bytes == right->max_file_bytes &&
        left->max_generation_bytes == right->max_generation_bytes && left->max_output_bytes == right->max_output_bytes;
}
/* Shared plumbing, separate authority families. Source-specific decoders and
 * native tags remain source-only; no preparation can pass as a source grant. */
static inline bool cliq_fixed_git_same_attempt(const struct cliq_worker_packet *left, const struct cliq_worker_packet *right) {
    return left->preparation_input_intent_ref[0] || right->preparation_input_intent_ref[0]
        ? cliq_preparation_same_attempt(left, right) : cliq_source_same_attempt(left, right);
}
static inline bool cliq_fixed_git_same_prepared(const struct cliq_worker_packet *left, const struct cliq_worker_packet *right) {
    return left->preparation_input_intent_ref[0] || right->preparation_input_intent_ref[0]
        ? cliq_preparation_same_attempt(left, right) : cliq_source_same_prepared(left, right);
}
static inline bool preparation_origin_matches_worker(const struct cliq_preparation_origin *origin, const struct cliq_worker_packet *binding) {
    return origin->reservation_device == binding->reservation_device && origin->reservation_inode == binding->reservation_inode &&
        origin->reservation_uid == binding->reservation_uid && origin->generation_device == binding->generation_device &&
        origin->generation_inode == binding->generation_inode && origin->controller_pid == (uint64_t)binding->subreaper_pid &&
        strcmp(origin->controller_token, binding->subreaper_start_token) == 0 && strcmp(origin->generation_ref, binding->generation_ref) == 0 &&
        strcmp(origin->spawn_nonce, binding->nonce) == 0 && strcmp(origin->activation_nonce, binding->activation_nonce) == 0;
}
/* Legacy records keep their exact decoder. A preparation prefix is accepted
 * only when its entire resource lifecycle precedes the original worker bind;
 * missing/partial/closed-only prefixes can never become no-spawn evidence. */
static inline bool reservation_complete_binding_offset(int fd, const struct cliq_worker_packet *expected, size_t *binding_offset) {
    unsigned char marker[8]; *binding_offset = 0;
    if (!reservation_pread_all(fd, marker, sizeof(marker), 0)) return false;
    if (memcmp(marker, "CLIQWPG2", sizeof(marker)) != 0) return true;
    unsigned char body[CLIQ_RESERVATION_BODY]; size_t offset = 0; struct cliq_preparation_origin origin;
    const size_t prefix = CLIQ_PREPARATION_MAX_FRAMES * CLIQ_PREPARATION_FRAME_BYTES; struct cliq_preparation_history history;
    if (!reservation_frame(fd, &offset, CLIQ_PREPARATION_FACT_BASE + CLIQ_PREPARATION_ORIGIN, body, sizeof(body)) ||
        !preparation_origin_decode(body, &origin) || !preparation_origin_matches_worker(&origin, expected) ||
        !preparation_history_read_prefix(fd, &origin, prefix, &history) || history.phase != CLIQ_PREPARATION_SCOPE_REMOVED ||
        history.frames != CLIQ_PREPARATION_MAX_FRAMES || !history.progress.worker_pid || !history.progress.input_bytes ||
        !cliq_hex_digest(history.progress.outputs[0].digest)) return false;
    *binding_offset = prefix; return true;
}
static inline bool reservation_read_complete(int fd, const struct cliq_worker_packet *expected, bool *attempted, struct cliq_worker_packet *actual) {
    size_t offset;
    return reservation_complete_binding_offset(fd, expected, &offset) && reservation_read_at(fd, expected, offset, attempted, actual);
}
/* Cleanup reads the original preparation prefix, optionally followed by its
 * completed final BIND. A worker intent/full birth belongs to the existing
 * preactivation/worker recovery path and is never reclassified here. */
static inline bool preparation_read_cleanup_history(int fd, const struct cliq_preparation_origin *expected,
    struct cliq_preparation_history *history) {
    struct stat before, after;
    if (fstat(fd, &before) != 0 || before.st_size <= 0 || before.st_size >
        (off_t)(CLIQ_PREPARATION_MAX_FRAMES * CLIQ_PREPARATION_FRAME_BYTES + CLIQ_RESERVATION_FULL_END)) return false;
    size_t prefix = 0; unsigned char marker[8];
    while (prefix < (size_t)before.st_size && prefix < CLIQ_PREPARATION_MAX_FRAMES * CLIQ_PREPARATION_FRAME_BYTES) {
        if (!reservation_pread_all(fd, marker, sizeof(marker), (off_t)prefix)) return false;
        if (prefix && memcmp(marker, "CLIQWRB1", sizeof(marker)) == 0) break;
        prefix += CLIQ_PREPARATION_FRAME_BYTES;
    }
    if (!preparation_history_read_prefix(fd, expected, prefix, history) || !preparation_prefix_complete(history)) return false;
    bool valid = before.st_size == (off_t)prefix;
    if (!valid && history->phase == CLIQ_PREPARATION_SCOPE_REMOVED && history->frames == CLIQ_PREPARATION_MAX_FRAMES &&
        before.st_size == (off_t)(prefix + CLIQ_RESERVATION_HEADER_END)) {
        size_t at = prefix; unsigned char body[CLIQ_RESERVATION_BODY]; struct cliq_worker_packet binding, actual; bool attempted;
        valid = reservation_frame(fd, &at, CLIQ_RESERVATION_BINDING, body, sizeof(body)) && reservation_decode(body, &binding) &&
            preparation_origin_matches_worker(expected, &binding) && reservation_read_at(fd, &binding, prefix, &attempted, &actual) && !attempted;
    }
    return valid && fstat(fd, &after) == 0 && before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}
#endif
