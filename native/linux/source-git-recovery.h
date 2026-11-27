#ifndef CLIQ_SOURCE_GIT_RECOVERY_H
#define CLIQ_SOURCE_GIT_RECOVERY_H

#include "source-git-history.h"

/* Cleanup only, under a newly held controller and the original exact root.
 * No old release, resume, recapture or result can be issued by this command.
 * Original progress is never rewritten as a fictional original FD join. */
static bool source_cleanup_retained(struct cliq_worker_packet *request, int *passed, size_t count,
    struct cliq_worker_packet *response) {
    source_controller_init();
    if (count != 2 || source_scope.attempted || worker_reservation.fd >= 0 || worker_creation_attempted || request->scope != 1 ||
        !cliq_source_inspection_id(request->source_inspection_id) || !cliq_source_digest(request->nonce) ||
        !cliq_source_digest(request->source_target_ref) || !cliq_source_digest(request->source_input_intent_ref)) return false;
    for (size_t i = 1; i < CLIQ_WORKER_MAX_SCOPES; i++) if (scopes[i].created) return false;
    source_scope.attempted = true;
    int root = passed[0], birth = passed[1], parent = -1, leaf = -1, group = -1;
    passed[0] = passed[1] = -1;
    struct cliq_source_history history = {0}, final; struct cliq_source_birth header = {0}; struct stat root_identity, before, named;
    bool valid = native_cgroup(root) && fstat(root, &root_identity) == 0 &&
        cliq_source_read_exact(birth, &header, sizeof(header), 0) &&
        memcmp(header.inspection_id, request->source_inspection_id, 44) == 0 && memcmp(header.staging_nonce, request->nonce, 65) == 0 &&
        memcmp(header.target_ref, request->source_target_ref, 65) == 0 && memcmp(header.input_intent_ref, request->source_input_intent_ref, 65) == 0 &&
        cliq_source_history_read(birth, &header, &history) && cliq_source_directory_matches(&history.creator.root, &root_identity) &&
        history.creator.pid != getpid() && original_process_absent((pid_t)history.creator.pid, history.creator.process_start_token) &&
        flock(birth, LOCK_EX | LOCK_NB) == 0;
    /* Record 1 has no actual resource identity; record 3 may have forked
     * before a durable PID/token. Neither gap can manufacture no-spawn. */
    valid = valid && cliq_source_recovery_prefix_complete(&history);
    char group_name[96];
    int length = snprintf(group_name, sizeof(group_name), "cliq-source-%s", request->nonce);
    valid = valid && length == 76;
    if (valid) {
        parent = openat(root, "controllers", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        valid = parent >= 0 && native_cgroup(parent) && fstat(parent, &before) == 0 &&
            cliq_source_directory_matches(&history.creator.parent, &before) &&
            fstatat(root, "controllers", &named, AT_SYMLINK_NOFOLLOW) == 0 && cliq_source_directory_matches(&history.creator.parent, &named);
    }
    bool group_present = false, leaf_present = false;
    if (valid) {
        group = openat(root, group_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        group_present = group >= 0;
        valid = group_present ? history.kind >= 2 && native_cgroup(group) && fstat(group, &before) == 0 &&
            (uint64_t)before.st_dev == history.born.cgroup_device && (uint64_t)before.st_ino == history.born.cgroup_inode &&
            before.st_dev == root_identity.st_dev && before.st_uid == geteuid() && before.st_gid == getegid() && (before.st_mode & 07777) == 0700 : errno == ENOENT;
    }
    struct tracked_set tracked = {0};
    if (valid && group_present) valid = collect_processes(group, &tracked, 0);
    if (valid && history.monitor.monitor_pid) valid = track_process(&tracked, (pid_t)history.monitor.monitor_pid, history.monitor.monitor_start_token);
    if (valid && history.ready.pid) valid = track_process(&tracked, (pid_t)history.ready.pid, history.ready.start_token) &&
        track_process(&tracked, (pid_t)history.ready.namespace_init_pid, history.ready.init_native_start_token);
    /* A recorded pre-attach monitor may not yet be in the cgroup. Signalling
     * uses its original token and pidfd, never an unbranded current PID. */
    if (valid && history.monitor.monitor_pid &&
        !original_process_absent((pid_t)history.monitor.monitor_pid, history.monitor.monitor_start_token))
        valid = stop_retained_subreaper((pid_t)history.monitor.monitor_pid, history.monitor.monitor_start_token);
    if (valid && group_present) valid = write_control(group, "cgroup.kill", "1");
    int64_t started = milliseconds();
    valid = valid && started >= 0;
    while (valid && ((group_present && !cgroup_empty(group)) || !tracked_absent(&tracked))) {
        int64_t now = milliseconds();
        if (now < started || now - started >= OBSERVATION_TIMEOUT_MS) { valid = false; break; }
        struct timespec pause = {0, 10000000}; nanosleep(&pause, NULL);
    }
    if (valid) {
        leaf = openat(parent, history.creator.leaf_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        leaf_present = leaf >= 0;
        valid = leaf_present ? native_cgroup(leaf) && fstat(leaf, &before) == 0 &&
            cliq_source_directory_matches(&history.creator.leaf, &before) && cgroup_empty(leaf) : errno == ENOENT;
    }
    valid = valid && original_process_absent((pid_t)history.creator.pid, history.creator.process_start_token) &&
        cliq_source_history_read(birth, &header, &final) && final.count == history.count && memcmp(final.digest, history.digest, 32) == 0 &&
        fstat(root, &before) == 0 && cliq_source_directory_matches(&history.creator.root, &before) &&
        fstat(parent, &before) == 0 && cliq_source_directory_matches(&history.creator.parent, &before) &&
        fstatat(root, "controllers", &named, AT_SYMLINK_NOFOLLOW) == 0 && cliq_source_directory_matches(&history.creator.parent, &named);
    if (valid && group_present) valid = fstat(group, &before) == 0 && (uint64_t)before.st_dev == history.born.cgroup_device &&
        (uint64_t)before.st_ino == history.born.cgroup_inode && cgroup_empty(group) &&
        fstatat(root, group_name, &named, AT_SYMLINK_NOFOLLOW) == 0 && before.st_dev == named.st_dev && before.st_ino == named.st_ino &&
        unlinkat(root, group_name, AT_REMOVEDIR) == 0;
    if (valid && leaf_present) valid = fstat(leaf, &before) == 0 && cliq_source_directory_matches(&history.creator.leaf, &before) && cgroup_empty(leaf) &&
        fstatat(parent, history.creator.leaf_name, &named, AT_SYMLINK_NOFOLLOW) == 0 && cliq_source_directory_matches(&history.creator.leaf, &named) &&
        unlinkat(parent, history.creator.leaf_name, AT_REMOVEDIR) == 0;
    valid = valid && fstatat(root, group_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        fstatat(parent, history.creator.leaf_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        tracked_absent(&tracked) && original_process_absent((pid_t)history.creator.pid, history.creator.process_start_token) &&
        cliq_source_history_read(birth, &header, &final) && final.count == history.count && memcmp(final.digest, history.digest, 32) == 0;
    /* Every right received by this command is consumed before success. No
     * current inspector FD close is attributed to the retired old producer. */
    if (!source_close_fd(&group)) valid = false;
    if (!source_close_fd(&leaf)) valid = false;
    if (!source_close_fd(&parent)) valid = false;
    if (!source_close_fd(&birth)) valid = false;
    if (!source_close_fd(&root)) valid = false;
    if (!valid) return false;
    *response = *request; response->command = CLIQ_SOURCE_CLEANUP_RETAINED; response->reservation_observation = history.kind;
    response->populated = 0; response->remaining_descendants = 0; response->init_reaped = history.ready.pid ? 1 : 0;
    source_scope.retired = true; return stamp_observation(response);
}
/* This branch is observation only for original resources. A retained handoff
 * may establish their original identities, never permission to kill/unlink a
 * current object. Present/replaced paths or any live original token wait. */
static bool source_check_registered_absent(struct cliq_worker_packet *request, int *passed, size_t count,
    struct cliq_worker_packet *response) {
    source_controller_init();
    if (count != 2 || source_scope.attempted || worker_reservation.fd >= 0 || worker_creation_attempted || request->scope != 1 ||
        !cliq_source_inspection_id(request->source_inspection_id) || !cliq_source_digest(request->nonce) ||
        !cliq_source_digest(request->source_target_ref) || !cliq_source_digest(request->source_input_intent_ref)) return false;
    for (size_t i = 1; i < CLIQ_WORKER_MAX_SCOPES; i++) if (scopes[i].created) return false;
    source_scope.attempted = true;
    int root = passed[0], snapshot_fd = passed[1], parent = -1; passed[0] = passed[1] = -1;
    struct stat root_identity, observed; struct cliq_source_birth header; struct cliq_source_history history;
    unsigned char *snapshot = NULL; size_t length = 0;
    bool valid = native_cgroup(root) && fstat(root, &root_identity) == 0 &&
        cliq_source_read_exact(snapshot_fd, &header, sizeof(header), 0) &&
        memcmp(header.inspection_id, request->source_inspection_id, sizeof(header.inspection_id)) == 0 &&
        memcmp(header.staging_nonce, request->nonce, sizeof(header.staging_nonce)) == 0 &&
        memcmp(header.target_ref, request->source_target_ref, sizeof(header.target_ref)) == 0 &&
        memcmp(header.input_intent_ref, request->source_input_intent_ref, sizeof(header.input_intent_ref)) == 0 &&
        cliq_source_history_read_sealed(snapshot_fd, &header, &history, &snapshot, &length) &&
        cliq_source_recovery_prefix_complete(&history) && cliq_source_directory_matches(&history.creator.root, &root_identity) &&
        header.supervisor_pid != getpid() && original_process_absent((pid_t)header.supervisor_pid, header.supervisor_start_token) &&
        history.creator.pid != getpid() && original_process_absent((pid_t)history.creator.pid, history.creator.process_start_token);
    free(snapshot);
    if (valid) {
        parent = openat(root, "controllers", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        valid = parent >= 0 && native_cgroup(parent) && fstat(parent, &observed) == 0 &&
            cliq_source_directory_matches(&history.creator.parent, &observed) &&
            fstatat(root, "controllers", &observed, AT_SYMLINK_NOFOLLOW) == 0 && cliq_source_directory_matches(&history.creator.parent, &observed);
    }
    char group_name[96]; int named = snprintf(group_name, sizeof(group_name), "cliq-source-%s", request->nonce);
    valid = valid && named == 76 && fstatat(root, group_name, &observed, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        fstatat(parent, history.creator.leaf_name, &observed, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    if (valid && history.monitor.monitor_pid) valid = original_process_absent((pid_t)history.monitor.monitor_pid, history.monitor.monitor_start_token);
    if (valid && history.ready.pid) valid = original_process_absent((pid_t)history.ready.pid, history.ready.start_token) &&
        original_process_absent((pid_t)history.ready.namespace_init_pid, history.ready.init_native_start_token);
    valid = valid && fstat(root, &observed) == 0 && cliq_source_directory_matches(&history.creator.root, &observed) &&
        fstat(parent, &observed) == 0 && cliq_source_directory_matches(&history.creator.parent, &observed) &&
        original_process_absent((pid_t)header.supervisor_pid, header.supervisor_start_token) &&
        original_process_absent((pid_t)history.creator.pid, history.creator.process_start_token);
    if (!source_close_fd(&parent)) valid = false;
    if (!source_close_fd(&snapshot_fd)) valid = false;
    if (!source_close_fd(&root)) valid = false;
    if (!valid) return false;
    *response = *request; response->command = CLIQ_SOURCE_CHECK_REGISTERED_ABSENT;
    response->reservation_observation = history.kind; response->populated = response->remaining_descendants = 0;
    response->init_reaped = history.ready.pid ? 1 : 0;
    source_scope.retired = true; return stamp_observation(response);
}
#endif
