#ifndef CLIQ_PREPARATION_GIT_RECOVERY_H
#define CLIQ_PREPARATION_GIT_RECOVERY_H

static bool preparation_cleanup_retained(struct cliq_worker_packet *request, int *passed, size_t count,
    struct cliq_worker_packet *response) {
    source_controller_init();
    if (count != 2 || source_scope.attempted || worker_reservation.fd >= 0 || worker_creation_attempted || request->scope != 1 ||
        !cliq_preparation_request_valid(request)) return false;
    for (size_t i = 1; i < CLIQ_WORKER_MAX_SCOPES; i++) if (scopes[i].created) return false;
    source_scope.attempted = true;
    int root = passed[0], birth = passed[1], parent = -1, leaf = -1, group = -1; passed[0] = passed[1] = -1;
    struct cliq_preparation_history history = {0}, final; struct cliq_preparation_origin origin = {0}; struct stat root_identity, before, named;
    unsigned char body[CLIQ_RESERVATION_BODY]; size_t offset = 0;
    bool valid = native_cgroup(root) && fstat(root, &root_identity) == 0 && reservation_file(birth, request, &before) &&
        reservation_frame(birth, &offset, CLIQ_PREPARATION_FACT_BASE, body, sizeof(body)) && preparation_origin_decode(body, &origin) &&
        preparation_packet_origin_matches(request, &origin) && preparation_read_cleanup_history(birth, &origin, &history) &&
        root_identity.st_dev == (dev_t)origin.root.device && root_identity.st_ino == (ino_t)origin.root.inode &&
        root_identity.st_uid == origin.root.uid && root_identity.st_gid == origin.root.gid && root_identity.st_mode == origin.root.mode &&
        origin.controller_pid != (uint64_t)getpid() && origin.supervisor_pid != (uint64_t)getpid() &&
        original_process_absent((pid_t)origin.supervisor_pid, origin.supervisor_token) &&
        original_process_absent((pid_t)origin.controller_pid, origin.controller_token) && flock(birth, LOCK_EX | LOCK_NB) == 0;
    char group_name[96]; int length = snprintf(group_name, sizeof(group_name), "cliq-preparation-%s", origin.spawn_nonce);
    valid = valid && length > 0 && (size_t)length < sizeof(group_name) && strcmp(group_name, request->cgroup_name) == 0;
    if (valid) {
        parent = openat(root, "controllers", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        valid = parent >= 0 && native_cgroup(parent) && fstat(parent, &before) == 0 &&
            before.st_dev == (dev_t)origin.parent.device && before.st_ino == (ino_t)origin.parent.inode &&
            before.st_uid == origin.parent.uid && before.st_gid == origin.parent.gid && before.st_mode == origin.parent.mode &&
            fstatat(root, "controllers", &named, AT_SYMLINK_NOFOLLOW) == 0 && preparation_same_directory(&before, &named);
    }
    bool group_present = false, leaf_present = false;
    if (valid) {
        group = openat(root, group_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); group_present = group >= 0;
        valid = group_present ? history.progress.cgroup_inode && native_cgroup(group) && fstat(group, &before) == 0 &&
            (uint64_t)before.st_dev == history.progress.cgroup_device && (uint64_t)before.st_ino == history.progress.cgroup_inode &&
            before.st_dev == root_identity.st_dev && before.st_uid == geteuid() && before.st_gid == getegid() && (before.st_mode & 07777) == 0700 : errno == ENOENT;
    }
    struct tracked_set tracked = {0}; const struct cliq_preparation_progress *progress = &history.progress;
    if (valid && group_present) valid = collect_processes(group, &tracked, 0);
    if (valid && progress->monitor_pid) valid = track_process(&tracked, (pid_t)progress->monitor_pid, progress->monitor_token);
    if (valid && progress->worker_pid) valid = track_process(&tracked, (pid_t)progress->worker_pid, progress->worker_token) &&
        track_process(&tracked, (pid_t)progress->init_pid, progress->init_native_token);
    if (valid && progress->monitor_pid && !original_process_absent((pid_t)progress->monitor_pid, progress->monitor_token))
        valid = stop_retained_subreaper((pid_t)progress->monitor_pid, progress->monitor_token);
    if (valid && group_present) valid = write_control(group, "cgroup.kill", "1");
    int64_t started = milliseconds(); valid = valid && started >= 0;
    while (valid && ((group_present && !cgroup_empty(group)) || !tracked_absent(&tracked))) {
        int64_t now = milliseconds(); if (now < started || now - started >= OBSERVATION_TIMEOUT_MS) { valid = false; break; }
        struct timespec interval = {0, 10000000}; nanosleep(&interval, NULL);
    }
    if (valid) {
        leaf = openat(parent, origin.controller_leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); leaf_present = leaf >= 0;
        valid = leaf_present ? native_cgroup(leaf) && fstat(leaf, &before) == 0 && before.st_dev == (dev_t)origin.leaf.device &&
            before.st_ino == (ino_t)origin.leaf.inode && before.st_uid == origin.leaf.uid && before.st_gid == origin.leaf.gid &&
            before.st_mode == origin.leaf.mode && cgroup_empty(leaf) : errno == ENOENT;
    }
    valid = valid && original_process_absent((pid_t)origin.supervisor_pid, origin.supervisor_token) &&
        original_process_absent((pid_t)origin.controller_pid, origin.controller_token) && preparation_read_cleanup_history(birth, &origin, &final) &&
        final.frames == history.frames && final.bytes == history.bytes && memcmp(final.digest, history.digest, sizeof(final.digest)) == 0 &&
        fstat(root, &before) == 0 && before.st_dev == root_identity.st_dev && before.st_ino == root_identity.st_ino &&
        fstat(parent, &before) == 0 && before.st_dev == (dev_t)origin.parent.device && before.st_ino == (ino_t)origin.parent.inode &&
        fstatat(root, "controllers", &named, AT_SYMLINK_NOFOLLOW) == 0 && preparation_same_directory(&before, &named);
    if (valid && group_present) valid = fstat(group, &before) == 0 && (uint64_t)before.st_dev == progress->cgroup_device &&
        (uint64_t)before.st_ino == progress->cgroup_inode && cgroup_empty(group) && fstatat(root, group_name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        preparation_same_directory(&before, &named) && unlinkat(root, group_name, AT_REMOVEDIR) == 0;
    if (valid && leaf_present) valid = fstat(leaf, &before) == 0 && before.st_dev == (dev_t)origin.leaf.device && before.st_ino == (ino_t)origin.leaf.inode &&
        cgroup_empty(leaf) && fstatat(parent, origin.controller_leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        preparation_same_directory(&before, &named) && unlinkat(parent, origin.controller_leaf, AT_REMOVEDIR) == 0;
    valid = valid && fstatat(root, group_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        fstatat(parent, origin.controller_leaf, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT && tracked_absent(&tracked) &&
        original_process_absent((pid_t)origin.supervisor_pid, origin.supervisor_token) && original_process_absent((pid_t)origin.controller_pid, origin.controller_token) &&
        preparation_read_cleanup_history(birth, &origin, &final) && final.frames == history.frames && final.bytes == history.bytes &&
        memcmp(final.digest, history.digest, sizeof(final.digest)) == 0;
    if (!source_close_fd(&group)) valid = false;
    if (!source_close_fd(&leaf)) valid = false;
    if (!source_close_fd(&parent)) valid = false;
    if (!source_close_fd(&birth)) valid = false;
    if (!source_close_fd(&root)) valid = false;
    if (!valid) return false;
    *response = *request; response->reservation_observation = history.phase; response->populated = 0;
    response->remaining_descendants = 0; response->init_reaped = progress->worker_pid ? 1 : 0;
    source_scope.retired = true; return stamp_observation(response);
}
#endif
