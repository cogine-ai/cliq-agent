#ifndef CLIQ_PREPARATION_GIT_CONTROLLER_H
#define CLIQ_PREPARATION_GIT_CONTROLLER_H

/* Same controller, same original reservation, disjoint non-executing owner.
 * The shared fixed-Git plumbing never receives a host generation payload. */
static bool preparation_same_directory(const struct stat *left, const struct stat *right) {
    return S_ISDIR(left->st_mode) && S_ISDIR(right->st_mode) && left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
        left->st_uid == right->st_uid && left->st_gid == right->st_gid && left->st_mode == right->st_mode;
}
static bool preparation_controller_origin_current(const struct cliq_preparation_origin *origin, int anchor) {
    struct stat root, parent, leaf, named; char token[CLIQ_WORKER_TOKEN_BYTES], pid[32];
    bool valid = native_cgroup(anchor) && fstat(anchor, &root) == 0 && origin->controller_pid == (uint64_t)getpid() &&
        cliq_process_token(getpid(), token) && strcmp(token, origin->controller_token) == 0 &&
        root.st_dev == (dev_t)origin->root.device && root.st_ino == (ino_t)origin->root.inode && root.st_uid == origin->root.uid &&
        root.st_gid == origin->root.gid && root.st_mode == origin->root.mode;
    int controllers = valid ? openat(anchor, "controllers", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    int directory = controllers >= 0 ? openat(controllers, origin->controller_leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
    valid = valid && controllers >= 0 && directory >= 0 && native_cgroup(controllers) && native_cgroup(directory) &&
        fstat(controllers, &parent) == 0 && parent.st_dev == (dev_t)origin->parent.device && parent.st_ino == (ino_t)origin->parent.inode &&
        parent.st_uid == origin->parent.uid && parent.st_gid == origin->parent.gid && parent.st_mode == origin->parent.mode &&
        fstatat(anchor, "controllers", &named, AT_SYMLINK_NOFOLLOW) == 0 && preparation_same_directory(&parent, &named) &&
        fstat(directory, &leaf) == 0 && leaf.st_dev == (dev_t)origin->leaf.device && leaf.st_ino == (ino_t)origin->leaf.inode &&
        leaf.st_uid == origin->leaf.uid && leaf.st_gid == origin->leaf.gid && leaf.st_mode == origin->leaf.mode &&
        fstatat(controllers, origin->controller_leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 && preparation_same_directory(&leaf, &named) &&
        source_control_equals(directory, "cgroup.procs", pid);
    if (!source_close_fd(&directory)) valid = false;
    if (!source_close_fd(&controllers)) valid = false;
    return valid;
}
static bool preparation_packet_origin_matches(const struct cliq_worker_packet *request, const struct cliq_preparation_origin *origin) {
    return cliq_preparation_request_valid(request) && preparation_origin_matches_worker(origin, request) &&
        strcmp(request->preparation_input_intent_ref, origin->input_intent_ref) == 0 &&
        request->max_processes == origin->max_processes && request->memory_bytes == origin->memory_bytes &&
        request->cpu_quota == origin->cpu_quota && request->max_open_files == origin->max_open_files &&
        request->max_file_bytes == origin->max_file_bytes && request->max_generation_bytes == origin->max_generation_bytes &&
        request->max_output_bytes == origin->max_output_bytes;
}
static bool preparation_reserve(struct cliq_worker_packet *request, int *passed, size_t count, struct cliq_worker_packet *response) {
    source_controller_init();
    if (source_scope.attempted || worker_reservation.fd >= 0 || worker_creation_attempted || request->scope == 0 || request->scope >= CLIQ_WORKER_MAX_SCOPES ||
        !cliq_preparation_request_valid(request) || count < 10 || count > CLIQ_WORKER_MAX_FDS) return false;
    for (size_t i = 1; i < CLIQ_WORKER_MAX_SCOPES; i++) if (scopes[i].created) return false;
    char group_name[96]; int length = snprintf(group_name, sizeof(group_name), "cliq-preparation-%s", request->nonce);
    if (length <= 0 || (size_t)length >= sizeof(group_name) || strcmp(group_name, request->cgroup_name) != 0) return false;
    struct stat origin_file, reservation, anchor; unsigned char body[CLIQ_RESERVATION_BODY]; struct cliq_preparation_origin origin;
    bool valid = source_read_config(passed[3], &source_scope.config) && fstat(passed[4], &origin_file) == 0 && S_ISREG(origin_file.st_mode) &&
        origin_file.st_size == CLIQ_RESERVATION_BODY && fcntl(passed[4], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
        reservation_pread_all(passed[4], body, sizeof(body), 0) && preparation_origin_decode(body, &origin) &&
        preparation_packet_origin_matches(request, &origin) && strcmp(origin.repository_digest, source_scope.config.repository_identity_digest) == 0 &&
        native_cgroup(passed[0]) && fstat(passed[0], &anchor) == 0 && preparation_controller_origin_current(&origin, passed[0]) &&
        reservation_file(passed[1], request, &reservation) && reservation.st_size == 0 && count == 8 + source_scope.config.file_count;
    for (size_t i = 5; valid && i < count; i++) {
        struct stat image; uint64_t expected = i == 5 ? source_scope.config.init_bytes : i == 7 ? source_scope.config.inspector_bytes :
            i >= 8 ? source_scope.config.files[i - 8].byte_count : 0;
        valid = fstat(passed[i], &image) == 0 && S_ISREG(image.st_mode) && image.st_size > 0 && image.st_size <= 268435456 &&
            (expected == 0 || (uint64_t)image.st_size == expected) &&
            fcntl(passed[i], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    }
    uint64_t runtime, reserve;
    if (!valid || !cliq_source_storage_reserve(&source_scope.config, request, &runtime, &reserve)) return false;
    int witness = reservation_independent(passed[1], request, true);
    if (witness < 0) return false;
    worker_reservation.fd = witness; worker_reservation.binding = *request; worker_reservation.bytes = 0; worker_reservation.binding_offset = 0;
    source_scope.attempted = true; source_scope.preparation = true; source_scope.preparation_origin = origin; source_scope.identity = *request;
    source_scope.anchor_identity = anchor;
    source_scope.birth = fcntl(witness, F_DUPFD_CLOEXEC, 4);
    if (source_scope.birth < 0) return false;
    source_scope.anchor = passed[0]; passed[0] = -1;
    source_scope.preparation_stream = passed[2]; passed[2] = -1;
    source_scope.config_fd = passed[3]; passed[3] = -1;
    source_scope.helper = passed[5]; passed[5] = -1; source_scope.bwrap = passed[6]; passed[6] = -1;
    source_scope.inspector = passed[7]; passed[7] = -1;
    for (uint32_t i = 0; i < source_scope.config.file_count; i++) { source_scope.files[i] = passed[8 + i]; passed[8 + i] = -1; }
    /* The durable original origin and create intent precede the first real
     * cgroup mutation. No growing parent-owned CAS input exists. */
    if (!preparation_history_begin(source_scope.birth, &origin) || !preparation_birth_step(1, request) ||
        mkdirat(source_scope.anchor, request->cgroup_name, 0700) != 0) return false;
    source_scope.cgroup = openat(source_scope.anchor, request->cgroup_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (source_scope.cgroup < 0 || !native_cgroup(source_scope.cgroup) || fstat(source_scope.cgroup, &source_scope.cgroup_identity) != 0) return false;
    source_scope.created = true; source_scope.identity.cgroup_device = source_scope.cgroup_identity.st_dev;
    source_scope.identity.cgroup_inode = source_scope.cgroup_identity.st_ino;
    if (!preparation_birth_step(2, &source_scope.identity) || !cgroup_empty(source_scope.cgroup) || !source_resources(request) || !source_controller_root_current()) return false;
    *response = source_scope.identity; response->command = CLIQ_PREPARATION_RESERVE; return stamp_observation(response);
}
static bool preparation_append(enum cliq_preparation_phase phase, const struct cliq_preparation_progress *progress) {
    if (!preparation_history_append(source_scope.birth, &source_scope.preparation_origin, phase, progress)) return false;
    struct stat file;
    if (fstat(worker_reservation.fd, &file) != 0 || file.st_size < 0) return false;
    worker_reservation.bytes = (size_t)file.st_size; return true;
}
static bool preparation_birth_step(uint32_t kind, const struct cliq_worker_packet *packet) {
    struct cliq_preparation_history history;
    if (!source_scope.preparation || !preparation_history_read(source_scope.birth, &source_scope.preparation_origin, &history)) return false;
    struct cliq_preparation_progress progress = history.progress; enum cliq_preparation_phase phase;
    if (kind == 6) return history.phase == CLIQ_PREPARATION_BLOCKED;
    if (kind == 8 || kind == 9) return history.phase == CLIQ_PREPARATION_INPUT_SEALED;
    switch (kind) {
        case 1: phase = CLIQ_PREPARATION_CREATE_INTENT; break;
        case 2: phase = CLIQ_PREPARATION_CGROUP; progress.cgroup_device = packet->cgroup_device; progress.cgroup_inode = packet->cgroup_inode; break;
        case 3: phase = CLIQ_PREPARATION_FORK_INTENT; break;
        case 4: phase = CLIQ_PREPARATION_MONITOR; progress.monitor_pid = packet->monitor_pid;
            memcpy(progress.monitor_token, packet->monitor_start_token, sizeof(progress.monitor_token)); break;
        case 5: phase = CLIQ_PREPARATION_BLOCKED; progress.worker_pid = packet->pid; progress.init_pid = packet->namespace_init_pid;
            progress.pid_namespace_inode = packet->pid_namespace_inode; progress.populated = 1;
            memcpy(progress.worker_token, packet->start_token, sizeof(progress.worker_token)); memcpy(progress.init_token, packet->init_start_token, sizeof(progress.init_token));
            memcpy(progress.init_native_token, packet->init_native_start_token, sizeof(progress.init_native_token)); break;
        case 7: phase = CLIQ_PREPARATION_INPUT_SEALED; progress.input_bytes = packet->source_byte_count; progress.input_entries = packet->source_entry_count;
            progress.input_shards = packet->source_shard_count; memcpy(progress.input_digest, packet->source_snapshot_digest, sizeof(progress.input_digest)); break;
        case 11: phase = CLIQ_PREPARATION_RESOURCES_CLOSED; progress.populated = packet->populated; progress.init_reaped = packet->init_reaped;
            progress.remaining_descendants = packet->remaining_descendants; break;
        case 12: phase = CLIQ_PREPARATION_SCOPE_REMOVED; break;
        default: return false;
    }
    return preparation_append(phase, &progress);
}
static bool preparation_record_result(const struct cliq_worker_packet *packet) {
    struct cliq_preparation_history history;
    if (!source_scope.preparation || !source_scope.result || !source_scope.dead || !source_scope.monitor_success ||
        !preparation_history_read(source_scope.birth, &source_scope.preparation_origin, &history)) return false;
    if (history.phase == CLIQ_PREPARATION_RESULT) {
        for (size_t i = 0; i < CLIQ_SOURCE_OUTPUTS; i++) if (history.progress.outputs[i].byte_count != packet->source_output_bytes[i] ||
            strcmp(history.progress.outputs[i].digest, packet->source_output_digests[i]) != 0) return false;
        return true;
    }
    struct cliq_preparation_progress progress = history.progress;
    progress.populated = 0; progress.init_reaped = 1; progress.remaining_descendants = 0; progress.exit_status = 0;
    for (size_t i = 0; i < CLIQ_SOURCE_OUTPUTS; i++) { progress.outputs[i].byte_count = packet->source_output_bytes[i];
        memcpy(progress.outputs[i].digest, packet->source_output_digests[i], sizeof(progress.outputs[i].digest)); }
    return preparation_append(CLIQ_PREPARATION_RESULT, &progress);
}
static bool preparation_finish(struct cliq_worker_packet *request, struct cliq_worker_packet *response, bool completed) {
    if (!source_scope.preparation || source_scope.retired || !source_controller_same(request)) return false;
    struct cliq_preparation_history history;
    if (!preparation_history_read(source_scope.birth, &source_scope.preparation_origin, &history)) return false;
    if (completed && (history.phase != CLIQ_PREPARATION_RESULT || !source_scope.result || !source_scope.dead || !source_scope.monitor_success)) return false;
    /* The original tagged receiver sends this only after actual output
     * readers and every issued TS/CAS consumer join. EOF alone cannot do so. */
    if (history.phase == CLIQ_PREPARATION_RESULT && !preparation_append(CLIQ_PREPARATION_CONSUMERS_JOINED, &history.progress)) return false;
    if (!source_retire(response)) return false;
    source_scope.preparation_completed = completed; response->command = request->command;
    response->reservation_observation = completed ? 1 : 0; return true;
}
static bool worker_preparation_final_binding(const struct cliq_worker_packet *request, int passed[CLIQ_WORKER_MAX_FDS], size_t count) {
    const struct cliq_preparation_origin *origin = &source_scope.preparation_origin;
    struct stat file, absent;
    if (count != 2 || !source_scope.preparation || !source_scope.retired || !source_scope.preparation_completed || worker_creation_attempted ||
        request->scope != 0 || !reservation_binding_valid(request) || !preparation_origin_matches_worker(origin, request) ||
        !reservation_file(passed[0], request, &file) || !preparation_controller_origin_current(origin, passed[1]) ||
        fstatat(passed[1], source_scope.identity.cgroup_name, &absent, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return false;
    struct cliq_preparation_history history;
    if (!preparation_history_read(worker_reservation.fd, origin, &history) || history.phase != CLIQ_PREPARATION_SCOPE_REMOVED ||
        history.frames != CLIQ_PREPARATION_MAX_FRAMES || file.st_size != (off_t)history.bytes) return false;
    worker_reservation.binding = *request; worker_reservation.binding_offset = history.bytes; worker_reservation.bytes = history.bytes;
    unsigned char body[CLIQ_RESERVATION_BODY]; reservation_encode(body, request);
    return reservation_append(&worker_reservation, CLIQ_RESERVATION_BINDING, body, sizeof(body));
}
#endif
