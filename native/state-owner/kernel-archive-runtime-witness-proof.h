/* Readonly observation of an already-retired original local-service witness.
 * Linux authority comes from the parent's genuine EX and the installed
 * Anchor borrow. This code never writes cgroup controls, starts or signals a
 * process, adopts a service, or changes the original birth transcript. */
#ifdef __linux__
#include "../linux/local-inference-birth.h"
_Static_assert(sizeof(struct cliq_local_birth_frame) == RW_FRAME, "archive witness frame layout changed");
_Static_assert(offsetof(struct cliq_local_birth_frame, packet) + offsetof(struct cliq_local_service_packet, binding) +
    offsetof(struct cliq_local_service_binding, launch) == 618, "archive witness launch offset changed");
_Static_assert(offsetof(struct cliq_local_birth_frame, packet) + offsetof(struct cliq_local_service_packet, binding) +
    offsetof(struct cliq_local_service_binding, native_nonce) == 2429, "archive witness nonce offset changed");
struct rw_retirement_observation {
    int anchor_fd, witness_fd;
    struct stat anchor, file;
    struct cliq_local_birth_frame first, last;
    struct sha256_context hash;
    uint64_t offset;
    uint32_t frames;
    unsigned int retirement_kind;
    int namespace_intent, ready;
};
static int rw_retire_observer(rw_archive *held) {
    rw_retirement_observation *proof = held->retirement; if (!proof) return 0;
    int failed = rw_close_fd(held, &proof->witness_fd) != 0;
    if (rw_close_fd(held, &proof->anchor_fd) != 0) failed = 1;
    if (failed) return -1;
    free(proof); held->retirement = NULL; return 0;
}
static int rw_birth_identity(const struct cliq_local_birth_identity *identity, const struct stat *actual) {
    return identity->device == ma_device(actual) && identity->inode == (uint64_t)actual->st_ino &&
        identity->uid == (uint64_t)actual->st_uid && identity->gid == (uint64_t)actual->st_gid && identity->mode == (uint64_t)actual->st_mode;
}
static int rw_observation_current(const rw_archive *held) {
    const rw_retirement_observation *proof = held->retirement; struct stat actual, named;
    return proof && rw_custody(held) == 0 && fstat(proof->anchor_fd, &actual) == 0 && same_inode(&actual, &proof->anchor) &&
        fstat(proof->witness_fd, &actual) == 0 && rw_witness_file(held, &actual) && source_metadata_same(&actual, &proof->file) &&
        fstatat(held->source_fd, proof->first.packet.binding.native_nonce, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        source_metadata_same(&actual, &named);
}
static inline int rw_begin_retired_observation(rw_archive *held, int anchor_fd, const unsigned char *origin,
                                               size_t size, unsigned int kind) {
    if (!held || held->failed || held->retirement || held->witness_fd >= 0 || rw_custody(held) != 0 || anchor_fd < 0 ||
        size != sizeof(struct cliq_local_birth_frame) || (kind != 1 && kind != 2) || held->physically_observed >= held->count ||
        (held->phase != RW_CAPTURE && held->phase != RW_COMPLETE) ||
        (held->capture_writer && (held->observation_ready || held->physically_observed != held->witnessed))) return -1;
    rw_retirement_observation *proof = calloc(1, sizeof(*proof)); if (!proof) return -1;
    held->retirement = proof; proof->anchor_fd = proof->witness_fd = -1; proof->retirement_kind = kind;
    memcpy(&proof->first, origin, sizeof(proof->first));
    const struct cliq_local_birth_frame *first = &proof->first;
    const struct cliq_local_service_binding *binding = &first->packet.binding;
    if (first->magic != CLIQ_LOCAL_BIRTH_MAGIC || first->step != CLIQ_LOCAL_BIRTH_RESERVED || first->ordinal != 1 ||
        !cliq_local_service_binding_valid(binding) || !rw_launch_id((const unsigned char *)binding->launch) ||
        binding->launch[43] || strcmp(held->observed_launch, binding->launch) >= 0 ||
        !rw_birth_identity(&first->state_root, &held->binding->owner->root) ||
        !rw_birth_identity(&first->runtime, &held->binding->owner->runtime) ||
        !rw_birth_identity(&first->private_parent, &held->source)) return -1;
    proof->anchor_fd = fcntl(anchor_fd, F_DUPFD_CLOEXEC, 0);
    if (proof->anchor_fd < 0 || !installed_keeper_cgroup_identity(proof->anchor_fd, geteuid(), getegid(), &proof->anchor, 1) ||
        !rw_birth_identity(&first->controller_anchor, &proof->anchor)) return -1;
    proof->witness_fd = openat(held->source_fd, binding->native_nonce, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (proof->witness_fd < 0 || flock(proof->witness_fd, LOCK_EX | LOCK_NB) != 0 || fstat(proof->witness_fd, &proof->file) != 0 ||
        !rw_witness_file(held, &proof->file) || !rw_birth_identity(&first->birth, &proof->file) || !rw_observation_current(held)) return -1;
    sha256_init(&proof->hash); return 0;
}
static int rw_dead_process(rw_archive *held, int64_t pid, const char *start) {
    if (!pid) return !start[0];
    if (pid <= 0 || pid > INT32_MAX || pid == getpid() || !cliq_local_birth_token(start, 192)) return 0;
    char actual[128]; int retirement = 0;
    int present = observe_process_with_retirement((pid_t)pid, actual, &retirement);
    if (retirement) { held->uncertain = 1; atomic_store(&kernel_global_poisoned, 1); return 0; }
    return present == 0 || (present == 1 && strcmp(actual, start) != 0);
}
static int rw_named_cgroup(int parent, const char *name, int fd, const struct cliq_local_birth_identity *identity, struct stat *actual) {
    struct stat named;
    return fd >= 0 && installed_keeper_cgroup_identity(fd, geteuid(), getegid(), actual, 1) &&
        (!identity || rw_birth_identity(identity, actual)) &&
        fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&named, actual);
}
static int rw_cgroup_empty(rw_archive *held, int group_fd) {
    int events = openat(group_fd, "cgroup.events", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (events < 0) return 0;
    struct statfs fs; char bytes[256]; size_t size = 0;
    int valid = fstatfs(events, &fs) == 0 && fs.f_type == CGROUP2_SUPER_MAGIC;
    while (valid && size < sizeof(bytes) - 1) {
        ssize_t count = read(events, bytes + size, sizeof(bytes) - 1 - size);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { valid = 0; break; }
        if (!count) break;
        size += (size_t)count;
    }
    if (rw_close_fd(held, &events) != 0 || !valid || size >= sizeof(bytes) - 1 || !size || bytes[size - 1] != '\n') return 0;
    bytes[size] = '\0'; int found = 0;
    for (char *line = bytes, *end; line < bytes + size; line = end + 1) {
        end = strchr(line, '\n'); if (!end) return 0;
        if ((size_t)(end - line) >= 10 && !memcmp(line, "populated ", 10)) {
            if (found || end - line != 11 || line[10] != '0') return 0;
            found = 1;
        }
    }
    return found;
}
static int rw_retired_containment(rw_archive *held) {
    rw_retirement_observation *proof = held->retirement;
    const struct cliq_local_birth_frame *first = &proof->first;
    const struct cliq_local_service_observation *last = &proof->last.packet.observation;
    if ((proof->namespace_intent && !proof->ready) || (last->monitor_pid && !last->namespace_init_pid) ||
        (proof->retirement_kind == 2 && (!proof->ready || !last->namespace_init_pid || !last->cgroup_inode)) ||
        !rw_dead_process(held, first->controller_pid, first->controller_start)) return -1;
    const int64_t pids[] = {last->preparation_pid, last->monitor_pid, last->namespace_init_pid, last->bootstrap_pid};
    const char *tokens[] = {last->preparation_start, last->monitor_start, last->namespace_init_start, last->bootstrap_start};
    for (size_t index = 0; index < 4; ++index) if (!rw_dead_process(held, pids[index], tokens[index])) return -1;
    char group_name[96]; int size = snprintf(group_name, sizeof(group_name), "cliq-local-%s", first->packet.binding.native_nonce);
    if (size < 0 || (size_t)size >= sizeof(group_name)) return -1;
    struct stat parent_stat, leaf_stat, group_stat;
    int anchor = proof->anchor_fd;
    int parent = openat(anchor, "controllers", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), leaf = -1, group = -1;
    int valid = rw_named_cgroup(anchor, "controllers", parent, &first->controller_parent, &parent_stat);
    if (valid) {
        leaf = openat(parent, first->controller_leaf_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        valid = leaf < 0 ? errno == ENOENT : rw_named_cgroup(parent, first->controller_leaf_name, leaf, &first->controller_leaf, &leaf_stat) &&
            rw_cgroup_empty(held, leaf) && rw_named_cgroup(parent, first->controller_leaf_name, leaf, &first->controller_leaf, &leaf_stat);
    }
    if (valid) {
        group = openat(anchor, group_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        valid = last->cgroup_inode ? rw_named_cgroup(anchor, group_name, group, NULL, &group_stat) &&
            ma_device(&group_stat) == last->cgroup_device && (uint64_t)group_stat.st_ino == last->cgroup_inode &&
            rw_cgroup_empty(held, group) && rw_named_cgroup(anchor, group_name, group, NULL, &group_stat) &&
            ma_device(&group_stat) == last->cgroup_device && (uint64_t)group_stat.st_ino == last->cgroup_inode :
            group < 0 && errno == ENOENT;
    }
    if (valid) {
        struct stat named;
        if (leaf < 0) valid = fstatat(parent, first->controller_leaf_name, &named, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
        if (valid && group < 0) valid = fstatat(anchor, group_name, &named, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
        if (valid) valid = rw_named_cgroup(anchor, "controllers", parent, &first->controller_parent, &parent_stat) &&
            rw_dead_process(held, first->controller_pid, first->controller_start) && rw_observation_current(held);
    }
    if (rw_close_fd(held, &group) != 0) valid = 0;
    if (rw_close_fd(held, &leaf) != 0) valid = 0;
    if (rw_close_fd(held, &parent) != 0) valid = 0;
    return valid ? 0 : -1;
}
static inline int rw_retired_observation_next(rw_archive *held) {
    if (!held || held->failed || !rw_observation_current(held)) return -1;
    rw_retirement_observation *proof = held->retirement;
    if (proof->offset == (uint64_t)proof->file.st_size) {
        unsigned char byte; ssize_t count;
        do { count = pread(proof->witness_fd, &byte, 1, (off_t)proof->offset); } while (count < 0 && errno == EINTR);
        if (!proof->frames || count || rw_retired_containment(held) != 0 || fsync(proof->witness_fd) != 0 ||
            fsync(held->source_fd) != 0 || !rw_observation_current(held)) return -1;
        held->observed_file = proof->file; held->observed_kind = proof->retirement_kind;
        const struct cliq_local_service_observation *last = &proof->last.packet.observation;
        held->observed_cgroup_inode = last->cgroup_inode; held->observed_namespace_inode = last->pid_namespace_inode;
        memcpy(held->observed_namespace_start, last->namespace_init_start, sizeof(held->observed_namespace_start));
        memcpy(held->observed_launch, proof->first.packet.binding.launch, sizeof(held->observed_launch));
        memcpy(held->observed_nonce, proof->first.packet.binding.native_nonce, sizeof(held->observed_nonce));
        publication_hash_hex(&proof->hash, held->observed_digest);
        if (rw_retire_observer(held) != 0) return -1;
        held->physically_observed++; held->observation_ready = 1; return 1;
    }
    struct cliq_local_birth_frame frame; unsigned char digest[32], zero[32] = {0};
    if (proof->frames >= CLIQ_LOCAL_BIRTH_MAX_FRAMES ||
        !cliq_local_birth_read_exact(proof->witness_fd, &frame, sizeof(frame), (off_t)proof->offset)) return -1;
    cliq_local_birth_hash(&frame, offsetof(struct cliq_local_birth_frame, digest), digest);
    const struct cliq_local_birth_frame *last = proof->frames ? &proof->last : NULL;
    if (frame.magic != CLIQ_LOCAL_BIRTH_MAGIC || frame.version != 1 || frame.ordinal != proof->frames + 1 ||
        frame.step < CLIQ_LOCAL_BIRTH_RESERVED || frame.step > CLIQ_LOCAL_BIRTH_FDS_RETIRED ||
        frame.packet.magic != CLIQ_LOCAL_SERVICE_MAGIC || frame.packet.version != 1 ||
        frame.packet.command != CLIQ_LOCAL_SERVICE_RESERVE || frame.packet.status ||
        !cliq_local_service_binding_valid(&frame.packet.binding) || !cliq_local_service_resources_valid(&frame.packet.resources) ||
        !cliq_hex_digest(frame.packet.input_digest) || frame.controller_pid <= 0 || frame.controller_pid > INT32_MAX ||
        !cliq_local_birth_token(frame.controller_start, sizeof(frame.controller_start)) ||
        !cliq_local_birth_controller_name(frame.controller_leaf_name) || !cliq_local_birth_observation_valid(&frame.packet.observation) ||
        memcmp(last ? last->digest : zero, frame.previous, 32) || memcmp(digest, frame.digest, 32) ||
        !cliq_local_birth_step_valid(last, &frame) || (!last && memcmp(&frame, &proof->first, sizeof(frame))) ||
        !rw_observation_current(held)) return -1;
    if (frame.step == CLIQ_LOCAL_BIRTH_NAMESPACE_INTENT) proof->namespace_intent = 1;
    if (frame.step == CLIQ_LOCAL_BIRTH_READY) proof->ready = 1;
    proof->last = frame; proof->frames++; proof->offset += sizeof(frame);
    sha256_update(&proof->hash, (const unsigned char *)&frame, sizeof(frame)); return 0;
}
#else
static int rw_retire_observer(rw_archive *held) { return held->retirement ? -1 : 0; }
static inline int rw_begin_retired_observation(rw_archive *held, int fd, const unsigned char *bytes, size_t size, unsigned int kind) {
    (void)held; (void)fd; (void)bytes; (void)size; (void)kind; return -1;
}
static inline int rw_retired_observation_next(rw_archive *held) { (void)held; return -1; }
#endif
static inline int rw_begin_observation_arguments(napi_env env, napi_callback_info info, rw_archive *held) {
    napi_value args[4]; size_t count = 4, size = 0; int32_t fd; uint32_t kind; bool buffer = false; void *bytes = NULL;
    if (napi_get_cb_info(env, info, &count, args, NULL, NULL) != napi_ok || count != 3 ||
        napi_get_value_int32(env, args[0], &fd) != napi_ok || fd < 0 ||
        napi_is_buffer(env, args[1], &buffer) != napi_ok || !buffer ||
        napi_get_buffer_info(env, args[1], &bytes, &size) != napi_ok ||
        napi_get_value_uint32(env, args[2], &kind) != napi_ok) return -1;
    return rw_begin_retired_observation(held, fd, bytes, size, kind);
}
static inline napi_value rw_observation_value(napi_env env, rw_archive *held) {
    if (!held || held->retirement || !held->observation_ready || held->failed) return NULL;
    int64_t seconds; uint32_t nanos; char ctime[32];
    ma_times(&held->observed_file, &seconds, &nanos);
    int written = snprintf(ctime, sizeof(ctime), "%lld", (long long)seconds);
    napi_value result, size, nanos_value;
    if (written <= 0 || (size_t)written >= sizeof(ctime) || napi_create_object(env, &result) != napi_ok ||
        !publication_set_string(env, result, "nativeNonce", held->observed_nonce) ||
        !publication_set_string(env, result, "launchId", held->observed_launch) ||
        !identity_member(env, result, "file", &held->observed_file) ||
        !publication_set_string(env, result, "sha256", held->observed_digest) ||
        !publication_set_string(env, result, "sourceCtimeSeconds", ctime) ||
        !decimal_member(env, result, "cgroupFileId", held->observed_cgroup_inode) ||
        !decimal_member(env, result, "pidNamespaceId", held->observed_namespace_inode) ||
        !publication_set_string(env, result, "namespaceInitStartToken", held->observed_namespace_start) ||
        napi_create_uint32(env, nanos, &nanos_value) != napi_ok || napi_set_named_property(env, result, "sourceCtimeNanos", nanos_value) != napi_ok ||
        napi_create_double(env, (double)held->observed_file.st_size, &size) != napi_ok ||
        napi_set_named_property(env, result, "byteCount", size) != napi_ok || napi_object_freeze(env, result) != napi_ok) return NULL;
    return result;
}
