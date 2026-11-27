/* Fixed, descriptor-relative publication operations. This mechanism creates no
 * approval, Run, claim or recovery authority. The owning TS producer supplies
 * one approved immutable operation and retains the original handle throughout
 * its durable barriers. Closing joins descriptors; it never guesses ownership
 * of an on-disk staging name and never removes a transient as a GC side effect. */
#include "../linux/worker-sha256.h"

/* Inert, bounded observations only. Each role keeps its FIRST actual fsync
 * enter/return, never an interval spanning an EINTR or a later maintenance
 * retry. Counts make those repetitions explicit. No timestamp grants a proof,
 * deadline extension, cleanup permission or descriptor ownership. */
typedef struct {
    unsigned int calls, attempts;
    int unavailable, outcome;
    unsigned long long monotonic_enter, realtime_enter, monotonic_return, realtime_return;
} publication_retirement_span;

struct publication_operation {
    state_lock *lock;
    source_root *root;
    napi_ref lock_ref, root_ref;
    int *parents;
    int arena_parent_fd, arena_fd;
    struct stat arena_parent_id, arena_id;
    char arena_name[44];
    int arena_removed, no_effect_retirement, namespace_retired, namespace_observer;
    int namespace_preimage_expected;
    unsigned long long namespace_preimage_device, namespace_preimage_inode;
#ifdef __APPLE__
    char arena_path[PATH_MAX], arena_parent_path[PATH_MAX];
#endif
    struct stat *parent_ids;
    char **components, *path;
    size_t parent_count;
    char staging[NAME_MAX + 1], quarantine[NAME_MAX + 1];
    int stage_fd, original_fd, replacing, deleting, making_directory, desired_directory, original_directory, desired_link, original_link, phase, closed, revoked, armed;
    char desired_target[4097], original_target[4097];
    struct stat stage_id, original_id, original_read_id;
    struct stat destination_id;
    int destination_ready, destination_reading, destination_verified;
    off_t destination_offset;
    struct sha256_context destination_hash;
    off_t desired_size, written, verified;
    int verifying;
    struct stat verification_id;
    mode_t desired_mode;
    char desired_digest[65];
    struct sha256_context stage_hash;
    struct sha256_context original_hash;
    off_t original_size, original_offset;
    mode_t original_mode;
    char original_digest[65];
    int original_verified, preimage_reading, preimage_verified;
    /* A separate, once-captured actual displaced inode. It never replaces the
     * approved original descriptor or grants reconciliation/cleanup success. */
    int actual_fd, actual_capture_attempted, actual_complete;
    struct stat actual_id, actual_read_id;
    char actual_name[NAME_MAX + 1], actual_digest[65];
    off_t actual_offset;
    struct sha256_context actual_hash;
    publication_retirement_span retirement_spans[3];
    int retirement_post_join_observed;
    publication_operation *next;
};
static const napi_type_tag publication_operation_tag = {0x7cb0b58110b14e7aULL, 0x9d7eedadf26574c4ULL};
static int publication_namespace_held(publication_operation *operation);
static publication_operation *publication_unwrap(napi_env env, napi_callback_info info);

static int publication_diagnostic_clock(clockid_t clock, unsigned long long *result) {
    struct timespec value;
    if (clock_gettime(clock, &value) != 0 || value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= 1000000000L ||
        (unsigned long long)value.tv_sec > (ULLONG_MAX - (unsigned long long)value.tv_nsec) / 1000000000ULL) return 0;
    *result = (unsigned long long)value.tv_sec * 1000000000ULL + (unsigned long long)value.tv_nsec;
    return 1;
}
static int publication_retirement_sync(publication_operation *operation, unsigned int role, int fd) {
    publication_retirement_span *span = &operation->retirement_spans[role];
    if (span->calls == UINT_MAX) span->unavailable = 1; else span->calls++;
    int status;
    do {
        int first = span->attempts == 0, saved = errno;
        if (span->attempts == UINT_MAX) span->unavailable = 1; else span->attempts++;
        if (first && (!publication_diagnostic_clock(CLOCK_MONOTONIC, &span->monotonic_enter) ||
            !publication_diagnostic_clock(CLOCK_REALTIME, &span->realtime_enter))) span->unavailable = 1;
        errno = saved;
        status = fsync(fd);
        saved = errno;
        if (first) {
            span->outcome = status == 0 ? 0 : saved == EINTR ? 1 : 2;
            if (!publication_diagnostic_clock(CLOCK_MONOTONIC, &span->monotonic_return) ||
                !publication_diagnostic_clock(CLOCK_REALTIME, &span->realtime_return) ||
                span->monotonic_return < span->monotonic_enter || span->realtime_return < span->realtime_enter) span->unavailable = 1;
        }
        errno = saved;
    } while (status < 0 && errno == EINTR);
    return status == 0;
}

static napi_value publication_retirement_diagnostic(napi_env env, publication_operation *operation) {
    napi_value result, row, member;
    /* Historical snapshot only: never open/close a locator after the actual
     * proof's joined recheck. Lifecycle flags and the original brand suffice;
     * this data cannot assert that today's pathname or authority is valid. */
    if (!operation->closed || !operation->retirement_post_join_observed || operation->lock->lock_fd < 0 ||
        operation->lock->publication_retirement_error || operation->lock->generation_retirement_error ||
        operation->lock->process_observation_retirement_error)
        return native_error(env, "publication diagnostic requires its original completed post-join observation");
    if (napi_create_array_with_length(env, 3, &result) != napi_ok) return NULL;
    for (unsigned int role = 0; role < 3; role++) {
        publication_retirement_span *span = &operation->retirement_spans[role];
        if (!span->attempts) { if (napi_get_null(env, &row) != napi_ok) return NULL; }
        else {
            if (napi_create_array_with_length(env, span->unavailable ? 3 : 7, &row) != napi_ok ||
                napi_create_uint32(env, span->calls, &member) != napi_ok || napi_set_element(env, row, 0, member) != napi_ok ||
                napi_create_uint32(env, span->attempts, &member) != napi_ok || napi_set_element(env, row, 1, member) != napi_ok ||
                napi_create_string_utf8(env, span->unavailable ? "unavailable" : span->outcome == 0 ? "ok" : span->outcome == 1 ? "interrupted" : "error",
                    NAPI_AUTO_LENGTH, &member) != napi_ok || napi_set_element(env, row, 2, member) != napi_ok) return NULL;
            if (!span->unavailable) {
                unsigned long long stamps[] = {span->monotonic_enter, span->realtime_enter, span->monotonic_return, span->realtime_return};
                for (unsigned int index = 0; index < 4; index++) {
                    char text[21]; snprintf(text, sizeof(text), "%llu", stamps[index]);
                    if (napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &member) != napi_ok || napi_set_element(env, row, index + 3, member) != napi_ok) return NULL;
                }
            }
            if (napi_object_freeze(env, row) != napi_ok) return NULL;
        }
        if (napi_set_element(env, result, role, row) != napi_ok) return NULL;
    }
    return napi_object_freeze(env, result) == napi_ok ? result : NULL;
}
static napi_value publication_read_retirement_diagnostic(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    return operation ? publication_retirement_diagnostic(env, operation) : NULL;
}

static void publication_close_fd(publication_operation *operation, int *slot) {
    int fd = *slot; *slot = -1;
    if (fd >= 0 && close(fd) < 0) operation->lock->publication_retirement_error = errno;
}
static void publication_close(publication_operation *operation) {
    operation->closed = operation->revoked = 1;
    publication_close_fd(operation, &operation->stage_fd);
    publication_close_fd(operation, &operation->original_fd);
    publication_close_fd(operation, &operation->actual_fd);
    publication_close_fd(operation, &operation->arena_fd);
    publication_close_fd(operation, &operation->arena_parent_fd);
    for (size_t index = operation->parent_count; index > 0; index--)
        publication_close_fd(operation, &operation->parents[index - 1]);
}
static int close_lock_publication_operations(state_lock *lock) {
    for (publication_operation *operation = lock->publication_operations; operation; operation = operation->next)
        publication_close(operation);
    return lock->publication_retirement_error;
}
static napi_value publication_retirement_error(napi_env env) {
    napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "publication descriptors did not retire; StateOwner remains held"); return NULL;
}
static void publication_free(napi_env env, publication_operation *operation) {
    state_lock *lock = operation->lock;
    publication_operation **link = &lock->publication_operations;
    while (*link && *link != operation) link = &(*link)->next;
    if (*link) *link = operation->next;
    napi_ref lock_ref = operation->lock_ref, root_ref = operation->root_ref;
    free(operation->parents); free(operation->parent_ids); free(operation->components); free(operation->path); free(operation);
    free_lock_if_done(lock);
    if (root_ref) napi_delete_reference(env, root_ref);
    if (lock_ref) napi_delete_reference(env, lock_ref);
}
static void publication_finalize(napi_env env, void *data, void *hint) {
    (void)hint; publication_operation *operation = data;
    publication_close(operation); publication_free(env, operation);
}
static publication_operation *publication_unwrap(napi_env env, napi_callback_info info) {
    napi_value self; bool tagged = false; publication_operation *operation = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &publication_operation_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&operation) != napi_ok || !operation) {
        native_error(env, "invalid opaque publication operation"); return NULL;
    }
    return operation;
}
static int publication_arena_held(publication_operation *operation) {
    struct stat parent, arena, named;
    if (!(operation->arena_fd >= 0 && operation->arena_parent_fd >= 0 &&
        fstat(operation->arena_parent_fd, &parent) == 0 && private_directory(&parent) &&
        source_path_metadata_same(&operation->arena_parent_id, &parent) &&
        fstatat(operation->lock->runtime_fd, "publications", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_path_metadata_same(&parent, &named) &&
        fstat(operation->arena_fd, &arena) == 0 && private_directory(&arena) && source_path_metadata_same(&operation->arena_id, &arena) &&
        arena.st_dev == operation->lock->root.st_dev && arena.st_dev == operation->root->ids[operation->root->count - 1].st_dev)) return 0;
    if (!operation->arena_removed) return fstatat(operation->arena_parent_fd, operation->arena_name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_path_metadata_same(&arena, &named);
    if (fstatat(operation->arena_parent_fd, operation->arena_name, &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return 0;
#ifdef __APPLE__
    char observed[PATH_MAX];
    return *operation->arena_path && fcntl(operation->arena_fd, F_GETPATH, observed) == 0 && !strcmp(observed, operation->arena_path) &&
        fcntl(operation->arena_parent_fd, F_GETPATH, observed) == 0 && !strcmp(observed, operation->arena_parent_path);
#else
    return arena.st_nlink == 0;
#endif
}
static int publication_parent_held(publication_operation *operation) {
    if (operation->closed || operation->lock->publication_retirement_error || !lock_is_held(operation->lock) ||
        !source_held(operation->root)) return 0;
    for (size_t index = 0; index < operation->parent_count; index++) {
        struct stat opened, named;
        if (operation->parents[index] < 0 || fstat(operation->parents[index], &opened) < 0 ||
            !S_ISDIR(opened.st_mode) || !source_path_metadata_same(&operation->parent_ids[index], &opened) ||
            opened.st_dev != operation->root->ids[operation->root->count - 1].st_dev) return 0;
        if (index && (fstatat(operation->parents[index - 1], operation->components[index - 1], &named, AT_SYMLINK_NOFOLLOW) < 0 ||
            !source_path_metadata_same(&opened, &named))) return 0;
    }
    return operation->parent_count > 0 && (operation->arena_fd < 0 || publication_arena_held(operation));
}
static int publication_absent(int parent, const char *name) {
    struct stat observed;
    return fstatat(parent, name, &observed, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
}
static int publication_stage_held(publication_operation *operation, int parent, const char *name) {
    struct stat opened, named;
    return operation->stage_fd >= 0 && fstat(operation->stage_fd, &opened) == 0 &&
        (operation->desired_directory ? S_ISDIR(opened.st_mode) : operation->desired_link ? S_ISLNK(opened.st_mode) : S_ISREG(opened.st_mode) && opened.st_nlink == 1) &&
        same_inode(&opened, &operation->stage_id) && opened.st_uid == operation->stage_id.st_uid &&
        opened.st_dev == operation->parent_ids[0].st_dev && (operation->desired_link || (opened.st_mode & 07777) == operation->desired_mode) &&
        fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        (operation->desired_directory ? source_path_metadata_same(&opened, &named) : source_metadata_same(&opened, &named)) &&
        (!operation->destination_ready || operation->desired_directory || source_metadata_same(&operation->destination_id, &opened));
}
static int publication_empty_directory(publication_operation *operation, int descriptor) {
    struct stat before, opened, after;
    if (fstat(descriptor, &before) < 0 || !S_ISDIR(before.st_mode)) return -1;
    int fd = openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &opened) < 0 || !source_metadata_same(&before, &opened)) { publication_close_fd(operation, &fd); return -1; }
    DIR *directory = fdopendir(fd);
    if (!directory) { publication_close_fd(operation, &fd); return -1; }
    int empty = 1; struct dirent *entry;
    for (;;) {
        errno = 0; entry = readdir(directory);
        if (!entry) { if (errno) empty = -1; break; }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { empty = 0; break; }
    }
    if (fstat(descriptor, &after) < 0 || !source_metadata_same(&before, &after)) empty = -1;
    if (closedir(directory) < 0) { operation->lock->publication_retirement_error = errno; return -1; }
    return empty;
}
static int publication_original_held(publication_operation *operation, int parent, const char *name, int exact_times) {
    struct stat opened, named;
    if (operation->original_fd < 0 || fstat(operation->original_fd, &opened) < 0 ||
        !(operation->original_directory ? S_ISDIR(opened.st_mode) : operation->original_link ? S_ISLNK(opened.st_mode) : S_ISREG(opened.st_mode) && opened.st_nlink == 1) ||
        !same_inode(&opened, &operation->original_id) || opened.st_uid != operation->original_id.st_uid ||
        opened.st_mode != operation->original_id.st_mode || (!operation->original_directory && opened.st_size != operation->original_size) ||
        fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
        !(operation->original_directory ? source_path_metadata_same(&opened, &named) : source_metadata_same(&opened, &named))) return 0;
    return !exact_times || (operation->original_directory ? source_path_metadata_same(&opened, &operation->original_id) : source_metadata_same(&opened, &operation->original_id));
}
static napi_value publication_undefined(napi_env env) { napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL; }
static int publication_open_link(int parent, const char *name) {
#ifdef __APPLE__
    /* Darwin's O_SYMLINK explicitly opens the link itself. Combining its
     * recipe with O_NOFOLLOW rejects even that link with ELOOP. */
    return openat(parent, name, O_RDONLY | O_SYMLINK | O_CLOEXEC);
#elif defined(__linux__)
    return openat(parent, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
#else
    (void)parent; (void)name; errno = ENOTSUP; return -1;
#endif
}
static int publication_link_target(int parent, const char *name, int fd, const char *target) {
    struct stat before, after, named; char bytes[4097];
    if (fd < 0 || fstat(fd, &before) < 0 || !S_ISLNK(before.st_mode) ||
        fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) < 0 || !source_metadata_same(&before, &named)) return 0;
    ssize_t length = readlinkat(parent, name, bytes, sizeof(bytes));
    if (length <= 0 || length > 4096 || (size_t)length != strlen(target) || memcmp(target, bytes, (size_t)length)) return 0;
    return fstat(fd, &after) == 0 && source_metadata_same(&before, &after) &&
        fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&before, &named);
}
static int publication_actual_held(publication_operation *operation) {
    struct stat opened, named;
    return (operation->phase == 3 || operation->phase == 4) && operation->actual_fd >= 0 && publication_parent_held(operation) &&
        fstat(operation->actual_fd, &opened) == 0 && same_inode(&operation->actual_id, &opened) && source_metadata_same(&operation->actual_read_id, &opened) &&
        fstatat(operation->arena_fd, operation->actual_name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&opened, &named);
}
/* Called only by the original successfully acknowledged namespace syscall,
 * before checking whether it displaced the expected inode. Failure is sticky
 * for this capture: later observation must not adopt a pathname after a gap. */
static int publication_capture_actual(publication_operation *operation, const char *name) {
    struct stat before, opened, named;
    if (operation->actual_capture_attempted) return 0;
    operation->actual_capture_attempted = 1;
    if (!publication_parent_held(operation) || fstatat(operation->arena_fd, name, &before, AT_SYMLINK_NOFOLLOW) < 0 || before.st_size < 0) return 0;
    int fd;
    if (S_ISLNK(before.st_mode)) fd = publication_open_link(operation->arena_fd, name);
    else if (S_ISREG(before.st_mode) || S_ISDIR(before.st_mode))
        fd = openat(operation->arena_fd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC | (S_ISDIR(before.st_mode) ? O_DIRECTORY : 0));
    else return 0;
    if (fd < 0) return 0;
    operation->actual_fd = fd;
    if (fstat(fd, &opened) < 0 || !source_metadata_same(&before, &opened) ||
        fstatat(operation->arena_fd, name, &named, AT_SYMLINK_NOFOLLOW) < 0 || !source_metadata_same(&opened, &named)) {
        publication_close_fd(operation, &operation->actual_fd); return 0;
    }
    operation->actual_id = operation->actual_read_id = opened;
    memcpy(operation->actual_name, name, strlen(name) + 1);
    sha256_init(&operation->actual_hash);
    return publication_actual_held(operation);
}
/* Only the acknowledged internal staging-to-quarantine move can advance this
 * fixed locator. Rename may change ctime, not the captured inode, byte length,
 * mtime, raw mode, owner or link count. Subsequent reads/restarts still compare
 * the complete frozen post-move metadata; this is never pathname adoption. */
static int publication_relocate_actual(publication_operation *operation) {
    struct stat observed, named, before = operation->actual_read_id;
    if (operation->actual_fd < 0 || operation->actual_offset || operation->actual_complete ||
        strcmp(operation->actual_name, operation->staging) ||
        fstat(operation->actual_fd, &observed) < 0 || !same_inode(&operation->actual_id, &observed)) return 0;
#ifdef __APPLE__
    before.st_ctimespec = observed.st_ctimespec;
#else
    before.st_ctim = observed.st_ctim;
#endif
    if (!source_metadata_same(&before, &observed) || !publication_parent_held(operation) ||
        fstatat(operation->arena_fd, operation->quarantine, &named, AT_SYMLINK_NOFOLLOW) < 0 || !source_metadata_same(&observed, &named)) return 0;
    operation->actual_read_id = observed;
    memcpy(operation->actual_name, operation->quarantine, strlen(operation->quarantine) + 1);
    return publication_actual_held(operation);
}
static napi_value publication_assert(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    if (!operation) return NULL;
    if (operation->lock->publication_retirement_error) return publication_retirement_error(env);
    if (!publication_parent_held(operation)) return native_error(env, "publication parent identity changed or closed");
    return publication_undefined(env);
}
static napi_value publication_release(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    if (!operation) return NULL;
    publication_close(operation);
    if (operation->lock->publication_retirement_error) return publication_retirement_error(env);
    return publication_undefined(env);
}
static napi_value publication_revoke(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    if (!operation) return NULL;
    operation->revoked = 1; operation->armed = 0; return publication_undefined(env);
}
static napi_value publication_arm(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    if (!operation) return NULL;
    if (!publication_parent_held(operation) || operation->revoked || operation->phase < 0 || operation->phase > 2)
        return native_error(env, "publication cannot arm a closed, revoked or already released envelope");
    operation->armed = 1; return publication_undefined(env);
}
static napi_value publication_discard_stage(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    if (!operation) return NULL;
    if (!publication_parent_held(operation) || operation->phase < 0 || operation->phase > 2)
        return native_error(env, "publication staging cannot be discarded after a possible semantic effect");
    if (operation->phase == 0 || operation->deleting) {
        if (operation->stage_fd >= 0) return native_error(env, "publication unexpected staging handle");
        if (operation->deleting && (!publication_original_held(operation, operation->parents[operation->parent_count - 1], operation->components[operation->parent_count - 1], 1) ||
            !publication_absent(operation->arena_fd, operation->quarantine)))
            return native_error(env, "publication delete may already have released its original effect");
        operation->no_effect_retirement = 1; operation->phase = -1; return publication_undefined(env);
    }
    if (operation->stage_fd < 0 || !*operation->staging) return native_error(env, "publication staging birth has no original held descriptor");
    const int parent = operation->arena_fd; struct stat before, after;
    if (!publication_stage_held(operation, parent, operation->staging) || fstat(operation->stage_fd, &before) < 0 ||
        (operation->desired_directory && publication_empty_directory(operation, operation->stage_fd) != 1))
        return native_error(env, "publication unpublished staging is not exactly owned and empty");
#ifdef __APPLE__
    char parent_path[PATH_MAX], expected_path[PATH_MAX], observed_path[PATH_MAX];
    if (operation->desired_directory && (fcntl(parent, F_GETPATH, parent_path) < 0 ||
        snprintf(expected_path, sizeof(expected_path), "%s/%s", parent_path, operation->staging) >= (int)sizeof(expected_path) ||
        fcntl(operation->stage_fd, F_GETPATH, observed_path) < 0 || strcmp(expected_path, observed_path)))
        return native_error(env, "publication unpublished directory changed before cleanup");
#endif
    if (unlinkat(parent, operation->staging, operation->desired_directory ? AT_REMOVEDIR : 0) < 0 ||
        fstat(operation->stage_fd, &after) < 0 || !same_inode(&before, &after))
        return native_error(env, "publication unpublished staging cleanup is uncertain");
#ifdef __APPLE__
    if (operation->desired_directory ? fcntl(operation->stage_fd, F_GETPATH, observed_path) < 0 || strcmp(expected_path, observed_path) ||
        fcntl(parent, F_GETPATH, observed_path) < 0 || strcmp(parent_path, observed_path) : after.st_nlink + 1 != before.st_nlink)
        return native_error(env, "publication unpublished staging unlink is not proven");
#else
    if (operation->desired_directory ? after.st_nlink != 0 : after.st_nlink + 1 != before.st_nlink)
        return native_error(env, "publication unpublished staging unlink is not proven");
#endif
    if (!publication_absent(parent, operation->staging) || !sync_directory(parent) || !publication_parent_held(operation))
        return native_error(env, "publication unpublished staging cleanup sync is unconfirmed");
    operation->no_effect_retirement = 1; operation->phase = -1; return publication_undefined(env);
}
static napi_value publication_stage(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    if (!operation) return NULL;
    if (!publication_parent_held(operation) || operation->revoked || operation->phase != 0) return native_error(env, "publication stage is not a fresh held operation");
    const int parent = operation->parents[operation->parent_count - 1];
    const char *name = operation->components[operation->parent_count - 1];
    if (!(operation->replacing ? operation->original_verified && publication_original_held(operation, parent, name, 1) : publication_absent(parent, name)) ||
        (*operation->staging && !publication_absent(operation->arena_fd, operation->staging)) || (operation->replacing && !publication_absent(operation->arena_fd, operation->quarantine)))
        return native_error(env, "publication destination or staging is not absent");
    if (operation->deleting) { operation->phase = 1; return publication_undefined(env); }
    const int arena = operation->arena_fd;
    if (operation->desired_link) {
        if (symlinkat(operation->desired_target, arena, operation->staging) < 0) return native_error(env, "cannot exclusively create publication symlink");
        operation->phase = 1; operation->stage_fd = publication_open_link(arena, operation->staging);
    } else if (operation->desired_directory) {
        if (mkdirat(arena, operation->staging, 0700) < 0) return native_error(env, "cannot exclusively create publication staging directory");
        operation->phase = 1;
        operation->stage_fd = openat(arena, operation->staging, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } else operation->stage_fd = openat(arena, operation->staging, O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (operation->stage_fd < 0) return native_error(env, "cannot exclusively create publication staging");
    /* The actual inode is retained even if normalization or later sync fails. */
    operation->phase = 1;
    if (fstat(operation->stage_fd, &operation->stage_id) < 0 ||
        !(operation->desired_directory ? S_ISDIR(operation->stage_id.st_mode) : operation->desired_link ? S_ISLNK(operation->stage_id.st_mode) : S_ISREG(operation->stage_id.st_mode) && operation->stage_id.st_nlink == 1) ||
        operation->stage_id.st_uid != geteuid() ||
        operation->stage_id.st_dev != operation->parent_ids[0].st_dev ||
        (!operation->desired_link && fchmod(operation->stage_fd, operation->desired_mode) < 0) || !publication_parent_held(operation) ||
        !publication_stage_held(operation, arena, operation->staging)) return native_error(env, "publication staging identity changed during birth");
    sha256_init(&operation->stage_hash);
    return publication_undefined(env);
}
static napi_value publication_write(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info); size_t argc = 1, size; napi_value value; void *bytes;
    if (!operation) return NULL;
    if (napi_get_cb_info(env, info, &argc, &value, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_buffer_info(env, value, &bytes, &size) != napi_ok || size == 0 || size > 65536)
        return native_error(env, "publication writes require one bounded nonempty byte chunk");
    if (!publication_parent_held(operation) || operation->revoked || operation->deleting || operation->making_directory || operation->desired_directory || operation->desired_link || operation->phase != 1 || operation->verifying || !publication_stage_held(operation, operation->arena_fd, operation->staging) ||
        (off_t)size > operation->desired_size - operation->written) return native_error(env, "publication staging is changed or exceeds its exact byte count");
    size_t done = 0;
    while (done < size) {
        ssize_t count = pwrite(operation->stage_fd, (const char *)bytes + done, size - done, operation->written + (off_t)done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return native_error(env, "publication staging write failed");
        done += (size_t)count;
    }
    operation->written += (off_t)size;
    sha256_update(&operation->stage_hash, bytes, size);
    if (!publication_parent_held(operation) || !publication_stage_held(operation, operation->arena_fd, operation->staging))
        return native_error(env, "publication staging changed during bounded write");
    return publication_undefined(env);
}
static void publication_hash_hex(struct sha256_context *hash, char text[65]) {
    unsigned char digest[32]; sha256_final(hash, digest);
    for (size_t index = 0; index < sizeof(digest); index++) snprintf(text + index * 2, 3, "%02x", digest[index]);
}
static napi_value publication_actual_chunk(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info); napi_value result;
    if (!operation) return NULL;
    if (!publication_actual_held(operation) || operation->actual_id.st_uid != geteuid() ||
        !(S_ISREG(operation->actual_id.st_mode) || S_ISLNK(operation->actual_id.st_mode)) ||
        (S_ISREG(operation->actual_id.st_mode) ? operation->actual_id.st_nlink != 1 || operation->actual_id.st_size > 268435456 :
          operation->actual_id.st_size <= 0 || operation->actual_id.st_size > 4096))
        return native_error(env, "publication actual preimage has no unchanged bounded readable owner");
    const off_t remaining = operation->actual_id.st_size - operation->actual_offset;
    const size_t size = remaining < 65536 ? (size_t)remaining : 65536;
    if (!size) {
        struct sha256_context hash = operation->actual_hash;
        publication_hash_hex(&hash, operation->actual_digest); operation->actual_complete = 1;
        return napi_get_null(env, &result) == napi_ok ? result : NULL;
    }
    void *bytes; if (napi_create_buffer(env, size, &bytes, &result) != napi_ok) return NULL;
    if (S_ISLNK(operation->actual_id.st_mode)) {
        char target[4097];
        ssize_t count = readlinkat(operation->arena_fd, operation->actual_name, target, sizeof(target));
        if (count < 0 || (size_t)count != size) return native_error(env, "publication actual raw link target changed or exceeds its bound");
        memcpy(bytes, target, size);
    } else {
        size_t done = 0;
        while (done < size) {
            ssize_t count = pread(operation->actual_fd, (char *)bytes + done, size - done, operation->actual_offset + (off_t)done);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) return native_error(env, "publication actual bounded preimage read failed");
            done += (size_t)count;
        }
    }
    if (!publication_actual_held(operation)) return native_error(env, "publication actual preimage changed during bounded read");
    sha256_update(&operation->actual_hash, bytes, size); operation->actual_offset += (off_t)size;
    return result;
}
static napi_value publication_read_original(napi_env env, napi_callback_info info, int mode) {
    publication_operation *operation = publication_unwrap(env, info); napi_value result; struct stat observed;
    if (!operation) return NULL;
    const int preimage = mode == 1, inspection = mode == 2;
    const char *name = preimage ? operation->quarantine : operation->components[operation->parent_count - 1];
    const int parent = preimage ? operation->arena_fd : operation->parents[operation->parent_count - 1];
    if (!publication_parent_held(operation) || !operation->replacing ||
        (preimage ? operation->phase != 4 : inspection ? operation->phase < 0 || operation->phase > 2 : operation->phase != 0) ||
        !publication_original_held(operation, parent, name, !preimage)) return native_error(env, "publication original file is not exactly held");
    if (preimage && !operation->preimage_reading) {
        operation->preimage_reading = 1; operation->original_offset = 0; sha256_init(&operation->original_hash);
        if (fstat(operation->original_fd, &operation->original_read_id) < 0) return native_error(env, "publication preimage observation failed");
    }
    if (operation->original_directory) {
        if (publication_empty_directory(operation, operation->original_fd) != 1 || !publication_parent_held(operation) ||
            !publication_original_held(operation, parent, name, 0)) return native_error(env, "publication original directory is not proven exactly empty");
        if (preimage) operation->preimage_verified = 1; else operation->original_verified = 1;
        return napi_get_null(env, &result) == napi_ok ? result : NULL;
    }
    if (operation->original_link) {
        if (!publication_link_target(parent, name, operation->original_fd, operation->original_target)) return native_error(env, "publication original symlink target differs");
        if (operation->original_offset) {
            if (preimage) operation->preimage_verified = 1; else operation->original_verified = 1;
            return napi_get_null(env, &result) == napi_ok ? result : NULL;
        }
        operation->original_offset = operation->original_size;
        return napi_create_buffer_copy(env, (size_t)operation->original_size, operation->original_target, NULL, &result) == napi_ok ? result : NULL;
    }
    if (fstat(operation->original_fd, &observed) < 0 ||
        !source_metadata_same(preimage ? &operation->original_read_id : &operation->original_id, &observed))
        return native_error(env, "publication original changed during complete hash");
    const off_t remaining = operation->original_size - operation->original_offset;
    const size_t size = remaining < 65536 ? (size_t)remaining : 65536;
    if (!size) {
        struct sha256_context hash = operation->original_hash; char digest[65]; publication_hash_hex(&hash, digest);
        if (strcmp(digest, operation->original_digest) != 0) return native_error(env, "publication original full digest differs");
        if (preimage) operation->preimage_verified = 1; else operation->original_verified = 1;
        return napi_get_null(env, &result) == napi_ok ? result : NULL;
    }
    void *bytes; if (napi_create_buffer(env, size, &bytes, &result) != napi_ok) return NULL;
    size_t done = 0;
    while (done < size) {
        ssize_t count = pread(operation->original_fd, (char *)bytes + done, size - done, operation->original_offset + (off_t)done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return native_error(env, "publication original bounded read failed");
        done += (size_t)count;
    }
    sha256_update(&operation->original_hash, bytes, size); operation->original_offset += (off_t)size;
    if (!publication_parent_held(operation) || !publication_original_held(operation, parent, name, !preimage) ||
        fstat(operation->original_fd, &observed) < 0 ||
        !source_metadata_same(preimage ? &operation->original_read_id : &operation->original_id, &observed))
        return native_error(env, "publication original changed during bounded read");
    return result;
}
static napi_value publication_original_chunk(napi_env env, napi_callback_info info) { return publication_read_original(env, info, 0); }
static napi_value publication_preimage_chunk(napi_env env, napi_callback_info info) { return publication_read_original(env, info, 1); }
static napi_value publication_inspection_original_chunk(napi_env env, napi_callback_info info) { return publication_read_original(env, info, 2); }
static napi_value publication_restart_read(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info); size_t argc = 1, length; napi_value value; char kind[24];
    if (!operation) return NULL;
    if (!publication_parent_held(operation) || napi_get_cb_info(env, info, &argc, &value, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_string_utf8(env, value, kind, sizeof(kind), &length) != napi_ok || length >= sizeof(kind) || strlen(kind) != length)
        return native_error(env, "publication read restart requires one fixed held slot");
    if (strcmp(kind, "original") == 0 || strcmp(kind, "inspection_original") == 0) {
        const int inspection = strcmp(kind, "inspection_original") == 0;
        if ((inspection ? operation->phase < 0 || operation->phase > 2 : operation->phase != 0) || !operation->replacing ||
            !publication_original_held(operation, operation->parents[operation->parent_count - 1], operation->components[operation->parent_count - 1], 1))
            return native_error(env, "publication original read has no unchanged pre-effect owner");
        operation->original_verified = 0; operation->original_offset = 0; sha256_init(&operation->original_hash);
    } else if (strcmp(kind, "preimage") == 0) {
        if (operation->phase != 4 || !operation->replacing || !publication_original_held(operation, operation->arena_fd, operation->quarantine, 0))
            return native_error(env, "publication preimage read has no exact displaced owner");
        operation->preimage_verified = operation->preimage_reading = 0; operation->original_offset = 0;
    } else if (strcmp(kind, "destination") == 0) {
        if (operation->phase < 4 || operation->deleting || !publication_stage_held(operation, operation->parents[operation->parent_count - 1], operation->components[operation->parent_count - 1]))
            return native_error(env, "publication destination read has no original committed owner");
        operation->destination_verified = operation->destination_reading = 0; operation->destination_offset = 0;
    } else if (strcmp(kind, "actual_preimage") == 0) {
        if (!publication_actual_held(operation)) return native_error(env, "publication actual preimage has no original captured descriptor");
        operation->actual_offset = 0; operation->actual_complete = 0; *operation->actual_digest = '\0'; sha256_init(&operation->actual_hash);
    } else return native_error(env, "unknown publication read slot");
    return publication_undefined(env);
}
static napi_value publication_destination_bytes(napi_env env, publication_operation *operation) {
    napi_value result;
    const char *name = operation->components[operation->parent_count - 1];
    const int parent = operation->parents[operation->parent_count - 1];
    if (operation->desired_directory) {
        operation->destination_verified = 1; return napi_get_null(env, &result) == napi_ok ? result : NULL;
    }
    if (!operation->destination_reading) { operation->destination_reading = 1; sha256_init(&operation->destination_hash); }
    if (operation->desired_link) {
        if (!publication_link_target(parent, name, operation->stage_fd, operation->desired_target)) return native_error(env, "publication destination link target differs");
        if (operation->destination_offset) { operation->destination_verified = 1; return napi_get_null(env, &result) == napi_ok ? result : NULL; }
        operation->destination_offset = operation->desired_size;
        return napi_create_buffer_copy(env, (size_t)operation->desired_size, operation->desired_target, NULL, &result) == napi_ok ? result : NULL;
    }
    const off_t remaining = operation->desired_size - operation->destination_offset;
    const size_t size = remaining < 65536 ? (size_t)remaining : 65536;
    if (!size) {
        struct sha256_context hash = operation->destination_hash; char digest[65]; publication_hash_hex(&hash, digest);
        if (strcmp(digest, operation->desired_digest) != 0) return native_error(env, "publication destination full digest differs");
        operation->destination_verified = 1; return napi_get_null(env, &result) == napi_ok ? result : NULL;
    }
    void *bytes; if (napi_create_buffer(env, size, &bytes, &result) != napi_ok) return NULL;
    size_t done = 0;
    while (done < size) {
        ssize_t count = pread(operation->stage_fd, (char *)bytes + done, size - done, operation->destination_offset + (off_t)done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return native_error(env, "publication destination bounded read failed");
        done += (size_t)count;
    }
    sha256_update(&operation->destination_hash, bytes, size); operation->destination_offset += (off_t)size;
    if (!(operation->namespace_observer ? publication_namespace_held(operation) : publication_parent_held(operation)) || !publication_stage_held(operation, parent, name))
        return operation->namespace_observer && operation->lock->publication_retirement_error ? publication_retirement_error(env) :
            native_error(env, "publication destination changed during full read");
    return result;
}
static napi_value publication_destination_chunk(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    if (!operation) return NULL;
    const char *name = operation->components[operation->parent_count - 1];
    const int parent = operation->parents[operation->parent_count - 1];
    if (!publication_parent_held(operation) || operation->deleting || operation->phase < 4 || !publication_stage_held(operation, parent, name))
        return native_error(env, "publication destination does not hold the original committed entry");
    return publication_destination_bytes(env, operation);
}
static napi_value publication_finish_stage(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info); char digest[65]; napi_value result; struct stat observed;
    if (!operation) return NULL;
    if (operation->revoked) return native_error(env, "publication semantic release is revoked");
    if (operation->deleting) {
        if (!publication_parent_held(operation) || operation->phase != 1) return native_error(env, "publication operation is not prepared");
        operation->phase = 2; return napi_get_boolean(env, true, &result) == napi_ok ? result : NULL;
    }
    if (!publication_parent_held(operation) || operation->phase != 1 || (!operation->desired_link && operation->written != operation->desired_size) ||
        !publication_stage_held(operation, operation->arena_fd, operation->staging)) return native_error(env, "publication staging is incomplete or changed");
    if (operation->desired_link) {
        if (!publication_link_target(operation->arena_fd, operation->staging, operation->stage_fd, operation->desired_target) ||
            !sync_directory(operation->parents[operation->parent_count - 1]) || !publication_parent_held(operation) ||
            !publication_stage_held(operation, operation->arena_fd, operation->staging) || fstat(operation->stage_fd, &operation->verification_id) < 0)
            return native_error(env, "publication symlink staging target or sync is unconfirmed");
        operation->phase = 2; return napi_get_boolean(env, true, &result) == napi_ok ? result : NULL;
    }
    if (operation->desired_directory) {
        if (publication_empty_directory(operation, operation->stage_fd) != 1 || !sync_directory(operation->stage_fd) ||
            !publication_parent_held(operation) || !publication_stage_held(operation, operation->arena_fd, operation->staging) ||
            fstat(operation->stage_fd, &operation->verification_id) < 0)
            return native_error(env, "publication directory staging is not exactly empty and synced");
        operation->phase = 2; return napi_get_boolean(env, true, &result) == napi_ok ? result : NULL;
    }
    if (!operation->verifying) {
        operation->verifying = 1; sha256_init(&operation->stage_hash);
        if (fstat(operation->stage_fd, &operation->verification_id) < 0 || operation->verification_id.st_size != operation->desired_size)
            return native_error(env, "publication staging actual size differs");
    }
    if (fstat(operation->stage_fd, &observed) < 0 || !source_metadata_same(&operation->verification_id, &observed))
        return native_error(env, "publication staging changed during complete hash");
    unsigned char bytes[65536];
    const off_t remaining = operation->desired_size - operation->verified;
    const size_t size = remaining < (off_t)sizeof(bytes) ? (size_t)remaining : sizeof(bytes);
    size_t done = 0;
    while (done < size) {
        ssize_t count = pread(operation->stage_fd, bytes + done, size - done, operation->verified + (off_t)done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return native_error(env, "publication staging complete read failed");
        done += (size_t)count;
    }
    sha256_update(&operation->stage_hash, bytes, size); operation->verified += (off_t)size;
    if (!publication_parent_held(operation) || !publication_stage_held(operation, operation->arena_fd, operation->staging) ||
        fstat(operation->stage_fd, &observed) < 0 || !source_metadata_same(&operation->verification_id, &observed))
        return native_error(env, "publication staging changed during complete hash");
    if (operation->verified != operation->desired_size)
        return napi_get_boolean(env, false, &result) == napi_ok ? result : NULL;
    struct sha256_context hash = operation->stage_hash; publication_hash_hex(&hash, digest);
    if (strcmp(digest, operation->desired_digest) != 0 || !sync_directory(operation->stage_fd) ||
        !publication_parent_held(operation) || !publication_stage_held(operation, operation->arena_fd, operation->staging))
        return native_error(env, "publication staging digest, identity or file sync failed");
    operation->phase = 2;
    return napi_get_boolean(env, true, &result) == napi_ok ? result : NULL;
}
static int publication_rename_exclusive(int from_parent, const char *from, int to_parent, const char *to) {
#ifdef __APPLE__
    return renameatx_np(from_parent, from, to_parent, to, RENAME_EXCL) == 0;
#elif defined(__linux__)
    return renameat2(from_parent, from, to_parent, to, RENAME_NOREPLACE) == 0;
#else
    (void)from_parent; (void)to_parent; (void)from; (void)to; errno = ENOTSUP; return 0;
#endif
}
static int publication_exchange(int from_parent, const char *from, int to_parent, const char *to) {
#ifdef __APPLE__
    return renameatx_np(from_parent, from, to_parent, to, RENAME_SWAP) == 0;
#elif defined(__linux__)
    return renameat2(from_parent, from, to_parent, to, RENAME_EXCHANGE) == 0;
#else
    (void)from_parent; (void)to_parent; (void)from; (void)to; errno = ENOTSUP; return 0;
#endif
}
static napi_value publication_status(napi_env env, const char *text) {
    napi_value value; return napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &value) == napi_ok ? value : NULL;
}
static int publication_original_unlinked(publication_operation *operation) {
    struct stat observed;
    if (!operation->preimage_verified || operation->original_fd < 0 || fstat(operation->original_fd, &observed) < 0 ||
        !same_inode(&observed, &operation->original_id)) return 0;
    if (!operation->original_directory) return observed.st_nlink + 1 == operation->original_read_id.st_nlink;
#ifdef __APPLE__
    char parent_path[PATH_MAX], expected_path[PATH_MAX], observed_path[PATH_MAX];
    const int parent = operation->arena_fd;
    return fcntl(parent, F_GETPATH, parent_path) == 0 &&
        snprintf(expected_path, sizeof(expected_path), "%s/%s", parent_path, operation->quarantine) < (int)sizeof(expected_path) &&
        fcntl(operation->original_fd, F_GETPATH, observed_path) == 0 && strcmp(expected_path, observed_path) == 0;
#else
    return observed.st_nlink == 0;
#endif
}
/* Read-only namespace classification from the actual original descriptors.
 * This does not rename, unlink, sync, advance phase, or assert a durable result;
 * the owning producer still reads full bytes and closes the original graph. */
static napi_value publication_inspect_state(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    if (!operation) return NULL;
    if (!publication_parent_held(operation)) return native_error(env, "publication read-only inspection parent is not exactly held");
    const int parent = operation->parents[operation->parent_count - 1];
    const char *name = operation->components[operation->parent_count - 1];
    const int arena = operation->arena_fd;
    const int stage_absent = !*operation->staging || publication_absent(arena, operation->staging);
    const int quarantine_absent = !*operation->quarantine || publication_absent(arena, operation->quarantine);
    if (!operation->arena_removed) {
        if (operation->deleting) {
            if (quarantine_absent && publication_original_held(operation, parent, name, 1))
                return publication_status(env, "unstarted");
        } else if (!publication_stage_held(operation, parent, name)) {
            if (quarantine_absent && (operation->replacing ? publication_original_held(operation, parent, name, 1) : publication_absent(parent, name)) &&
                ((stage_absent && operation->stage_fd < 0) || (*operation->staging && publication_stage_held(operation, arena, operation->staging))))
                return publication_status(env, "unstarted");
            return native_error(env, "publication read-only inspection cannot adopt an unheld destination");
        }
    }
    if (operation->deleting ? !publication_absent(parent, name) : !publication_stage_held(operation, parent, name))
        return native_error(env, "publication read-only inspection destination is ambiguous");
    if (operation->replacing && !operation->deleting && !stage_absent) {
        if (!quarantine_absent || !publication_original_held(operation, arena, operation->staging, 0) ||
            (operation->original_directory && publication_empty_directory(operation, operation->original_fd) != 1))
            return native_error(env, "publication read-only inspection displaced staging is ambiguous");
    } else {
        if (!stage_absent) return native_error(env, "publication read-only inspection staging is ambiguous");
        if (operation->replacing && (quarantine_absent ? !publication_original_unlinked(operation) :
            !publication_original_held(operation, arena, operation->quarantine, 0) ||
            (operation->original_directory && publication_empty_directory(operation, operation->original_fd) != 1)))
            return native_error(env, "publication read-only inspection original quarantine is ambiguous");
    }
    if (!publication_parent_held(operation)) return native_error(env, "publication read-only inspection lost its original parent");
    return publication_status(env, operation->phase >= 5 && quarantine_absent && stage_absent ? "cleaned" : "effect_present");
}
/* Observation and original-effect maintenance only. This never releases the
 * staged desired entry into an old/absent destination. A lost syscall reply
 * can be reconciled only while these actual original descriptors survive. */
static napi_value publication_reconcile(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    if (!operation) return NULL;
    if (!publication_parent_held(operation)) return native_error(env, "publication reconciliation parent is not exactly held");
    if (operation->arena_removed) return publication_status(env, "cleaned");
    const int parent = operation->parents[operation->parent_count - 1]; const char *name = operation->components[operation->parent_count - 1];
    const int arena = operation->arena_fd;
    const int stage_absent = !*operation->staging || publication_absent(arena, operation->staging);
    const int quarantine_absent = !*operation->quarantine || publication_absent(arena, operation->quarantine);
    if (operation->deleting) {
        if (quarantine_absent && publication_original_held(operation, parent, name, 1)) return publication_status(env, "unstarted");
        if (!publication_absent(parent, name)) return native_error(env, "publication delete destination is ambiguous");
    } else if (!publication_stage_held(operation, parent, name)) {
        if (quarantine_absent && (operation->replacing ? publication_original_held(operation, parent, name, 1) : publication_absent(parent, name)) &&
            ((stage_absent && operation->stage_fd < 0) || (*operation->staging && publication_stage_held(operation, arena, operation->staging))))
            return publication_status(env, "unstarted");
        return native_error(env, "publication reconciliation cannot adopt a destination without its original descriptor");
    }
    if (operation->replacing && !operation->deleting && !stage_absent) {
        if (!quarantine_absent || !publication_original_held(operation, arena, operation->staging, 0) ||
            (operation->original_directory && publication_empty_directory(operation, operation->original_fd) != 1) ||
            !publication_rename_exclusive(arena, operation->staging, arena, operation->quarantine))
            return native_error(env, "publication displaced staging has no exact original maintenance owner");
        if (operation->actual_fd >= 0 && !publication_relocate_actual(operation))
            return native_error(env, "publication actual preimage changed during its original maintenance move");
    } else if (!stage_absent) return native_error(env, "publication staging is ambiguous after the original effect");
    int cleaned = operation->phase == 5;
    if (operation->replacing) {
        if (publication_absent(arena, operation->quarantine)) {
            if (!publication_original_unlinked(operation)) return native_error(env, "publication transient absence does not prove its original unlink");
            cleaned = 1;
        } else if (!publication_original_held(operation, arena, operation->quarantine, 0) ||
            (operation->original_directory && publication_empty_directory(operation, operation->original_fd) != 1))
            return native_error(env, "publication original quarantine is ambiguous");
    }
    if (!sync_directory(arena) || !sync_directory(parent) || !publication_parent_held(operation) ||
        (operation->deleting ? !publication_absent(parent, name) : !publication_stage_held(operation, parent, name)))
        return native_error(env, "publication reconciliation directory sync or identity is unconfirmed");
    if (!operation->deleting) {
        if (fstat(operation->stage_fd, &operation->destination_id) < 0) return native_error(env, "publication reconciled destination identity unavailable");
        operation->destination_ready = 1;
    }
    operation->phase = cleaned ? 5 : 4;
    return publication_status(env, cleaned ? "cleaned" : "committed");
}
static napi_value publication_commit(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    struct stat observed;
    if (!operation) return NULL;
    if (!publication_parent_held(operation) || operation->revoked || !operation->armed || operation->phase != 2 ||
        (!operation->deleting && (!publication_stage_held(operation, operation->arena_fd, operation->staging) ||
        fstat(operation->stage_fd, &observed) < 0 || !source_metadata_same(&operation->verification_id, &observed))))
        return native_error(env, "publication commit does not hold its finished staging");
    const int parent = operation->parents[operation->parent_count - 1];
    const int arena = operation->arena_fd;
    const char *name = operation->components[operation->parent_count - 1];
    if (operation->deleting) {
        if (!operation->original_verified || !publication_original_held(operation, parent, name, 1) ||
            (operation->original_directory && publication_empty_directory(operation, operation->original_fd) != 1) ||
            !publication_absent(arena, operation->quarantine) || !publication_rename_exclusive(parent, name, arena, operation->quarantine))
            return native_error(env, "publication delete did not quarantine its exact original");
        operation->phase = 3;
        if (!publication_capture_actual(operation, operation->quarantine)) return native_error(env, "publication actual delete preimage could not be captured; retain its private inode");
        if (!publication_parent_held(operation) || !publication_absent(parent, name) || !publication_original_held(operation, arena, operation->quarantine, 0) ||
            (operation->original_directory && publication_empty_directory(operation, operation->original_fd) != 1) || !sync_directory(arena) || !sync_directory(parent) ||
            !publication_parent_held(operation) || !publication_original_held(operation, arena, operation->quarantine, 0))
            return native_error(env, "publication delete identity or directory sync is unconfirmed");
        operation->phase = 4; return publication_undefined(env);
    }
    if (operation->replacing) {
        if (!operation->original_verified || !publication_original_held(operation, parent, name, 1) ||
            (operation->original_directory && publication_empty_directory(operation, operation->original_fd) != 1) || !publication_absent(arena, operation->quarantine) ||
            !publication_exchange(arena, operation->staging, parent, name)) return native_error(env, "publication replacement did not exchange its exact original");
    } else if (!publication_absent(parent, name) || !publication_rename_exclusive(arena, operation->staging, parent, name))
        return native_error(env, "publication create did not preserve destination absence");
    operation->phase = 3;
    if (operation->replacing && !publication_capture_actual(operation, operation->staging))
        return native_error(env, "publication actual replacement preimage could not be captured; retain every transient");
    if (operation->replacing && (!publication_parent_held(operation) || !publication_stage_held(operation, parent, name) ||
        !publication_original_held(operation, arena, operation->staging, 0) ||
        (operation->original_directory && publication_empty_directory(operation, operation->original_fd) != 1) ||
        !publication_rename_exclusive(arena, operation->staging, arena, operation->quarantine)))
        return native_error(env, "publication displaced original is uncertain; retain every transient");
    if (operation->replacing && !publication_relocate_actual(operation))
        return native_error(env, "publication actual preimage changed during its original quarantine move");
    if (!publication_parent_held(operation) || !publication_stage_held(operation, parent, name) ||
        !publication_absent(arena, operation->staging) || !sync_directory(arena) || !sync_directory(parent) ||
        !publication_parent_held(operation) || !publication_stage_held(operation, parent, name))
        return native_error(env, "publication create identity or parent sync is unconfirmed");
    if (fstat(operation->stage_fd, &operation->destination_id) < 0) return native_error(env, "publication committed identity unavailable");
    operation->destination_ready = 1; operation->phase = 4; return publication_undefined(env);
}
static int publication_set_string(napi_env env, napi_value object, const char *key, const char *text) {
    napi_value value; return napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &value) == napi_ok && napi_set_named_property(env, object, key, value) == napi_ok;
}
static int publication_private_identity(napi_env env, napi_value object, const char *key, const struct stat *info) {
    napi_value value, uid, mode;
#ifdef __APPLE__
    unsigned long long device = (uint32_t)info->st_dev;
#else
    unsigned long long device = info->st_dev;
#endif
    return private_directory(info) && napi_create_object(env, &value) == napi_ok &&
        decimal_member(env, value, "deviceId", device) && decimal_member(env, value, "fileId", info->st_ino) &&
        napi_create_uint32(env, info->st_uid, &uid) == napi_ok && napi_set_named_property(env, value, "ownerUid", uid) == napi_ok &&
        napi_create_uint32(env, info->st_mode & 07777, &mode) == napi_ok && napi_set_named_property(env, value, "mode", mode) == napi_ok &&
        napi_object_freeze(env, value) == napi_ok && napi_set_named_property(env, object, key, value) == napi_ok;
}
static napi_value publication_describe_actual(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info); napi_value result, location, mode, links, empty;
    if (!operation) return NULL;
    if (!publication_actual_held(operation)) return native_error(env, "publication actual preimage was not captured by its original syscall");
    const struct stat *actual = &operation->actual_id;
    const char *kind = S_ISREG(actual->st_mode) ? "file" : S_ISLNK(actual->st_mode) ? "symlink" : S_ISDIR(actual->st_mode) ? "directory" : "unsupported";
    if (napi_create_object(env, &result) != napi_ok || napi_create_object(env, &location) != napi_ok ||
        !publication_set_string(env, location, "kind", "publication_arena") || !publication_set_string(env, location, "arenaId", operation->arena_name) ||
        !publication_set_string(env, location, "component", operation->actual_name) || napi_object_freeze(env, location) != napi_ok ||
        napi_set_named_property(env, result, "location", location) != napi_ok || !publication_set_string(env, result, "kind", kind) ||
        !identity_member(env, result, "identity", actual) || !decimal_member(env, result, "byteCount", (unsigned long long)actual->st_size) ||
        napi_create_uint32(env, actual->st_mode & 07777, &mode) != napi_ok || napi_set_named_property(env, result, "mode", mode) != napi_ok ||
        napi_create_double(env, (double)actual->st_nlink, &links) != napi_ok || napi_set_named_property(env, result, "linkCount", links) != napi_ok)
        return NULL;
    if (S_ISDIR(actual->st_mode)) {
        int is_empty = publication_empty_directory(operation, operation->actual_fd);
        if (is_empty < 0 || !publication_actual_held(operation)) return native_error(env, "publication actual directory emptiness is uncertain");
        if (napi_get_boolean(env, is_empty == 1, &empty) != napi_ok || napi_set_named_property(env, result, "empty", empty) != napi_ok) return NULL;
    }
    if (operation->actual_complete && !publication_set_string(env, result, "digest", operation->actual_digest)) return NULL;
    return napi_object_freeze(env, result) == napi_ok ? result : NULL;
}
static int publication_observe_at(napi_env env, publication_operation *operation, int parent, const char *name, napi_value *result) {
    struct stat observed;
    if (napi_create_object(env, result) != napi_ok) return 0;
    if (fstatat(parent, name, &observed, AT_SYMLINK_NOFOLLOW) < 0)
        return errno == ENOENT && publication_set_string(env, *result, "kind", "absent");
    const char *kind = S_ISREG(observed.st_mode) ? "file" : S_ISDIR(observed.st_mode) ? "directory" : S_ISLNK(observed.st_mode) ? "symlink" : "unsupported";
    napi_value mode, size, links;
    if (!(publication_set_string(env, *result, "kind", kind) && identity_member(env, *result, "identity", &observed) &&
        napi_create_uint32(env, observed.st_mode & 07777, &mode) == napi_ok && napi_set_named_property(env, *result, "mode", mode) == napi_ok &&
        napi_create_double(env, (double)observed.st_size, &size) == napi_ok && napi_set_named_property(env, *result, "byteCount", size) == napi_ok &&
        napi_create_double(env, (double)observed.st_nlink, &links) == napi_ok && napi_set_named_property(env, *result, "linkCount", links) == napi_ok)) return 0;
    if (S_ISREG(observed.st_mode)) {
        const char *digest = NULL;
        if (operation->destination_verified && same_inode(&observed, &operation->stage_id) && source_metadata_same(&observed, &operation->destination_id)) digest = operation->desired_digest;
        else if (operation->original_verified && same_inode(&observed, &operation->original_id) && source_metadata_same(&observed, &operation->original_id)) digest = operation->original_digest;
        else if (operation->preimage_verified && same_inode(&observed, &operation->original_id) && source_metadata_same(&observed, &operation->original_read_id)) digest = operation->original_digest;
        if (digest && !publication_set_string(env, *result, "digest", digest)) return 0;
    } else if (S_ISLNK(observed.st_mode)) {
        char bytes[4097], digest[65]; ssize_t length = readlinkat(parent, name, bytes, sizeof(bytes)); struct stat after;
        if (length <= 0 || length > 4096) return 0;
        bytes[length] = '\0';
        if (strlen(bytes) != (size_t)length || !utf8_valid((unsigned char *)bytes) ||
            fstatat(parent, name, &after, AT_SYMLINK_NOFOLLOW) < 0 || !source_metadata_same(&observed, &after)) return 0;
        struct sha256_context hash; sha256_init(&hash); sha256_update(&hash, (unsigned char *)bytes, (size_t)length); publication_hash_hex(&hash, digest);
        if (!publication_set_string(env, *result, "target", bytes) || !publication_set_string(env, *result, "digest", digest)) return 0;
    } else if (S_ISDIR(observed.st_mode)) {
        int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct stat opened;
        if (fd < 0) return 0;
        int valid = fstat(fd, &opened) == 0 && source_path_metadata_same(&observed, &opened);
        int empty = valid ? publication_empty_directory(operation, fd) : -1;
        valid = valid && empty >= 0 && fstatat(parent, name, &opened, AT_SYMLINK_NOFOLLOW) == 0 && source_path_metadata_same(&observed, &opened);
        publication_close_fd(operation, &fd);
        napi_value is_empty;
        if (!valid || operation->lock->publication_retirement_error || napi_get_boolean(env, empty == 1, &is_empty) != napi_ok ||
            napi_set_named_property(env, *result, "empty", is_empty) != napi_ok) return 0;
    }
    return 1;
}
static napi_value publication_observe(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info); napi_value result, destination, staging, quarantine, parent, arena, mode, links, retired, observation, fact = NULL; struct stat parent_id, arena_id, arena_parent_id;
    if (!operation) return NULL;
    if (!publication_parent_held(operation)) return native_error(env, "publication observation parent changed or closed");
    if (operation->phase >= 4 && !operation->no_effect_retirement && (operation->deleting ? !publication_absent(operation->parents[operation->parent_count - 1], operation->components[operation->parent_count - 1]) :
        !publication_stage_held(operation, operation->parents[operation->parent_count - 1], operation->components[operation->parent_count - 1]))) return native_error(env, "publication committed destination changed");
    if (napi_create_object(env, &result) != napi_ok ||
        fstat(operation->parents[operation->parent_count - 1], &parent_id) < 0 || napi_create_object(env, &parent) != napi_ok ||
        !identity_member(env, parent, "identity", &parent_id) || napi_create_uint32(env, parent_id.st_mode & 07777, &mode) != napi_ok ||
        napi_set_named_property(env, parent, "mode", mode) != napi_ok || napi_create_double(env, (double)parent_id.st_nlink, &links) != napi_ok ||
        napi_set_named_property(env, parent, "linkCount", links) != napi_ok || napi_set_named_property(env, result, "parent", parent) != napi_ok ||
        fstat(operation->arena_fd, &arena_id) < 0 || napi_create_object(env, &arena) != napi_ok ||
        !publication_set_string(env, arena, "id", operation->arena_name) || !identity_member(env, arena, "identity", &arena_id) ||
        napi_create_uint32(env, arena_id.st_mode & 07777, &mode) != napi_ok || napi_set_named_property(env, arena, "mode", mode) != napi_ok ||
        napi_create_double(env, (double)arena_id.st_nlink, &links) != napi_ok || napi_set_named_property(env, arena, "linkCount", links) != napi_ok ||
        fstat(operation->arena_parent_fd, &arena_parent_id) < 0 || !publication_private_identity(env, arena, "parentIdentity", &arena_parent_id) ||
        napi_get_boolean(env, operation->phase == 6, &retired) != napi_ok || napi_set_named_property(env, arena, "retired", retired) != napi_ok ||
        napi_get_boolean(env, operation->arena_removed, &retired) != napi_ok || napi_set_named_property(env, arena, "absent", retired) != napi_ok ||
        napi_set_named_property(env, result, "arena", arena) != napi_ok ||
        !publication_observe_at(env, operation, operation->parents[operation->parent_count - 1], operation->components[operation->parent_count - 1], &destination) ||
        napi_set_named_property(env, result, "destination", destination) != napi_ok ||
        (*operation->staging && (!publication_observe_at(env, operation, operation->arena_fd, operation->staging, &staging) || napi_set_named_property(env, result, "staging", staging) != napi_ok)) ||
        (*operation->quarantine && (!publication_observe_at(env, operation, operation->arena_fd, operation->quarantine, &quarantine) || napi_set_named_property(env, result, "quarantine", quarantine) != napi_ok)) ||
        !publication_parent_held(operation))
        return native_error(env, "publication path observation failed");
    if (operation->phase == 6) {
        if (napi_create_object(env, &observation) != napi_ok) return NULL;
#ifdef __APPLE__
        if (!publication_set_string(env, observation, "kind", "darwin_unlinked") ||
            napi_get_boolean(env, true, &fact) != napi_ok || napi_set_named_property(env, observation, "heldPathUnchanged", fact) != napi_ok ||
            napi_set_named_property(env, observation, "parentPathUnchanged", fact) != napi_ok ||
            napi_create_double(env, (double)arena_id.st_nlink, &links) != napi_ok || napi_set_named_property(env, observation, "observedLinkCount", links) != napi_ok) return NULL;
#else
        (void)fact;
        if (!publication_set_string(env, observation, "kind", "linux_unlinked") ||
            napi_create_uint32(env, (uint32_t)arena_id.st_nlink, &links) != napi_ok || napi_set_named_property(env, observation, "linkCount", links) != napi_ok) return NULL;
#endif
        if (napi_set_named_property(env, arena, "retirementObservation", observation) != napi_ok) return NULL;
    }
    return result;
}
static napi_value publication_cleanup(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info);
    if (!operation) return NULL;
    const int parent = operation->parents[operation->parent_count - 1];
    const int arena = operation->arena_fd;
    if (!publication_parent_held(operation) || operation->phase != 4 ||
        !(operation->deleting ? publication_absent(parent, operation->components[operation->parent_count - 1]) :
          publication_stage_held(operation, parent, operation->components[operation->parent_count - 1])) ||
        (*operation->staging && !publication_absent(arena, operation->staging)))
        return native_error(env, "publication cleanup is not positively complete");
    if (operation->replacing) {
        struct stat original;
        if (!operation->preimage_verified || !publication_original_held(operation, arena, operation->quarantine, 0) ||
            (operation->original_directory ? publication_empty_directory(operation, operation->original_fd) != 1 :
             fstat(operation->original_fd, &original) < 0 || !source_metadata_same(&original, &operation->original_read_id)))
            return native_error(env, "publication original preimage is not preserved or exact cleanup is uncertain");
#ifdef __APPLE__
        char parent_path[PATH_MAX], expected_path[PATH_MAX], observed_path[PATH_MAX];
        if (operation->original_directory && (fcntl(arena, F_GETPATH, parent_path) < 0 ||
            snprintf(expected_path, sizeof(expected_path), "%s/%s", parent_path, operation->quarantine) >= (int)sizeof(expected_path) ||
            fcntl(operation->original_fd, F_GETPATH, observed_path) < 0 || strcmp(expected_path, observed_path)))
            return native_error(env, "publication original directory locator changed before cleanup");
#endif
        if (unlinkat(arena, operation->quarantine, operation->original_directory ? AT_REMOVEDIR : 0) < 0 ||
            fstat(operation->original_fd, &original) < 0 || !same_inode(&original, &operation->original_id))
            return native_error(env, "publication original cleanup is uncertain");
#ifdef __APPLE__
        if (operation->original_directory ? fcntl(operation->original_fd, F_GETPATH, observed_path) < 0 || strcmp(expected_path, observed_path) ||
            fcntl(arena, F_GETPATH, observed_path) < 0 || strcmp(parent_path, observed_path) : original.st_nlink + 1 != operation->original_read_id.st_nlink)
            return native_error(env, "publication original unlink is not proven");
#else
        if (operation->original_directory ? original.st_nlink != 0 : original.st_nlink + 1 != operation->original_read_id.st_nlink)
            return native_error(env, "publication original unlink is not proven");
#endif
        if (!publication_absent(arena, operation->quarantine)) return native_error(env, "publication cleanup name is not absent");
    }
    if (!sync_directory(arena) || !sync_directory(parent) || !publication_parent_held(operation)) return native_error(env, "publication cleanup parent sync is unconfirmed");
    operation->phase = 5; return publication_undefined(env);
}
static napi_value publication_retire_arena(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info); struct stat unlinked, named;
    if (!operation) return NULL;
    if (!publication_parent_held(operation) || (operation->phase != -1 && operation->phase != 5 && operation->phase != 6))
        return native_error(env, "publication arena retirement requires its completed original cleanup");
    if (operation->phase == 6) return publication_undefined(env);
    if (operation->arena_removed) goto sync_parents;
    if ((*operation->staging && !publication_absent(operation->arena_fd, operation->staging)) ||
        (*operation->quarantine && !publication_absent(operation->arena_fd, operation->quarantine)) ||
        publication_empty_directory(operation, operation->arena_fd) != 1 || !publication_retirement_sync(operation, 0, operation->arena_fd))
        return native_error(env, "publication arena is not exactly empty and synced");
#ifdef __APPLE__
    char observed[PATH_MAX];
    if (fcntl(operation->arena_parent_fd, F_GETPATH, operation->arena_parent_path) < 0 ||
        snprintf(operation->arena_path, sizeof(operation->arena_path), "%s/%s", operation->arena_parent_path, operation->arena_name) >= (int)sizeof(operation->arena_path) ||
        fcntl(operation->arena_fd, F_GETPATH, observed) < 0 || strcmp(observed, operation->arena_path))
        return native_error(env, "publication arena original held path changed before retirement");
#endif
    if (unlinkat(operation->arena_parent_fd, operation->arena_name, AT_REMOVEDIR) < 0 ||
        fstat(operation->arena_fd, &unlinked) < 0 || !source_path_metadata_same(&operation->arena_id, &unlinked))
        return native_error(env, "publication arena original rmdir is unconfirmed");
    operation->arena_removed = 1;
sync_parents:
    if (!publication_arena_held(operation) ||
        fstatat(operation->arena_parent_fd, operation->arena_name, &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT ||
        !publication_retirement_sync(operation, 1, operation->arena_parent_fd) ||
        !publication_retirement_sync(operation, 2, operation->parents[operation->parent_count - 1]) || !publication_parent_held(operation))
        return native_error(env, "publication arena original unlink or parent sync is unconfirmed");
    operation->phase = 6; return publication_undefined(env);
}
static napi_value publication_assert_arena_retired(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_unwrap(env, info); struct stat parent, named;
    if (!operation) return NULL;
    operation->retirement_post_join_observed = 0;
    if (operation->lock->publication_retirement_error) return publication_retirement_error(env);
    if (!operation->closed || operation->phase != 6 || !operation->arena_removed || !lock_is_held(operation->lock))
        return native_error(env, "publication arena has no original completed unlink and joined descriptors");
    int fd = openat(operation->lock->runtime_fd, "publications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return native_error(env, "publication retirement parent cannot be observed");
    int valid = fstat(fd, &parent) == 0 && private_directory(&parent) && source_path_metadata_same(&operation->arena_parent_id, &parent) &&
        fstatat(operation->lock->runtime_fd, "publications", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_path_metadata_same(&parent, &named) &&
        fstatat(fd, operation->arena_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT && lock_is_held(operation->lock);
    publication_close_fd(operation, &fd);
    if (operation->lock->publication_retirement_error) return publication_retirement_error(env);
    if (!valid) return native_error(env, "publication arena retirement named absence or original parent changed");
    operation->retirement_post_join_observed = 1;
    return publication_undefined(env);
}
static int publication_string(napi_env env, napi_value object, const char *key, char *text, size_t capacity) {
    napi_value value; size_t length;
    return napi_get_named_property(env, object, key, &value) == napi_ok &&
        napi_get_value_string_utf8(env, value, NULL, 0, &length) == napi_ok && length > 0 && length < capacity &&
        napi_get_value_string_utf8(env, value, text, capacity, &length) == napi_ok && strlen(text) == length;
}
static int publication_integer(napi_env env, napi_value object, const char *key, double maximum, double *number) {
    napi_value value;
    return napi_get_named_property(env, object, key, &value) == napi_ok && napi_get_value_double(env, value, number) == napi_ok &&
        *number >= 0 && *number <= maximum && *number == (double)(unsigned long long)*number;
}
static int publication_component(const char *name) {
    return *name && strlen(name) <= NAME_MAX && !strchr(name, '/') && !strchr(name, '\\') &&
        strcmp(name, ".") != 0 && strcmp(name, "..") != 0 && strcasecmp(name, ".git") != 0;
}
static int publication_target(napi_env env, napi_value object, char target[4097], char digest[65]) {
    char observed[65]; struct sha256_context hash;
    if (!publication_string(env, object, "target", target, 4097) || !utf8_valid((unsigned char *)target) ||
        !publication_string(env, object, "digest", digest, 65) || strlen(digest) != 64) return 0;
    sha256_init(&hash); sha256_update(&hash, (unsigned char *)target, strlen(target)); publication_hash_hex(&hash, observed);
    return strcmp(observed, digest) == 0;
}
static int publication_expected_inode(napi_env env, napi_value value, const struct stat *observed) {
    napi_value member; unsigned long long device, inode;
    return napi_get_named_property(env, value, "deviceId", &member) == napi_ok && read_unsigned_id(env, member, &device) &&
        napi_get_named_property(env, value, "fileId", &member) == napi_ok && read_unsigned_id(env, member, &inode) &&
#ifdef __APPLE__
        device == (uint32_t)observed->st_dev &&
#else
        device == (unsigned long long)observed->st_dev &&
#endif
        inode == (unsigned long long)observed->st_ino;
}
static int publication_expected_identity(napi_env env, napi_value value, const struct stat *observed) {
    double uid;
    return publication_expected_inode(env, value, observed) && publication_integer(env, value, "ownerUid", 4294967295.0, &uid) && uid == observed->st_uid;
}
static int publication_expected_parent(napi_env env, napi_value value, const struct stat *observed) {
    double mode;
    return publication_expected_identity(env, value, observed) && publication_integer(env, value, "mode", 07777, &mode) && mode == (observed->st_mode & 07777);
}
static int publication_open_arena(napi_env env, publication_operation *operation, int retaining, napi_value retained) {
    state_lock *lock = operation->lock; napi_value value;
    if (operation->root->ids[operation->root->count - 1].st_dev != lock->root.st_dev) return 0;
    if (!retaining && mkdirat(lock->runtime_fd, "publications", 0700) < 0 && errno != EEXIST) return 0;
    operation->arena_parent_fd = openat(lock->runtime_fd, "publications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (operation->arena_parent_fd < 0 || fstat(operation->arena_parent_fd, &operation->arena_parent_id) < 0 ||
        !private_directory(&operation->arena_parent_id) || operation->arena_parent_id.st_dev != lock->root.st_dev) return 0;
    if (!retaining && mkdirat(operation->arena_parent_fd, operation->arena_name, 0700) < 0) return 0;
    operation->arena_fd = openat(operation->arena_parent_fd, operation->arena_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (operation->arena_fd < 0 || fstat(operation->arena_fd, &operation->arena_id) < 0 || !publication_arena_held(operation) ||
        (retaining && (napi_get_named_property(env, retained, "arena", &value) != napi_ok || !publication_expected_inode(env, value, &operation->arena_id)))) return 0;
    return retaining || (sync_directory(operation->arena_fd) && sync_directory(operation->arena_parent_fd) && sync_directory(lock->runtime_fd));
}
static napi_value open_publication_operation(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info); napi_value self, argv[2], value, parents, desired, expected, retained = NULL;
    size_t argc = 2; bool tagged = false, retaining = false; source_root *root = NULL; char kind[16], expected_kind[16], desired_kind[16]; double mode, size;
    if (!lock) return NULL;
    if (lock->publication_retirement_error) return publication_retirement_error(env);
    if (!lock_is_held(lock) || napi_get_cb_info(env, info, &argc, argv, &self, NULL) != napi_ok || argc != 2 ||
        napi_check_object_type_tag(env, argv[0], &source_root_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, argv[0], (void **)&root) != napi_ok || !root || !source_held(root))
        return native_error(env, "publication requires actual held StateOwner and workspace descriptors");
    publication_operation *operation = calloc(1, sizeof(*operation));
    if (!operation) return native_error(env, "publication operation allocation failed");
    operation->lock = lock; operation->root = root; operation->stage_fd = operation->original_fd = operation->actual_fd = operation->arena_fd = operation->arena_parent_fd = -1;
    const char *error = "invalid fixed publication operation";
    operation->path = malloc(4097);
    if (!operation->path || napi_get_named_property(env, argv[1], "arenaId", &value) != napi_ok ||
        !read_component(env, value, operation->arena_name, sizeof(operation->arena_name), 43) ||
        !publication_string(env, argv[1], "path", operation->path, 4097) ||
        !publication_string(env, argv[1], "kind", kind, sizeof(kind)) ||
        napi_get_named_property(env, argv[1], "expected", &expected) != napi_ok ||
        !publication_string(env, expected, "kind", expected_kind, sizeof(expected_kind)) ||
        napi_get_named_property(env, argv[1], "desired", &desired) != napi_ok ||
        !publication_string(env, desired, "kind", desired_kind, sizeof(desired_kind)) ||
        napi_get_named_property(env, argv[1], "parents", &parents) != napi_ok) goto fail;
    if (napi_has_named_property(env, argv[1], "retained", &retaining) != napi_ok ||
        (retaining && napi_get_named_property(env, argv[1], "retained", &retained) != napi_ok)) goto fail;
    const int abort_removal = strcmp(kind, "abort_rmdir") == 0;
    operation->deleting = strcmp(kind, "delete") == 0 || abort_removal; operation->making_directory = strcmp(kind, "mkdir") == 0;
    operation->replacing = strcmp(kind, "replace") == 0 || operation->deleting;
    if (!operation->replacing && !operation->making_directory && strcmp(kind, "create") != 0) goto fail;
    /* Abort has no desired-entry or staging capability. Its expected inode
     * comes from the sole producer's original completed directory receipt;
     * the physical mechanism still proves identity/emptiness before and after
     * quarantining it, and never treats a foreign displaced inode as cleanup. */
    if (abort_removal) {
        bool staging;
        if (strcmp(expected_kind, "directory") ||
            napi_has_named_property(env, argv[1], "stagingName", &staging) != napi_ok || staging) goto fail;
    }
    if (operation->deleting) { if (strcmp(desired_kind, "absent") != 0) goto fail; mode = 0; }
    else if (strcmp(desired_kind, "symlink") == 0) { operation->desired_link = 1; mode = 0777; }
    else if ((strcmp(desired_kind, "file") != 0 && strcmp(desired_kind, "directory") != 0) ||
        !publication_integer(env, desired, "mode", 0777, &mode) || (mode != 0644 && mode != 0755)) goto fail;
    if (!operation->deleting && !operation->making_directory &&
        (!publication_string(env, argv[1], "stagingName", operation->staging, sizeof(operation->staging)) || !publication_component(operation->staging))) goto fail;
    operation->desired_directory = strcmp(desired_kind, "directory") == 0;
    if (operation->making_directory) strcpy(operation->staging, "desired");
    if ((operation->making_directory && !operation->desired_directory) ||
        (!operation->replacing && !operation->making_directory && operation->desired_directory)) goto fail;
    if (operation->desired_directory) { if (mode != 0755) goto fail; }
    else if (!operation->deleting) {
        if (operation->desired_link) {
            if (!publication_target(env, desired, operation->desired_target, operation->desired_digest)) goto fail;
            operation->desired_size = (off_t)strlen(operation->desired_target);
        } else {
        if (!publication_integer(env, desired, "byteCount", 9007199254740991.0, &size) ||
            !publication_string(env, desired, "digest", operation->desired_digest, sizeof(operation->desired_digest)) || strlen(operation->desired_digest) != 64) goto fail;
        for (size_t index = 0; index < 64; index++) if (!((operation->desired_digest[index] >= '0' && operation->desired_digest[index] <= '9') ||
            (operation->desired_digest[index] >= 'a' && operation->desired_digest[index] <= 'f'))) goto fail;
        operation->desired_size = (off_t)size;
        }
    }
    operation->desired_mode = (mode_t)mode;
    if (operation->replacing) {
        double original_mode, original_size;
        operation->original_directory = strcmp(expected_kind, "directory") == 0; operation->original_link = strcmp(expected_kind, "symlink") == 0;
        if ((!operation->original_directory && !operation->original_link && strcmp(expected_kind, "file") != 0) ||
            (!operation->original_link && !publication_integer(env, expected, "mode", 07777, &original_mode)) ||
            !publication_string(env, argv[1], "quarantineName", operation->quarantine, sizeof(operation->quarantine)) || !publication_component(operation->quarantine) ||
            (*operation->staging && strcmp(operation->quarantine, operation->staging) == 0)) goto fail;
        if (abort_removal && strcmp(operation->quarantine, "preimage")) goto fail;
        if (operation->original_link) {
            if (!publication_target(env, expected, operation->original_target, operation->original_digest)) goto fail;
            operation->original_size = (off_t)strlen(operation->original_target); original_mode = 0777;
        } else if (!operation->original_directory) {
            if (!publication_integer(env, expected, "byteCount", 9007199254740991.0, &original_size) ||
                !publication_string(env, expected, "digest", operation->original_digest, sizeof(operation->original_digest)) || strlen(operation->original_digest) != 64) goto fail;
            operation->original_size = (off_t)original_size;
        }
        operation->original_mode = (mode_t)original_mode;
        sha256_init(&operation->original_hash);
    } else if (strcmp(expected_kind, "absent") != 0) goto fail;
    size_t count = 1;
    for (const char *part = operation->path; *part; part++) if (*part == '/') count++;
    operation->parents = malloc(count * sizeof(int)); operation->parent_ids = calloc(count, sizeof(struct stat)); operation->components = calloc(count, sizeof(char *));
    if (!operation->parents || !operation->parent_ids || !operation->components) goto fail;
    for (size_t index = 0; index < count; index++) operation->parents[index] = -1;
    uint32_t parent_length;
    if (napi_get_array_length(env, parents, &parent_length) != napi_ok || parent_length != count) goto fail;
    char *component = operation->path;
    for (size_t index = 0; index < count; index++) {
        char *end = strchr(component, '/'); if (end) *end = '\0';
        if (!publication_component(component)) goto fail;
        operation->components[index] = component;
        operation->parents[index] = index == 0 ? fcntl(root->fds[root->count - 1], F_DUPFD_CLOEXEC, 0) :
            openat(operation->parents[index - 1], operation->components[index - 1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        operation->parent_count = index + 1;
        if (operation->parents[index] < 0 || fstat(operation->parents[index], &operation->parent_ids[index]) < 0 ||
            !S_ISDIR(operation->parent_ids[index].st_mode) ||
            operation->parent_ids[index].st_dev != root->ids[root->count - 1].st_dev ||
            napi_get_element(env, parents, (uint32_t)index, &value) != napi_ok || !publication_expected_parent(env, value, &operation->parent_ids[index])) goto fail;
        if (!end) break;
        component = end + 1;
    }
    if (!publication_parent_held(operation) || (retaining && !publication_open_arena(env, operation, 1, retained))) goto fail;
    if (operation->replacing) {
        const char *original_name = retaining ? operation->quarantine : operation->components[count - 1];
        const int original_parent = retaining ? operation->arena_fd : operation->parents[count - 1];
        operation->original_fd = operation->original_link ? publication_open_link(original_parent, original_name) :
            openat(original_parent, original_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (operation->original_fd < 0 || fstat(operation->original_fd, &operation->original_id) < 0 ||
            (!operation->original_link && (operation->original_id.st_mode & 07777) != operation->original_mode) || (!operation->original_directory && operation->original_id.st_size != operation->original_size) ||
            !publication_original_held(operation, original_parent, original_name, 1)) goto fail;
        if (operation->original_directory) {
            napi_value identity;
            if (napi_get_named_property(env, expected, "identity", &identity) != napi_ok || !publication_expected_identity(env, identity, &operation->original_id)) goto fail;
        }
        if (retaining && (napi_get_named_property(env, retained, "preimage", &value) != napi_ok || !publication_expected_inode(env, value, &operation->original_id))) goto fail;
    }
    if (!retaining && !publication_open_arena(env, operation, 0, retained)) goto fail;
    if (retaining) {
        const int parent = operation->parents[count - 1]; const char *name = operation->components[count - 1];
        if (*operation->staging && !publication_absent(operation->arena_fd, operation->staging)) goto fail;
        if (operation->deleting) { if (!publication_absent(parent, name)) goto fail; }
        else {
            operation->stage_fd = operation->desired_link ? publication_open_link(parent, name) :
                openat(parent, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC | (operation->desired_directory ? O_DIRECTORY : 0));
            if (operation->stage_fd < 0 || fstat(operation->stage_fd, &operation->stage_id) < 0 ||
                operation->stage_id.st_uid != geteuid() ||
                napi_get_named_property(env, retained, "destination", &value) != napi_ok || !publication_expected_inode(env, value, &operation->stage_id) ||
                !publication_stage_held(operation, parent, name) || (!operation->desired_directory && operation->stage_id.st_size != operation->desired_size)) goto fail;
            operation->destination_id = operation->stage_id; operation->destination_ready = 1;
        }
        operation->phase = 4; operation->revoked = 1;
    }
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, publication_assert, NULL, NULL, NULL, napi_default, NULL},
        {"arm", NULL, publication_arm, NULL, NULL, NULL, napi_default, NULL},
        {"revoke", NULL, publication_revoke, NULL, NULL, NULL, napi_default, NULL},
        {"discardStage", NULL, publication_discard_stage, NULL, NULL, NULL, napi_default, NULL},
        {"inspectState", NULL, publication_inspect_state, NULL, NULL, NULL, napi_default, NULL},
        {"reconcile", NULL, publication_reconcile, NULL, NULL, NULL, napi_default, NULL},
        {"stage", NULL, publication_stage, NULL, NULL, NULL, napi_default, NULL},
        {"writeChunk", NULL, publication_write, NULL, NULL, NULL, napi_default, NULL},
        {"finishStage", NULL, publication_finish_stage, NULL, NULL, NULL, napi_default, NULL},
        {"readOriginalChunk", NULL, publication_original_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"readInspectionOriginalChunk", NULL, publication_inspection_original_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"readPreimageChunk", NULL, publication_preimage_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"describeActualPreimage", NULL, publication_describe_actual, NULL, NULL, NULL, napi_default, NULL},
        {"readActualPreimageChunk", NULL, publication_actual_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"readDestinationChunk", NULL, publication_destination_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"restartRead", NULL, publication_restart_read, NULL, NULL, NULL, napi_default, NULL},
        {"commit", NULL, publication_commit, NULL, NULL, NULL, napi_default, NULL},
        {"observe", NULL, publication_observe, NULL, NULL, NULL, napi_default, NULL},
        {"finishCleanup", NULL, publication_cleanup, NULL, NULL, NULL, napi_default, NULL},
        {"finishArenaRetirement", NULL, publication_retire_arena, NULL, NULL, NULL, napi_default, NULL},
        {"assertArenaRetired", NULL, publication_assert_arena_retired, NULL, NULL, NULL, napi_default, NULL},
        {"readRetirementDiagnostic", NULL, publication_read_retirement_diagnostic, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, publication_release, NULL, NULL, NULL, napi_default, NULL}
    };
    napi_value result;
    if (napi_create_reference(env, self, 1, &operation->lock_ref) != napi_ok || napi_create_reference(env, argv[0], 1, &operation->root_ref) != napi_ok ||
        napi_create_object(env, &result) != napi_ok || napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &publication_operation_tag) != napi_ok || napi_wrap(env, result, operation, publication_finalize, NULL, NULL) != napi_ok) goto fail;
    operation->next = lock->publication_operations; lock->publication_operations = operation;
    return result;
fail:
    publication_close(operation); publication_free(env, operation);
    if (lock->publication_retirement_error) return publication_retirement_error(env);
    return native_error(env, error);
}

/* A different physical role and type tag: no original FD is reconstructed,
 * and borrowing an original publisher's arm/commit/cleanup method fails its
 * tag check. Complete claim/birth/progress/takeover checks remain the sole
 * production consumer's responsibility; these observations grant no release. */
static const napi_type_tag publication_namespace_tag = {0x752cdf928ecb4a71ULL, 0x98e17d6ab42f3906ULL};
static publication_operation *publication_namespace_unwrap(napi_env env, napi_callback_info info) {
    napi_value self; bool tagged = false; publication_operation *operation = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &publication_namespace_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&operation) != napi_ok || !operation) {
        native_error(env, "invalid opaque publication namespace observer"); return NULL;
    }
    return operation;
}
static napi_value publication_namespace_error(napi_env env, publication_operation *operation, const char *message) {
    return operation->lock->publication_retirement_error ? publication_retirement_error(env) : native_error(env, message);
}
/* Zero=invalid, one=empty, two=the sole registered original preimage. The
 * latter only routes to the unchanged retained constructor, never retirement. */
static int publication_namespace_inventory(publication_operation *operation) {
    struct stat before, opened, after, slot;
    if (operation->arena_fd < 0 || operation->arena_removed) return 0;
    if (fstat(operation->arena_fd, &before) < 0 || !private_directory(&before)) return 0;
    int fd = openat(operation->arena_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    if (fstat(fd, &opened) < 0 || !source_metadata_same(&before, &opened)) { publication_close_fd(operation, &fd); return 0; }
    DIR *directory = fdopendir(fd);
    if (!directory) { publication_close_fd(operation, &fd); return 0; }
    int state = 1; struct dirent *entry;
    for (;;) {
        errno = 0; entry = readdir(directory);
        if (!entry) { if (errno) state = 0; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (state != 1 || !operation->namespace_preimage_expected || !*operation->quarantine ||
            strcmp(entry->d_name, operation->quarantine) ||
            fstatat(operation->arena_fd, operation->quarantine, &slot, AT_SYMLINK_NOFOLLOW) < 0 ||
            slot.st_dev != operation->lock->root.st_dev ||
            !(S_ISDIR(slot.st_mode) || S_ISLNK(slot.st_mode) || (S_ISREG(slot.st_mode) && slot.st_nlink == 1)) ||
#ifdef __APPLE__
            (unsigned long long)(uint32_t)slot.st_dev != operation->namespace_preimage_device ||
#else
            (unsigned long long)slot.st_dev != operation->namespace_preimage_device ||
#endif
            (unsigned long long)slot.st_ino != operation->namespace_preimage_inode) { state = 0; break; }
        state = 2;
    }
    if (fstat(operation->arena_fd, &after) < 0 || !source_metadata_same(&before, &after)) state = 0;
    if (closedir(directory) < 0) { operation->lock->publication_retirement_error = errno; return 0; }
    return state;
}
static int publication_namespace_held(publication_operation *operation) {
    struct stat parent, named;
    if (operation->closed || operation->lock->publication_retirement_error ||
        !lock_is_held_with_retirement(operation->lock, &operation->lock->publication_retirement_error) || !source_held(operation->root)) return 0;
    for (size_t index = 0; index < operation->parent_count; index++) {
        struct stat opened;
        if (operation->parents[index] < 0 || fstat(operation->parents[index], &opened) < 0 || !S_ISDIR(opened.st_mode) ||
            !source_path_metadata_same(&operation->parent_ids[index], &opened) || opened.st_dev != operation->lock->root.st_dev ||
            (index && (fstatat(operation->parents[index - 1], operation->components[index - 1], &named, AT_SYMLINK_NOFOLLOW) < 0 ||
                !source_path_metadata_same(&opened, &named)))) return 0;
    }
    if (!operation->parent_count || (operation->arena_fd >= 0 && !publication_arena_held(operation)) || operation->arena_parent_fd < 0 ||
        fstat(operation->arena_parent_fd, &parent) < 0 || !private_directory(&parent) ||
        !source_path_metadata_same(&operation->arena_parent_id, &parent) || parent.st_dev != operation->lock->root.st_dev ||
        fstatat(operation->lock->runtime_fd, "publications", &named, AT_SYMLINK_NOFOLLOW) < 0 ||
        !source_path_metadata_same(&parent, &named)) return 0;
    if (operation->arena_fd < 0 || operation->arena_removed)
        return publication_absent(operation->arena_parent_fd, operation->arena_name);
    return publication_namespace_inventory(operation) > 0 && !operation->lock->publication_retirement_error &&
        publication_arena_held(operation);
}
static int publication_namespace_destination_held(publication_operation *operation) {
    const int parent = operation->parents[operation->parent_count - 1];
    const char *name = operation->components[operation->parent_count - 1];
    return operation->deleting ? publication_absent(parent, name) : publication_stage_held(operation, parent, name);
}
static napi_value publication_namespace_assert(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_namespace_unwrap(env, info);
    if (!operation) return NULL;
    if (operation->lock->publication_retirement_error) return publication_retirement_error(env);
    if (!publication_namespace_held(operation) || !publication_namespace_destination_held(operation))
        return publication_namespace_error(env, operation, "publication registered namespace or desired inode changed");
    return publication_undefined(env);
}
static napi_value publication_namespace_read(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_namespace_unwrap(env, info); napi_value result;
    if (!operation) return NULL;
    if (operation->lock->publication_retirement_error) return publication_retirement_error(env);
    if (!publication_namespace_held(operation) || !publication_namespace_destination_held(operation))
        return publication_namespace_error(env, operation, "publication namespace desired read lost its registered identity");
    if (operation->deleting) {
        operation->destination_verified = 1;
        return napi_get_null(env, &result) == napi_ok ? result : NULL;
    }
    result = publication_destination_bytes(env, operation);
    if (!result) return NULL;
    if (!publication_namespace_held(operation) || !publication_namespace_destination_held(operation))
        return publication_namespace_error(env, operation, "publication namespace changed during complete desired read");
    return result;
}
static napi_value publication_namespace_observe(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_namespace_unwrap(env, info); napi_value result, destination, parent, mode, links; struct stat info_parent;
    if (!operation) return NULL;
    if (operation->lock->publication_retirement_error) return publication_retirement_error(env);
    if (!publication_namespace_held(operation) || !publication_namespace_destination_held(operation))
        return publication_namespace_error(env, operation, "publication namespace observation lost its exact registered parent or desired inode");
    const int parent_fd = operation->parents[operation->parent_count - 1];
    if (napi_create_object(env, &result) != napi_ok || napi_create_object(env, &parent) != napi_ok ||
        fstat(parent_fd, &info_parent) < 0 || !identity_member(env, parent, "identity", &info_parent) ||
        napi_create_uint32(env, info_parent.st_mode & 07777, &mode) != napi_ok || napi_set_named_property(env, parent, "mode", mode) != napi_ok ||
        napi_create_double(env, (double)info_parent.st_nlink, &links) != napi_ok || napi_set_named_property(env, parent, "linkCount", links) != napi_ok ||
        napi_set_named_property(env, result, "parent", parent) != napi_ok ||
        !publication_set_string(env, result, "state", operation->arena_fd < 0 || operation->arena_removed ? "arena_absent" :
            publication_namespace_inventory(operation) == 2 ? "original_slots_present" : "original_arena_empty") ||
        !publication_private_identity(env, result, "parentIdentity", &operation->arena_parent_id) ||
        !publication_observe_at(env, operation, parent_fd, operation->components[operation->parent_count - 1], &destination) ||
        napi_set_named_property(env, result, "destination", destination) != napi_ok ||
        !publication_namespace_held(operation) || !publication_namespace_destination_held(operation))
        return operation->lock->publication_retirement_error ? publication_retirement_error(env) : native_error(env, "publication current namespace observation failed");
    return result;
}
/* Explicit original-claim maintenance only. Observation never invokes this.
 * There is no preimage unlink, creation, stage, normalization or release. */
static napi_value publication_namespace_retire(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_namespace_unwrap(env, info);
    if (!operation) return NULL;
    if (operation->lock->publication_retirement_error) return publication_retirement_error(env);
    if (!publication_namespace_held(operation) || !publication_namespace_destination_held(operation) || !operation->destination_verified)
        return publication_namespace_error(env, operation, "publication namespace retirement requires its full desired read and exact empty envelope");
    if (operation->arena_fd >= 0 && !operation->arena_removed) {
        if (publication_namespace_inventory(operation) != 1 || !publication_retirement_sync(operation, 0, operation->arena_fd) || !publication_namespace_held(operation))
            return publication_namespace_error(env, operation, "publication namespace original empty arena sync is unconfirmed");
#ifdef __APPLE__
        char observed[PATH_MAX];
        if (fcntl(operation->arena_parent_fd, F_GETPATH, operation->arena_parent_path) < 0 ||
            snprintf(operation->arena_path, sizeof(operation->arena_path), "%s/%s", operation->arena_parent_path, operation->arena_name) >= (int)sizeof(operation->arena_path) ||
            fcntl(operation->arena_fd, F_GETPATH, observed) < 0 || strcmp(observed, operation->arena_path))
            return native_error(env, "publication namespace original empty arena locator changed");
#endif
        if (unlinkat(operation->arena_parent_fd, operation->arena_name, AT_REMOVEDIR) < 0)
            return native_error(env, "publication namespace original empty arena rmdir is unconfirmed");
        operation->arena_removed = 1;
    }
    if (!publication_namespace_held(operation) || !publication_namespace_destination_held(operation) ||
        !publication_retirement_sync(operation, 1, operation->arena_parent_fd) ||
        !publication_retirement_sync(operation, 2, operation->parents[operation->parent_count - 1]) ||
        !publication_namespace_held(operation) || !publication_namespace_destination_held(operation))
        return publication_namespace_error(env, operation, "publication namespace current absence or parent sync is unconfirmed");
    operation->namespace_retired = 1;
    return publication_undefined(env);
}
static napi_value publication_namespace_release(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_namespace_unwrap(env, info);
    if (!operation) return NULL;
    publication_close(operation);
    return operation->lock->publication_retirement_error ? publication_retirement_error(env) : publication_undefined(env);
}
static napi_value publication_namespace_retired(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_namespace_unwrap(env, info); struct stat parent, named; napi_value result, fact;
    if (!operation) return NULL;
    operation->retirement_post_join_observed = 0;
    if (operation->lock->publication_retirement_error) return publication_retirement_error(env);
    if (!operation->closed || !operation->namespace_retired ||
        !lock_is_held_with_retirement(operation->lock, &operation->lock->publication_retirement_error) || !source_held(operation->root))
        return publication_namespace_error(env, operation, "publication namespace has no current synced absence and joined handles");
    int fd = openat(operation->lock->runtime_fd, "publications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return native_error(env, "publication namespace original parent cannot be reobserved");
    int valid = fstat(fd, &parent) == 0 && private_directory(&parent) && source_path_metadata_same(&operation->arena_parent_id, &parent) &&
        fstatat(operation->lock->runtime_fd, "publications", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_path_metadata_same(&parent, &named) &&
        publication_absent(fd, operation->arena_name) &&
        lock_is_held_with_retirement(operation->lock, &operation->lock->publication_retirement_error) && source_held(operation->root);
    publication_close_fd(operation, &fd);
    if (operation->lock->publication_retirement_error) return publication_retirement_error(env);
    if (!valid) return native_error(env, "publication namespace current parent or registered absence changed after join");
    if (napi_create_object(env, &result) != napi_ok || !publication_set_string(env, result, "kind", "namespace_absence") ||
        !publication_set_string(env, result, "arenaId", operation->arena_name) || !publication_private_identity(env, result, "parentIdentity", &parent) ||
        napi_get_boolean(env, true, &fact) != napi_ok || napi_set_named_property(env, result, "arenaAbsent", fact) != napi_ok ||
        napi_set_named_property(env, result, "arenaParentFsyncCompleted", fact) != napi_ok ||
        napi_set_named_property(env, result, "workspaceParentFsyncCompleted", fact) != napi_ok) return NULL;
    operation->retirement_post_join_observed = 1;
    return result;
}
static napi_value publication_namespace_read_retirement_diagnostic(napi_env env, napi_callback_info info) {
    publication_operation *operation = publication_namespace_unwrap(env, info);
    return operation ? publication_retirement_diagnostic(env, operation) : NULL;
}
static int publication_namespace_private_input(napi_env env, napi_value value) {
    napi_value member; unsigned long long device, inode; double uid, mode;
    return napi_get_named_property(env, value, "deviceId", &member) == napi_ok && read_unsigned_id(env, member, &device) &&
        napi_get_named_property(env, value, "fileId", &member) == napi_ok && read_unsigned_id(env, member, &inode) && inode > 0 &&
        publication_integer(env, value, "ownerUid", 4294967295.0, &uid) && uid == geteuid() &&
        publication_integer(env, value, "mode", 07777, &mode) && mode == 0700;
}
static napi_value open_publication_namespace_observer(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info); napi_value self, argv[2], value, parents, desired, arena_identity, parent_identity, destination_identity;
    size_t argc = 2; bool tagged = false, present; source_root *root = NULL; char desired_kind[16]; double mode = 0, size = 0;
    if (!lock) return NULL;
    if (lock->publication_retirement_error) return publication_retirement_error(env);
    if (!lock_is_held_with_retirement(lock, &lock->publication_retirement_error) || napi_get_cb_info(env, info, &argc, argv, &self, NULL) != napi_ok || argc != 2 ||
        napi_check_object_type_tag(env, argv[0], &source_root_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, argv[0], (void **)&root) != napi_ok || !root || !source_held(root) ||
        root->ids[root->count - 1].st_dev != lock->root.st_dev)
        return lock->publication_retirement_error ? publication_retirement_error(env) : native_error(env, "publication namespace requires actual same-device StateOwner and workspace descriptors");
    publication_operation *operation = calloc(1, sizeof(*operation));
    if (!operation) return native_error(env, "publication namespace allocation failed");
    operation->lock = lock; operation->root = root; operation->namespace_observer = 1;
    operation->stage_fd = operation->original_fd = operation->actual_fd = operation->arena_fd = operation->arena_parent_fd = -1;
    const char *error = "publication namespace does not match its complete registered envelope";
    operation->path = malloc(4097);
    if (!operation->path || napi_get_named_property(env, argv[1], "arenaId", &value) != napi_ok ||
        !read_component(env, value, operation->arena_name, sizeof(operation->arena_name), 43) ||
        !publication_string(env, argv[1], "path", operation->path, 4097) ||
        napi_get_named_property(env, argv[1], "parents", &parents) != napi_ok ||
        napi_get_named_property(env, argv[1], "arenaIdentity", &arena_identity) != napi_ok || !publication_namespace_private_input(env, arena_identity) ||
        napi_get_named_property(env, argv[1], "parentIdentity", &parent_identity) != napi_ok || !publication_namespace_private_input(env, parent_identity) ||
        napi_get_named_property(env, argv[1], "desired", &desired) != napi_ok || !publication_string(env, desired, "kind", desired_kind, sizeof(desired_kind))) goto fail;
    operation->deleting = !strcmp(desired_kind, "absent"); operation->desired_directory = !strcmp(desired_kind, "directory"); operation->desired_link = !strcmp(desired_kind, "symlink");
    if (!operation->deleting) {
        if (operation->desired_link) {
            if (!publication_target(env, desired, operation->desired_target, operation->desired_digest)) goto fail;
            operation->desired_size = (off_t)strlen(operation->desired_target); mode = 0777;
        } else if ((!operation->desired_directory && strcmp(desired_kind, "file")) ||
            !publication_integer(env, desired, "mode", 07777, &mode) ||
            (operation->desired_directory ? mode != 0755 : mode != 0644 && mode != 0755)) goto fail;
        else if (!operation->desired_directory) {
            if (!publication_integer(env, desired, "byteCount", 268435456.0, &size) ||
                !publication_string(env, desired, "digest", operation->desired_digest, sizeof(operation->desired_digest)) || strlen(operation->desired_digest) != 64) goto fail;
            for (size_t index = 0; index < 64; index++) if (!((operation->desired_digest[index] >= '0' && operation->desired_digest[index] <= '9') ||
                (operation->desired_digest[index] >= 'a' && operation->desired_digest[index] <= 'f'))) goto fail;
            operation->desired_size = (off_t)size;
        }
        operation->desired_mode = (mode_t)mode;
    }
    for (size_t index = 0; index < 2; index++) {
        const char *key = index ? "quarantineName" : "stagingName"; char *target = index ? operation->quarantine : operation->staging;
        if (napi_has_named_property(env, argv[1], key, &present) != napi_ok ||
            (present && (!publication_string(env, argv[1], key, target, NAME_MAX + 1) || !publication_component(target)))) goto fail;
    }
    if ((!*operation->staging && !*operation->quarantine) || (*operation->staging && !strcmp(operation->staging, operation->quarantine))) goto fail;
    if (napi_has_named_property(env, argv[1], "retainedPreimage", &present) != napi_ok) goto fail;
    if (present) {
        napi_value identity, member;
        if (!*operation->quarantine || napi_get_named_property(env, argv[1], "retainedPreimage", &identity) != napi_ok ||
            napi_get_named_property(env, identity, "deviceId", &member) != napi_ok || !read_unsigned_id(env, member, &operation->namespace_preimage_device) ||
            napi_get_named_property(env, identity, "fileId", &member) != napi_ok || !read_unsigned_id(env, member, &operation->namespace_preimage_inode) ||
            !operation->namespace_preimage_inode) goto fail;
        operation->namespace_preimage_expected = 1;
    }
    size_t count = 1; for (const char *part = operation->path; *part; part++) if (*part == '/') count++;
    operation->parents = malloc(count * sizeof(int)); operation->parent_ids = calloc(count, sizeof(struct stat)); operation->components = calloc(count, sizeof(char *));
    if (!operation->parents || !operation->parent_ids || !operation->components) goto fail;
    for (size_t index = 0; index < count; index++) operation->parents[index] = -1;
    uint32_t parent_length; if (napi_get_array_length(env, parents, &parent_length) != napi_ok || parent_length != count) goto fail;
    char *component = operation->path;
    for (size_t index = 0; index < count; index++) {
        char *end = strchr(component, '/'); if (end) *end = '\0';
        if (!publication_component(component)) goto fail;
        operation->components[index] = component;
        operation->parents[index] = index == 0 ? fcntl(root->fds[root->count - 1], F_DUPFD_CLOEXEC, 0) :
            openat(operation->parents[index - 1], operation->components[index - 1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        operation->parent_count = index + 1;
        if (operation->parents[index] < 0 || fstat(operation->parents[index], &operation->parent_ids[index]) < 0 ||
            !S_ISDIR(operation->parent_ids[index].st_mode) || operation->parent_ids[index].st_dev != lock->root.st_dev ||
            napi_get_element(env, parents, (uint32_t)index, &value) != napi_ok || !publication_expected_parent(env, value, &operation->parent_ids[index])) goto fail;
        if (!end) break;
        component = end + 1;
    }
    operation->arena_parent_fd = openat(lock->runtime_fd, "publications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (operation->arena_parent_fd < 0 || fstat(operation->arena_parent_fd, &operation->arena_parent_id) < 0 ||
        !private_directory(&operation->arena_parent_id) || operation->arena_parent_id.st_dev != lock->root.st_dev ||
        !publication_expected_parent(env, parent_identity, &operation->arena_parent_id)) goto fail;
    struct stat named;
    if (fstatat(operation->arena_parent_fd, operation->arena_name, &named, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!private_directory(&named) || !publication_expected_parent(env, arena_identity, &named)) goto fail;
        operation->arena_fd = openat(operation->arena_parent_fd, operation->arena_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (operation->arena_fd < 0 || fstat(operation->arena_fd, &operation->arena_id) < 0 || !source_path_metadata_same(&named, &operation->arena_id)) goto fail;
    } else if (errno != ENOENT) goto fail;
    const int parent = operation->parents[count - 1]; const char *name = operation->components[count - 1];
    if (!operation->deleting) {
        operation->stage_fd = operation->desired_link ? publication_open_link(parent, name) :
            openat(parent, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC | (operation->desired_directory ? O_DIRECTORY : 0));
        if (operation->stage_fd < 0 || fstat(operation->stage_fd, &operation->stage_id) < 0 || operation->stage_id.st_uid != geteuid() ||
            napi_get_named_property(env, argv[1], "destinationIdentity", &destination_identity) != napi_ok ||
            !publication_expected_identity(env, destination_identity, &operation->stage_id) ||
            (!operation->desired_directory && operation->stage_id.st_size != operation->desired_size)) goto fail;
        operation->destination_id = operation->stage_id; operation->destination_ready = 1;
    }
    if (!publication_namespace_held(operation) || !publication_namespace_destination_held(operation)) goto fail;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, publication_namespace_assert, NULL, NULL, NULL, napi_default, NULL},
        {"observe", NULL, publication_namespace_observe, NULL, NULL, NULL, napi_default, NULL},
        {"readDestinationChunk", NULL, publication_namespace_read, NULL, NULL, NULL, napi_default, NULL},
        {"retireNamespace", NULL, publication_namespace_retire, NULL, NULL, NULL, napi_default, NULL},
        {"assertNamespaceRetired", NULL, publication_namespace_retired, NULL, NULL, NULL, napi_default, NULL},
        {"readRetirementDiagnostic", NULL, publication_namespace_read_retirement_diagnostic, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, publication_namespace_release, NULL, NULL, NULL, napi_default, NULL}
    };
    napi_value result;
    if (napi_create_reference(env, self, 1, &operation->lock_ref) != napi_ok || napi_create_reference(env, argv[0], 1, &operation->root_ref) != napi_ok ||
        napi_create_object(env, &result) != napi_ok || napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &publication_namespace_tag) != napi_ok || napi_wrap(env, result, operation, publication_finalize, NULL, NULL) != napi_ok) goto fail;
    operation->next = lock->publication_operations; lock->publication_operations = operation; return result;
fail:
    publication_close(operation); publication_free(env, operation);
    if (lock->publication_retirement_error) return publication_retirement_error(env);
    return native_error(env, error);
}
