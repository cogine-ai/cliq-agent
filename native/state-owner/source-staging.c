/* A source inspection owns a fixed staging reservation, not a fictional Run
 * generation. No writer, path override or execution descriptor is exported. */
typedef struct staging_cleanup_frame {
    DIR *directory;
    struct stat identity;
    char name[NAME_MAX + 1];
    size_t path_length;
    struct staging_cleanup_frame *parent;
} staging_cleanup_frame;
struct source_staging {
    state_lock *lock;
    napi_ref lock_ref;
    int parent_fd, fd, closed, absent;
    struct stat parent, identity;
    char name[44];
    int cleanup_parent_fd;
    staging_cleanup_frame *cleanup;
    source_staging *next;
};
static const napi_type_tag source_staging_tag = {0xc1a78a40c3a78ff1ULL, 0x8b534c0f2a74d9e5ULL};
static napi_value staging_retirement_failure(napi_env env) {
    napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "exact source staging retirement did not complete"); return NULL;
}
static void staging_close_fd(source_staging *staging, int *slot) {
    const int fd = *slot; *slot = -1;
    if (fd >= 0 && close(fd) < 0) staging->lock->source_retirement_error = errno;
}
static void staging_close_cleanup(source_staging *staging) {
    while (staging->cleanup) {
        staging_cleanup_frame *frame = staging->cleanup; staging->cleanup = frame->parent;
        if (closedir(frame->directory) < 0) staging->lock->source_retirement_error = errno;
        free(frame);
    }
    staging_close_fd(staging, &staging->cleanup_parent_fd);
}
static int close_source_staging(source_staging *staging) {
    staging->closed = 1;
    staging_close_cleanup(staging);
    staging_close_fd(staging, &staging->fd);
    staging_close_fd(staging, &staging->parent_fd);
    return staging->lock->source_retirement_error;
}
static int close_lock_source_stagings(state_lock *lock) {
    for (source_staging *staging = lock->source_stagings; staging; staging = staging->next) close_source_staging(staging);
    return lock->source_retirement_error;
}
static void finalize_source_staging(napi_env env, void *data, void *hint) {
    (void)hint; source_staging *staging = data; state_lock *lock = staging->lock;
    close_source_staging(staging);
    source_staging **link = &lock->source_stagings;
    while (*link && *link != staging) link = &(*link)->next;
    if (*link) *link = staging->next;
    napi_ref ref = staging->lock_ref; free(staging);
    free_lock_if_done(lock);
    if (ref) napi_delete_reference(env, ref);
}
static source_staging *unwrap_source_staging(napi_env env, napi_callback_info info) {
    napi_value self; bool matches = false; source_staging *staging = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &source_staging_tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, self, (void **)&staging) != napi_ok || !staging) {
        native_error(env, "invalid opaque source staging handle"); return NULL;
    }
    return staging;
}
static int staging_parent_held(source_staging *staging, int fd) {
    struct stat opened, named;
    return lock_is_held(staging->lock) && fstat(fd, &opened) == 0 && private_directory(&opened) &&
        opened.st_dev == staging->lock->root.st_dev && same_inode(&opened, &staging->parent) &&
        fstatat(staging->lock->runtime_fd, "source-inspections", &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        private_directory(&named) && same_inode(&opened, &named);
}
static int staging_identity_same(source_staging *staging, const struct stat *observed) {
    return private_directory(observed) && same_inode(observed, &staging->identity) &&
        observed->st_dev == staging->lock->root.st_dev && observed->st_uid == staging->identity.st_uid;
}
static int staging_held(source_staging *staging) {
    struct stat opened, named;
    if (staging->closed || staging->lock->source_retirement_error || staging->parent_fd < 0 ||
        !staging_parent_held(staging, staging->parent_fd)) return 0;
    if (staging->absent) return fstatat(staging->parent_fd, staging->name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    return staging->fd >= 0 && fstat(staging->fd, &opened) == 0 && staging_identity_same(staging, &opened) &&
        fstatat(staging->parent_fd, staging->name, &named, AT_SYMLINK_NOFOLLOW) == 0 && staging_identity_same(staging, &named);
}
static napi_value source_staging_assert(napi_env env, napi_callback_info info) {
    source_staging *staging = unwrap_source_staging(env, info); napi_value value;
    if (!staging) return NULL;
    if (!staging_held(staging)) return native_error(env, "source staging identity changed or closed");
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_staging_close(napi_env env, napi_callback_info info) {
    source_staging *staging = unwrap_source_staging(env, info); napi_value value;
    if (!staging) return NULL;
    if (close_source_staging(staging)) return staging_retirement_failure(env);
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_staging_assert_retired(napi_env env, napi_callback_info info) {
    source_staging *staging = unwrap_source_staging(env, info); napi_value value;
    if (!staging) return NULL;
    if (close_source_staging(staging) || !lock_is_held(staging->lock)) return staging_retirement_failure(env);
    int parent = openat(staging->lock->runtime_fd, "source-inspections", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int valid = parent >= 0 && staging_parent_held(staging, parent);
    struct stat named;
    if (valid) valid = fstatat(parent, staging->name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        sync_directory(parent) && staging_parent_held(staging, parent) &&
        fstatat(parent, staging->name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    if (parent >= 0 && close(parent) < 0) staging->lock->source_retirement_error = errno;
    if (!valid || staging->lock->source_retirement_error) return staging_retirement_failure(env);
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static int staging_cleanup_same(const struct stat *before, const struct stat *after) {
    return S_ISDIR(after->st_mode) && same_inode(before, after) && before->st_uid == after->st_uid &&
        before->st_gid == after->st_gid && before->st_mode == after->st_mode;
}
static int staging_cleanup_held_from(source_staging *staging, staging_cleanup_frame *first) {
    if (staging->lock->source_retirement_error || !staging_parent_held(staging, staging->cleanup_parent_fd)) return 0;
    for (staging_cleanup_frame *frame = first; frame; frame = frame->parent) {
        const int parent = frame->parent ? dirfd(frame->parent->directory) : staging->cleanup_parent_fd;
        struct stat opened, named;
        if (fstat(dirfd(frame->directory), &opened) < 0 || !staging_cleanup_same(&frame->identity, &opened) ||
            opened.st_dev != staging->lock->root.st_dev || opened.st_uid != geteuid() ||
            fstatat(parent, frame->name, &named, AT_SYMLINK_NOFOLLOW) < 0 || !staging_cleanup_same(&opened, &named)) return 0;
    }
    return 1;
}
static int staging_cleanup_held(source_staging *staging) { return staging_cleanup_held_from(staging, staging->cleanup); }
static int staging_cleanup_push(source_staging *staging, int parent, const char *name,
                                const struct stat *identity, size_t path_length) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat opened;
    if (fd < 0 || fstat(fd, &opened) < 0 || !staging_cleanup_same(identity, &opened)) {
        if (fd >= 0 && close(fd) < 0) staging->lock->source_retirement_error = errno;
        return 0;
    }
    staging_cleanup_frame *frame = calloc(1, sizeof(*frame));
    if (!frame) { if (close(fd) < 0) staging->lock->source_retirement_error = errno; return 0; }
    frame->directory = fdopendir(fd);
    if (!frame->directory) {
        if (close(fd) < 0) staging->lock->source_retirement_error = errno;
        free(frame); return 0;
    }
    frame->identity = opened; frame->parent = staging->cleanup; frame->path_length = path_length;
    memcpy(frame->name, name, strlen(name) + 1); staging->cleanup = frame;
    return staging_cleanup_held(staging);
}
/* One exact entry per call. The trusted owning operation yields between calls
 * and joins this cursor; no recursive stack or generic delete path escapes. */
static napi_value source_staging_retire_step(napi_env env, napi_callback_info info) {
    source_staging *staging = unwrap_source_staging(env, info); napi_value value;
    if (!staging) return NULL;
    if (!staging->cleanup) {
        if (close_source_staging(staging) || !lock_is_held(staging->lock)) goto failed;
        staging->cleanup_parent_fd = openat(staging->lock->runtime_fd, "source-inspections", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (staging->cleanup_parent_fd < 0 || !staging_parent_held(staging, staging->cleanup_parent_fd)) goto failed;
        struct stat named;
        if (fstatat(staging->cleanup_parent_fd, staging->name, &named, AT_SYMLINK_NOFOLLOW) < 0) {
            if (errno != ENOENT) goto failed;
            goto complete;
        }
        if (!staging_identity_same(staging, &named) ||
            !staging_cleanup_push(staging, staging->cleanup_parent_fd, staging->name, &named, 0)) goto failed;
    }
    if (!staging_cleanup_held(staging)) goto failed;
    staging_cleanup_frame *frame = staging->cleanup;
    errno = 0; struct dirent *entry = readdir(frame->directory);
    if (!entry) {
        if (errno || !staging_cleanup_held(staging)) goto failed;
        const int parent = frame->parent ? dirfd(frame->parent->directory) : staging->cleanup_parent_fd;
        char name[NAME_MAX + 1]; memcpy(name, frame->name, strlen(frame->name) + 1);
        /* Keep authority on the original inode across rmdir: named absence
         * alone could merely mean that a raced-in replacement was removed. */
#ifdef __APPLE__
        /* APFS caches directory nlink after unlink. OS-held path observations
         * discriminate a renamed original; they are never reopened as paths. */
        char parent_path[PATH_MAX], expected_path[PATH_MAX], observed_path[PATH_MAX];
        if (fcntl(parent, F_GETPATH, parent_path) < 0) goto failed;
        const int length = snprintf(expected_path, sizeof(expected_path), "%s/%s", parent_path, name);
        if (length < 0 || (size_t)length >= sizeof(expected_path) ||
            fcntl(dirfd(frame->directory), F_GETPATH, observed_path) < 0 || strcmp(observed_path, expected_path)) goto failed;
#endif
        struct stat unlinked;
        if (unlinkat(parent, name, AT_REMOVEDIR) < 0 || fstat(dirfd(frame->directory), &unlinked) < 0 ||
            !staging_cleanup_same(&frame->identity, &unlinked)) goto failed;
#ifdef __APPLE__
        if (fcntl(dirfd(frame->directory), F_GETPATH, observed_path) < 0 || strcmp(observed_path, expected_path) ||
            fcntl(parent, F_GETPATH, observed_path) < 0 || strcmp(observed_path, parent_path)) goto failed;
#else
        if (unlinked.st_nlink != 0) goto failed;
#endif
        struct stat named;
        if (fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT ||
            !staging_cleanup_held_from(staging, frame->parent)) goto failed;
        staging->cleanup = frame->parent;
        const int closed = closedir(frame->directory); free(frame);
        if (closed < 0) { staging->lock->source_retirement_error = errno; goto failed; }
        if (!sync_directory(parent)) goto failed;
        if (!staging->cleanup) goto complete;
    } else if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
        const int parent = dirfd(frame->directory); struct stat named;
        if (fstatat(parent, entry->d_name, &named, AT_SYMLINK_NOFOLLOW) < 0 || !staging_cleanup_held(staging) ||
            named.st_dev != staging->lock->root.st_dev || named.st_uid != geteuid()) goto failed;
        if (S_ISDIR(named.st_mode)) {
            const size_t length = frame->path_length + strlen(entry->d_name) + 1;
            if (length > 4096 || !staging_cleanup_push(staging, parent, entry->d_name, &named, length)) goto failed;
        } else if (unlinkat(parent, entry->d_name, 0) < 0 || !sync_directory(parent)) goto failed;
    }
    return napi_get_boolean(env, false, &value) == napi_ok ? value : NULL;
complete:
    {
        struct stat named;
        if (!sync_directory(staging->cleanup_parent_fd) || !staging_parent_held(staging, staging->cleanup_parent_fd) ||
            fstatat(staging->cleanup_parent_fd, staging->name, &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) goto failed;
        staging_close_cleanup(staging);
        if (staging->lock->source_retirement_error) goto failed;
        return napi_get_boolean(env, true, &value) == napi_ok ? value : NULL;
    }
failed:
    if (!staging->lock->source_retirement_error) staging->lock->source_retirement_error = errno ? errno : EIO;
    staging_close_cleanup(staging);
    return staging_retirement_failure(env);
}
static napi_value source_staging_open(napi_env env, napi_callback_info info, int create) {
    state_lock *lock = unwrap_lock(env, info); napi_value argv[3], self, result;
    size_t argc = create ? 1 : 3;
    if (!lock) return NULL;
    source_staging *staging = calloc(1, sizeof(*staging));
    if (!staging) return native_error(env, "source staging allocation failed");
    staging->lock = lock; staging->fd = staging->parent_fd = staging->cleanup_parent_fd = -1;
    const char *error = "source staging requires the fixed derived id and held StateOwner";
    unsigned long long device = 0, file = 0;
    if (napi_get_cb_info(env, info, &argc, argv, &self, NULL) != napi_ok || argc != (create ? 1u : 3u) ||
        !read_component(env, argv[0], staging->name, sizeof(staging->name), 43) || !lock_is_held(lock) ||
        lock->source_retirement_error || (!create && (!read_unsigned_id(env, argv[1], &device) || !read_unsigned_id(env, argv[2], &file)))) goto fail;
    error = "source inspection parent must be a same-device private no-follow directory";
    if (create && mkdirat(lock->runtime_fd, "source-inspections", 0700) < 0 && errno != EEXIST) goto fail;
    staging->parent_fd = openat(lock->runtime_fd, "source-inspections", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (staging->parent_fd < 0 || fstat(staging->parent_fd, &staging->parent) < 0 ||
        !private_directory(&staging->parent) || staging->parent.st_dev != lock->root.st_dev ||
        !staging_parent_held(staging, staging->parent_fd)) goto fail;
    error = "source inspection staging reservation must be absent, never overwritten";
    if (create && mkdirat(staging->parent_fd, staging->name, 0700) < 0) goto fail;
    staging->fd = openat(staging->parent_fd, staging->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (!create && staging->fd < 0 && errno == ENOENT) {
        staging->absent = 1;
        staging->identity.st_dev = (dev_t)device; staging->identity.st_ino = (ino_t)file;
        staging->identity.st_uid = geteuid(); staging->identity.st_mode = S_IFDIR | 0700;
    } else {
        error = "source inspection staging identity does not match its actual reservation";
        if (staging->fd < 0 || fstat(staging->fd, &staging->identity) < 0 || !private_directory(&staging->identity) ||
            staging->identity.st_dev != lock->root.st_dev) goto fail;
#ifdef __APPLE__
        unsigned long long observed_device = (uint32_t)staging->identity.st_dev;
#else
        unsigned long long observed_device = staging->identity.st_dev;
#endif
        if (!create && (observed_device != device || staging->identity.st_ino != file)) goto fail;
    }
    if (!staging_held(staging) || (create && (!sync_directory(staging->fd) || !sync_directory(staging->parent_fd) ||
        !sync_directory(lock->runtime_fd)))) goto fail;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, source_staging_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, source_staging_close, NULL, NULL, NULL, napi_default, NULL},
        {"retireStep", NULL, source_staging_retire_step, NULL, NULL, NULL, napi_default, NULL},
        {"assertRetired", NULL, source_staging_assert_retired, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_reference(env, self, 1, &staging->lock_ref) != napi_ok || napi_create_object(env, &result) != napi_ok ||
        !identity_member(env, result, "identity", &staging->identity) ||
        napi_define_properties(env, result, 4, methods) != napi_ok ||
        napi_type_tag_object(env, result, &source_staging_tag) != napi_ok ||
        napi_wrap(env, result, staging, finalize_source_staging, NULL, NULL) != napi_ok) goto fail;
    staging->next = lock->source_stagings; lock->source_stagings = staging;
    napi_object_freeze(env, result); return result;
fail:
    close_source_staging(staging);
    if (staging->lock_ref) napi_delete_reference(env, staging->lock_ref);
    free(staging);
    return lock->source_retirement_error ? staging_retirement_failure(env) : native_error(env, error);
}
static napi_value create_source_staging(napi_env env, napi_callback_info info) { return source_staging_open(env, info, 1); }
static napi_value open_source_staging(napi_env env, napi_callback_info info) { return source_staging_open(env, info, 0); }
