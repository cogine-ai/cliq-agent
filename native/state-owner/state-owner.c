#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libproc.h>
#elif defined(__linux__)
#include <linux/magic.h>
#include <sys/vfs.h>
#endif

static napi_value native_error(napi_env env, const char *message) {
    napi_throw_error(env, "ERR_CLIQ_STATE_OWNER_NATIVE", message);
    return NULL;
}

typedef struct {
    int root_fd, runtime_fd, lock_fd;
    struct stat root, runtime, lock;
    char *path;
} state_lock;

typedef struct {
    int root_fd, parent_fd, file_fd;
    state_lock *lock;
    napi_ref lock_ref;
    char *workspace_path, *relative_path;
    struct stat root, parent, file;
    off_t consumed;
} source_file;

static const napi_type_tag lock_tag = {0x3d641bc705864cfbULL, 0xab53499f3ee988c4ULL};
static const napi_type_tag source_file_tag = {0x61a27c90123f446eULL, 0xb5d23e4704a5917cULL};

static napi_value assert_prior_process_dead(napi_env env, napi_callback_info info);
static napi_value move_generation(napi_env env, napi_callback_info info);
static napi_value inspect_workspace_identity(napi_env env, napi_callback_info info);
static napi_value open_workspace_source_file(napi_env env, napi_callback_info info);
static napi_value open_workspace_git_index(napi_env env, napi_callback_info info);
static napi_value list_workspace_source_directory(napi_env env, napi_callback_info info);
static napi_value read_workspace_source_symlink(napi_env env, napi_callback_info info);
static int literal_child_present(int parent, const char *literal);

/* Reopening a path is only a locator check. Authority stays on these held
 * descriptors, and flock is released solely by closing the lock descriptor. */
static void close_lock(state_lock *lock) {
    if (lock->lock_fd >= 0) close(lock->lock_fd);
    if (lock->runtime_fd >= 0) close(lock->runtime_fd);
    if (lock->root_fd >= 0) close(lock->root_fd);
    lock->root_fd = lock->runtime_fd = lock->lock_fd = -1;
}

static void finalize_lock(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    state_lock *lock = data;
    close_lock(lock);
    free(lock->path);
    free(lock);
}

static int same_inode(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int private_directory(const struct stat *info) {
    return S_ISDIR(info->st_mode) && info->st_uid == geteuid() && (info->st_mode & 07777) == 0700;
}

static int private_lock_file(const struct stat *info) {
    return S_ISREG(info->st_mode) && info->st_uid == geteuid() &&
           (info->st_mode & 07777) == 0600 && info->st_nlink == 1;
}

/* No pathname component may be a symlink, including ancestors of StateRoot. */
static int open_root_impl(const char *path, int require_literal) {
    if (path[0] != '/' || path[1] == '\0') { errno = EINVAL; return -1; }
    int current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) return -1;
    const char *part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t size = end ? (size_t)(end - part) : strlen(part);
        if (size == 0 || size > NAME_MAX || (size == 1 && part[0] == '.') ||
            (size == 2 && part[0] == '.' && part[1] == '.')) {
            close(current); errno = EINVAL; return -1;
        }
        char name[NAME_MAX + 1];
        memcpy(name, part, size); name[size] = '\0';
        if (require_literal && literal_child_present(current, name) != 1) {
            close(current); errno = ENOENT; return -1;
        }
        int next = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int failure = errno;
        close(current);
        if (next < 0) { errno = failure; return -1; }
        current = next;
        if (!end) break;
        part = end + 1;
        if (*part == '\0') { close(current); errno = EINVAL; return -1; }
    }
    return current;
}

static int open_root(const char *path) { return open_root_impl(path, 0); }
static int open_literal_root(const char *path) { return open_root_impl(path, 1); }

static int lock_is_held(state_lock *lock) {
    if (lock->lock_fd < 0) return 0;
    struct stat root, runtime, file, named;
    int reopened = open_root(lock->path);
    if (reopened < 0) return 0;
    int valid = fstat(reopened, &named) == 0 && same_inode(&named, &lock->root);
    close(reopened);
    return valid && fstat(lock->root_fd, &root) == 0 && private_directory(&root) && same_inode(&root, &lock->root) &&
        fstat(lock->runtime_fd, &runtime) == 0 && private_directory(&runtime) && same_inode(&runtime, &lock->runtime) &&
        fstatat(lock->root_fd, "runtime", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&named, &runtime) &&
        fstat(lock->lock_fd, &file) == 0 && private_lock_file(&file) && same_inode(&file, &lock->lock) &&
        fstatat(lock->runtime_fd, "state-owner.lock", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&named, &file);
}

static state_lock *unwrap_lock(napi_env env, napi_callback_info info) {
    napi_value self;
    bool matches = false;
    state_lock *lock = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &lock_tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, self, (void **)&lock) != napi_ok || !lock) {
        native_error(env, "invalid StateOwner lock handle");
        return NULL;
    }
    return lock;
}

static napi_value assert_held(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    if (!lock_is_held(lock)) return native_error(env, "StateOwner root/runtime/lock descriptor identity changed or closed");
    napi_value result;
    if (napi_get_undefined(env, &result) != napi_ok) return NULL;
    return result;
}

static napi_value release_lock(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    close_lock(lock);
    napi_value result;
    if (napi_get_undefined(env, &result) != napi_ok) return NULL;
    return result;
}

static int decimal_member(napi_env env, napi_value object, const char *key, unsigned long long number) {
    char text[32];
    snprintf(text, sizeof(text), "%llu", number);
    napi_value value;
    return napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &value) == napi_ok &&
           napi_set_named_property(env, object, key, value) == napi_ok;
}

static int identity_member(napi_env env, napi_value object, const char *key, const struct stat *info) {
    napi_value value, uid;
#ifdef __APPLE__
    unsigned long long device = (uint32_t)info->st_dev;
#else
    unsigned long long device = info->st_dev;
#endif
    return napi_create_object(env, &value) == napi_ok &&
        decimal_member(env, value, "deviceId", device) && decimal_member(env, value, "fileId", info->st_ino) &&
        napi_create_uint32(env, info->st_uid, &uid) == napi_ok && napi_set_named_property(env, value, "ownerUid", uid) == napi_ok &&
        napi_object_freeze(env, value) == napi_ok && napi_set_named_property(env, object, key, value) == napi_ok;
}

static napi_value acquire_lock(napi_env env, napi_callback_info info) {
    size_t argc = 2, length;
    napi_value argv[2];
    bool create;
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 2 ||
        napi_get_value_string_utf8(env, argv[0], NULL, 0, &length) != napi_ok || length == 0 || length >= PATH_MAX ||
        napi_get_value_bool(env, argv[1], &create) != napi_ok) return native_error(env, "invalid StateOwner lock input");
    state_lock *lock = calloc(1, sizeof(*lock));
    if (!lock) return native_error(env, "StateOwner lock allocation failed");
    lock->root_fd = lock->runtime_fd = lock->lock_fd = -1;
    lock->path = malloc(length + 1);
    const char *error = "cannot open StateOwner root without following symlinks";
    if (!lock->path || napi_get_value_string_utf8(env, argv[0], lock->path, length + 1, &length) != napi_ok ||
        strlen(lock->path) != length) goto fail;
    lock->root_fd = open_root(lock->path);
    if (lock->root_fd < 0 || fstat(lock->root_fd, &lock->root) < 0 || !private_directory(&lock->root)) goto fail;
    error = "StateOwner runtime must be an existing private 0700 directory";
    if (create && mkdirat(lock->root_fd, "runtime", 0700) < 0 && errno != EEXIST) goto fail;
    lock->runtime_fd = openat(lock->root_fd, "runtime", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (lock->runtime_fd < 0 || fstat(lock->runtime_fd, &lock->runtime) < 0 || !private_directory(&lock->runtime)) goto fail;
    error = "StateOwner lock must be an existing private 0600 regular file with link count 1";
    int flags = O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;
    /* Separate exclusive creation from opening the winning inode. Concurrent
     * plain O_CREAT opens can fail with ENOENT on macOS during initial creation. */
    lock->lock_fd = openat(lock->runtime_fd, "state-owner.lock", flags | (create ? O_CREAT | O_EXCL : 0), 0600);
    if (create && lock->lock_fd < 0 && errno == EEXIST) {
        lock->lock_fd = openat(lock->runtime_fd, "state-owner.lock", flags);
    }
    if (lock->lock_fd < 0 || fstat(lock->lock_fd, &lock->lock) < 0 || !private_lock_file(&lock->lock)) goto fail;
    int status;
    do { status = flock(lock->lock_fd, LOCK_EX | LOCK_NB); } while (status < 0 && errno == EINTR);
    if (status < 0) {
        error = (errno == EWOULDBLOCK || errno == EAGAIN) ? "StateOwner OS lock is already held" : "StateOwner OS lock acquisition failed";
        goto fail;
    }
    error = "StateOwner descriptor identity changed during acquisition";
    if (!lock_is_held(lock) || fsync(lock->lock_fd) < 0 || fsync(lock->runtime_fd) < 0 || fsync(lock->root_fd) < 0) goto fail;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, assert_held, NULL, NULL, NULL, napi_default, NULL},
        {"assertPriorProcessDead", NULL, assert_prior_process_dead, NULL, NULL, NULL, napi_default, NULL},
        {"moveGeneration", NULL, move_generation, NULL, NULL, NULL, napi_default, NULL},
        {"inspectWorkspaceIdentity", NULL, inspect_workspace_identity, NULL, NULL, NULL, napi_default, NULL},
        {"openWorkspaceSourceFile", NULL, open_workspace_source_file, NULL, NULL, NULL, napi_default, NULL},
        {"openWorkspaceGitIndex", NULL, open_workspace_git_index, NULL, NULL, NULL, napi_default, NULL},
        {"listWorkspaceSourceDirectory", NULL, list_workspace_source_directory, NULL, NULL, NULL, napi_default, NULL},
        {"readWorkspaceSourceSymlink", NULL, read_workspace_source_symlink, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, release_lock, NULL, NULL, NULL, napi_default, NULL}
    };
    error = "StateOwner lock handle creation failed";
    if (napi_create_object(env, &result) != napi_ok ||
        !identity_member(env, result, "root", &lock->root) || !identity_member(env, result, "runtime", &lock->runtime) ||
        !identity_member(env, result, "lock", &lock->lock) ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &lock_tag) != napi_ok ||
        napi_wrap(env, result, lock, finalize_lock, NULL, NULL) != napi_ok) goto fail;
    return result;
fail:
    finalize_lock(env, lock, NULL);
    return native_error(env, error);
}

static int read_component(napi_env env, napi_value value, char *text, size_t capacity, size_t exact_length) {
    size_t length;
    if (napi_get_value_string_utf8(env, value, NULL, 0, &length) != napi_ok || length == 0 || length >= capacity ||
        (exact_length && length != exact_length) ||
        napi_get_value_string_utf8(env, value, text, capacity, &length) != napi_ok) return 0;
    for (size_t i = 0; i < length; i++) {
        char c = text[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return 0;
    }
    return 1;
}

static int read_unsigned_id(napi_env env, napi_value value, unsigned long long *number) {
    char text[21], canonical[21], *end;
    size_t length;
    if (napi_get_value_string_utf8(env, value, NULL, 0, &length) != napi_ok || length == 0 || length >= sizeof(text) ||
        napi_get_value_string_utf8(env, value, text, sizeof(text), &length) != napi_ok || strlen(text) != length ||
        text[0] < '0' || text[0] > '9') return 0;
    errno = 0;
    *number = strtoull(text, &end, 10);
    if (errno || *end) return 0;
    snprintf(canonical, sizeof(canonical), "%llu", *number);
    return strcmp(text, canonical) == 0;
}

static int sync_directory(int fd) {
    int status;
    do { status = fsync(fd); } while (status < 0 && errno == EINTR);
    return status == 0;
}

static int open_private_child(int parent, const char *name, int create, struct stat *identity, dev_t device) {
    if (create && mkdirat(parent, name, 0700) < 0 && errno != EEXIST) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, identity) < 0 || !private_directory(identity) || identity->st_dev != device) { close(fd); return -1; }
    return fd;
}

static int generation_identity(const struct stat *info, unsigned long long device, unsigned long long file) {
#ifdef __APPLE__
    int protected = private_lock_file(info); /* private, single-link 0600 backing image */
    unsigned long long observed_device = (uint32_t)info->st_dev;
#else
    /* Directory link counts include child '..' entries; they are not file
     * hardlink counts and are not immutable generation identity. */
    int protected = private_directory(info);
    unsigned long long observed_device = info->st_dev;
#endif
    return protected && observed_device == device && (unsigned long long)info->st_ino == file;
}

/* 0 is positive ENOENT only; wrong type/identity and other I/O errors fail. */
static int generation_at(int parent, const char *name, unsigned long long device, unsigned long long file, struct stat *identity) {
    if (fstatat(parent, name, identity, AT_SYMLINK_NOFOLLOW) < 0) return errno == ENOENT ? 0 : -1;
    return generation_identity(identity, device, file) ? 1 : -1;
}

static int quarantine_parents_valid(state_lock *lock, int parents[5], struct stat identities[5], const char *names[5]) {
    if (!lock_is_held(lock)) return 0;
    for (int i = 0; i < 5; i++) {
        struct stat held, named;
        int parent = (i == 0 || i == 3) ? lock->root_fd : parents[i - 1];
        if (fstat(parents[i], &held) < 0 || !private_directory(&held) || !same_inode(&held, &identities[i]) ||
            fstatat(parent, names[i], &named, AT_SYMLINK_NOFOLLOW) < 0 || !same_inode(&named, &held)) return 0;
    }
    return 1;
}

/* A fixed descriptor-relative relocation, never execution/death authority.
 * No directory scan, overwrite, copy/unlink fallback, rollback or deletion. */
static napi_value move_generation(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    if (!lock_is_held(lock)) return native_error(env, "StateOwner root/runtime/lock descriptor identity changed or closed");
    size_t argc = 6;
    napi_value argv[6];
    char run[129], generation[44], target[44], source[48];
    unsigned long long device, file;
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 5 ||
        !read_component(env, argv[0], run, sizeof(run), 0) || !read_component(env, argv[1], generation, sizeof(generation), 43) ||
        !read_component(env, argv[2], target, sizeof(target), 43) ||
        !read_unsigned_id(env, argv[3], &device) || !read_unsigned_id(env, argv[4], &file)) {
        return native_error(env, "invalid generation quarantine identity");
    }
#ifdef __APPLE__
    snprintf(source, sizeof(source), "%s.img", generation);
#else
    snprintf(source, sizeof(source), "%s", generation);
#endif
    int parents[5] = {-1, -1, -1, -1, -1}, generation_fd = -1;
    struct stat identities[5], original, destination, opened;
    const char *names[5] = {"runs", run, "generations", "quarantine", "workspace-generations"};
    const char *error = "generation quarantine requires private same-device no-follow parent descriptors";
    for (int i = 0; i < 3; i++) {
        parents[i] = open_private_child(i == 0 ? lock->root_fd : parents[i - 1], names[i], 0, &identities[i], lock->root.st_dev);
        if (parents[i] < 0) goto done;
    }
    error = "generation quarantine source identity differs or is unreadable";
    int source_exists = generation_at(parents[2], source, device, file, &original);
    if (source_exists < 0) goto done;
    error = "generation quarantine target requires private same-device no-follow parent descriptors";
    for (int i = 3; i < 5; i++) {
        parents[i] = open_private_child(i == 3 ? lock->root_fd : parents[i - 1], names[i], source_exists, &identities[i], lock->root.st_dev);
        if (parents[i] < 0) goto done;
    }
    error = "generation quarantine requires exactly one original or exact target; refusing conflict or identity drift";
    int target_exists = generation_at(parents[4], target, device, file, &destination);
    if (target_exists < 0 || source_exists + target_exists != 1) goto done;
    int flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;
#ifndef __APPLE__
    flags |= O_DIRECTORY;
#endif
    generation_fd = openat(source_exists ? parents[2] : parents[4], source_exists ? source : target, flags);
    if (generation_fd < 0 || fstat(generation_fd, &opened) < 0 || !generation_identity(&opened, device, file) ||
        opened.st_dev != lock->root.st_dev) goto done;
    error = "generation quarantine parent or source descriptor identity changed";
    if (!quarantine_parents_valid(lock, parents, identities, names) ||
        generation_at(parents[2], source, device, file, &original) != source_exists ||
        generation_at(parents[4], target, device, file, &destination) != target_exists) goto done;
    /* Persist newly created quarantine ancestors before moving. Retry also
     * repeats these syncs: an earlier crash may have interrupted any one. */
    error = "generation quarantine parent fsync failed; retry the exact locator pair";
    if (!sync_directory(lock->root_fd)) goto done;
    for (int i = 0; i < 5; i++) if (!sync_directory(parents[i])) goto done;
    error = "generation quarantine parent or source descriptor identity changed";
    if (!quarantine_parents_valid(lock, parents, identities, names) ||
        generation_at(parents[2], source, device, file, &original) != source_exists ||
        generation_at(parents[4], target, device, file, &destination) != target_exists) goto done;
    if (source_exists) {
        error = "generation quarantine no-replace rename failed; no overwrite or copy fallback is allowed";
#ifdef __APPLE__
        if (renameatx_np(parents[2], source, parents[4], target, RENAME_EXCL) < 0) goto done;
#else
        if (renameat2(parents[2], source, parents[4], target, RENAME_NOREPLACE) < 0) goto done;
#endif
    }
    error = "generation quarantine parent fsync failed; retry the exact locator pair";
    if (!sync_directory(parents[2]) || !sync_directory(parents[4])) goto done;
    error = "generation quarantine post-move descriptor identity or original absence changed";
    if (!quarantine_parents_valid(lock, parents, identities, names) || fstat(generation_fd, &opened) < 0 ||
        !generation_identity(&opened, device, file) ||
        generation_at(parents[2], source, device, file, &original) != 0 ||
        generation_at(parents[4], target, device, file, &destination) != 1) goto done;
    error = NULL;
done:
    if (generation_fd >= 0) close(generation_fd);
    for (int i = 4; i >= 0; i--) if (parents[i] >= 0) close(parents[i]);
    if (error) return native_error(env, error);
    napi_value result, identity;
    if (napi_create_object(env, &result) != napi_ok || !identity_member(env, result, "identity", &destination) ||
        napi_get_named_property(env, result, "identity", &identity) != napi_ok) return NULL;
    return identity;
}

static int same_file_observation(const struct stat *left, const struct stat *right) {
    if (!same_inode(left, right) || left->st_uid != right->st_uid || left->st_gid != right->st_gid ||
        left->st_mode != right->st_mode || left->st_nlink != right->st_nlink || left->st_size != right->st_size ||
        left->st_mtime != right->st_mtime || left->st_ctime != right->st_ctime) return 0;
#ifdef __APPLE__
    return left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

/* openat on a case-insensitive volume can resolve ".Git" for literal ".git".
 * Inspect the held parent's actual entry names before accepting that lookup. */
static int literal_child_present(int parent, const char *literal) {
    int scan_fd = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scan_fd < 0) return -1;
    DIR *stream = fdopendir(scan_fd);
    if (!stream) { close(scan_fd); return -1; }
    int found = 0;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, literal) == 0) found = 1;
        errno = 0;
    }
    int read_error = errno;
    closedir(stream);
    return read_error == 0 ? found : -1;
}

/* A read-only Session identity observation. The path locates one root; all
 * Git/config reads then use its held descriptor and reject symlink aliases. */
static napi_value inspect_workspace_identity(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    if (!lock_is_held(lock)) return native_error(env, "StateOwner root/runtime/lock descriptor identity changed or closed");
    size_t argc = 1, length;
    napi_value argv[1], result = NULL, git_value = NULL, config_value = NULL;
    int root_fd = -1, git_fd = -1, config_fd = -1, reopened = -1;
    char *path = NULL, *config_bytes = NULL;
    struct stat root, git, config_before, config_after, named;
    int has_git = 0, has_config = 0;
    int literal_git, literal_config = 0;
    const char *error = "invalid workspace path for descriptor-held identity inspection";
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_string_utf8(env, argv[0], NULL, 0, &length) != napi_ok ||
        length < 2 || length >= PATH_MAX) goto done;
    path = malloc(length + 1);
    if (!path || napi_get_value_string_utf8(env, argv[0], path, length + 1, &length) != napi_ok ||
        strlen(path) != length) goto done;
    error = "workspace root must be a same-user no-follow directory";
    root_fd = open_literal_root(path);
    if (root_fd < 0 || fstat(root_fd, &root) < 0 || !S_ISDIR(root.st_mode) || root.st_uid != geteuid()) goto done;
    error = "workspace .git must be a literal same-user directory on the root device";
    literal_git = literal_child_present(root_fd, ".git");
    if (literal_git < 0) goto done;
    git_fd = openat(root_fd, ".git", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (git_fd < 0) {
        if (errno != ENOENT || literal_git != 0) goto done;
    } else {
        if (literal_git != 1) goto done;
        has_git = 1;
        if (fstat(git_fd, &git) < 0 || !S_ISDIR(git.st_mode) || git.st_uid != root.st_uid ||
            git.st_dev != root.st_dev) goto done;
        error = "workspace .git/config must be a stable same-user regular file of at most 1 MiB";
        literal_config = literal_child_present(git_fd, "config");
        if (literal_config < 0) goto done;
        config_fd = openat(git_fd, "config", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (config_fd < 0) {
            if (errno != ENOENT || literal_config != 0) goto done;
        } else {
            if (literal_config != 1) goto done;
            has_config = 1;
            if (fstat(config_fd, &config_before) < 0 || !S_ISREG(config_before.st_mode) ||
                config_before.st_uid != root.st_uid || config_before.st_dev != root.st_dev ||
                config_before.st_nlink != 1 || config_before.st_size < 0 ||
                config_before.st_size > 1024 * 1024) goto done;
            size_t size = (size_t)config_before.st_size, consumed = 0;
            config_bytes = malloc(size + 1);
            if (!config_bytes) goto done;
            while (consumed < size) {
                ssize_t count = read(config_fd, config_bytes + consumed, size - consumed);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) goto done;
                consumed += (size_t)count;
            }
            char extra;
            ssize_t extra_count;
            do { extra_count = read(config_fd, &extra, 1); } while (extra_count < 0 && errno == EINTR);
            if (extra_count != 0 || fstat(config_fd, &config_after) < 0 ||
                !same_file_observation(&config_before, &config_after) ||
                fstatat(git_fd, "config", &named, AT_SYMLINK_NOFOLLOW) < 0 ||
                !same_file_observation(&config_before, &named)) goto done;
        }
    }
    error = "workspace root or .git identity changed during descriptor-held inspection";
    reopened = open_literal_root(path);
    if (reopened < 0 || fstat(reopened, &named) < 0 || !same_file_observation(&root, &named) ||
        literal_child_present(root_fd, ".git") != has_git ||
        !lock_is_held(lock)) goto done;
    if (has_git) {
        if (fstatat(root_fd, ".git", &named, AT_SYMLINK_NOFOLLOW) < 0 ||
            !same_file_observation(&git, &named) ||
            literal_child_present(git_fd, "config") != has_config) goto done;
        if (!has_config && (fstatat(git_fd, "config", &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)) goto done;
    } else if (fstatat(root_fd, ".git", &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) goto done;
    if (napi_create_object(env, &result) != napi_ok || !identity_member(env, result, "root", &root)) {
        result = NULL; goto done;
    }
    if (has_git) {
        if (napi_create_object(env, &git_value) != napi_ok ||
            !identity_member(env, git_value, "identity", &git)) { result = NULL; goto done; }
        if (has_config) {
            if (napi_create_buffer_copy(env, (size_t)config_before.st_size, config_bytes, NULL, &config_value) != napi_ok ||
                napi_set_named_property(env, git_value, "configBytes", config_value) != napi_ok) { result = NULL; goto done; }
        }
        if (napi_set_named_property(env, result, "git", git_value) != napi_ok) { result = NULL; goto done; }
    }
    error = NULL;
done:
    if (reopened >= 0) close(reopened);
    if (config_fd >= 0) close(config_fd);
    if (git_fd >= 0) close(git_fd);
    if (root_fd >= 0) close(root_fd);
    free(config_bytes);
    free(path);
    return error ? native_error(env, error) : result;
}

static void close_source_file(source_file *file) {
    if (file->file_fd >= 0) close(file->file_fd);
    if (file->parent_fd >= 0) close(file->parent_fd);
    if (file->root_fd >= 0) close(file->root_fd);
    file->file_fd = file->parent_fd = file->root_fd = -1;
}

static void finalize_source_file(napi_env env, void *data, void *hint) {
    (void)hint;
    source_file *file = data;
    close_source_file(file);
    if (file->lock_ref) napi_delete_reference(env, file->lock_ref);
    free(file->workspace_path);
    free(file->relative_path);
    free(file);
}

static source_file *unwrap_source_file(napi_env env, napi_callback_info info) {
    napi_value self;
    bool matches = false;
    source_file *file = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &source_file_tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, self, (void **)&file) != napi_ok || !file) {
        native_error(env, "invalid workspace source file handle");
        return NULL;
    }
    return file;
}

/* The caller may name only a literal, root-relative source leaf. Git metadata
 * is deliberately excluded from this ordinary-source reader. */
static int valid_source_relative_path(const char *path) {
    if (!*path || *path == '/' || strlen(path) >= PATH_MAX || strchr(path, '\\')) return 0;
    const char *part = path;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t size = end ? (size_t)(end - part) : strlen(part);
        if (size == 0 || size > NAME_MAX || (size == 1 && part[0] == '.') ||
            (size == 2 && part[0] == '.' && part[1] == '.') ||
            (size == 4 && part[0] == '.' && (part[1] == 'g' || part[1] == 'G') &&
             (part[2] == 'i' || part[2] == 'I') && (part[3] == 't' || part[3] == 'T'))) return 0;
        if (!end) return 1;
        part = end + 1;
    }
    return 0;
}

/* Open every parent from the held root. An alias on a case-insensitive volume
 * never satisfies the literal component check. */
static int open_source_parent(int root_fd, const char *relative_path, const struct stat *root,
                              struct stat *parent_identity) {
    int parent = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (parent < 0) return -1;
    const char *part = relative_path, *end;
    while ((end = strchr(part, '/')) != NULL) {
        size_t size = (size_t)(end - part);
        char component[NAME_MAX + 1];
        memcpy(component, part, size); component[size] = '\0';
        if (literal_child_present(parent, component) != 1) { close(parent); return -1; }
        int next = openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat observed;
        if (next < 0 || fstat(next, &observed) < 0 || !S_ISDIR(observed.st_mode) ||
            observed.st_uid != root->st_uid || observed.st_dev != root->st_dev) {
            if (next >= 0) close(next);
            close(parent); return -1;
        }
        close(parent);
        parent = next;
        part = end + 1;
    }
    if (fstat(parent, parent_identity) < 0) { close(parent); return -1; }
    return parent;
}

static int source_parent_stable(source_file *file) {
    if (!lock_is_held(file->lock)) return 0;
    int reopened = open_literal_root(file->workspace_path);
    struct stat named_root, current_root, current_parent;
    int root_valid = reopened >= 0 && fstat(reopened, &named_root) == 0 &&
        fstat(file->root_fd, &current_root) == 0 &&
        same_file_observation(&file->root, &named_root) &&
        same_file_observation(&file->root, &current_root);
    if (reopened >= 0) close(reopened);
    if (!root_valid) return 0;
    int parent = open_source_parent(file->root_fd, file->relative_path, &file->root, &current_parent);
    int parent_valid = parent >= 0 && fstat(file->parent_fd, &named_root) == 0 &&
        same_file_observation(&file->parent, &current_parent) &&
        same_file_observation(&file->parent, &named_root);
    if (parent >= 0) close(parent);
    return parent_valid;
}

static int source_file_stable(source_file *file, int require_complete) {
    if (file->file_fd < 0 || (require_complete && file->consumed != file->file.st_size) ||
        !source_parent_stable(file)) return 0;
    struct stat current_file, named_file;
    const char *leaf = strrchr(file->relative_path, '/');
    leaf = leaf ? leaf + 1 : file->relative_path;
    return literal_child_present(file->parent_fd, leaf) == 1 &&
        fstat(file->file_fd, &current_file) == 0 &&
        fstatat(file->parent_fd, leaf, &named_file, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_file_observation(&file->file, &current_file) &&
        same_file_observation(&file->file, &named_file) &&
        lock_is_held(file->lock);
}

static napi_value source_file_close(napi_env env, napi_callback_info info) {
    source_file *file = unwrap_source_file(env, info);
    if (!file) return NULL;
    close_source_file(file);
    if (file->lock_ref) {
        napi_delete_reference(env, file->lock_ref);
        file->lock_ref = NULL;
        file->lock = NULL;
    }
    napi_value result;
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}

static napi_value source_file_read_chunk(napi_env env, napi_callback_info info) {
    source_file *file = unwrap_source_file(env, info);
    if (!file) return NULL;
    size_t argc = 1;
    napi_value argv[1];
    double requested;
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_double(env, argv[0], &requested) != napi_ok ||
        requested < 1 || requested > 1024 * 1024 || requested != (double)(uint32_t)requested ||
        !source_file_stable(file, 0)) return native_error(env, "workspace source file changed or read request is invalid");
    size_t size = (size_t)requested;
    if ((off_t)size > file->file.st_size - file->consumed) size = (size_t)(file->file.st_size - file->consumed);
    char *bytes = malloc(size ? size : 1);
    if (!bytes) return native_error(env, "workspace source read allocation failed");
    ssize_t count;
    do { count = read(file->file_fd, bytes, size); } while (count < 0 && errno == EINTR);
    if (count < 0 || (size > 0 && count == 0)) { free(bytes); return native_error(env, "workspace source file changed during read"); }
    file->consumed += count;
    napi_value result;
    napi_status status = napi_create_buffer_copy(env, (size_t)count, bytes, NULL, &result);
    free(bytes);
    return status == napi_ok ? result : NULL;
}

static napi_value source_file_assert_stable(napi_env env, napi_callback_info info) {
    source_file *file = unwrap_source_file(env, info);
    if (!file) return NULL;
    if (!source_file_stable(file, 1)) return native_error(env, "workspace source file is incomplete or changed");
    napi_value result;
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}

static napi_value open_workspace_file(napi_env env, napi_callback_info info, int git_index) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    napi_value self, argv[7], result, value;
    size_t argc = git_index ? 7 : 5, workspace_length, relative_length = 0;
    unsigned long long device, inode, git_device = 0, git_inode = 0;
    uint32_t owner, git_owner = 0;
    source_file *file = NULL;
    const char *error = git_index ? "workspace Git index input is invalid" : "workspace source file input is invalid";
    if (!lock_is_held(lock) || napi_get_cb_info(env, info, &argc, argv, &self, NULL) != napi_ok ||
        argc != (size_t)(git_index ? 7 : 5) ||
        napi_get_value_string_utf8(env, argv[0], NULL, 0, &workspace_length) != napi_ok ||
        workspace_length < 2 || workspace_length >= PATH_MAX) goto done;
    if (git_index) {
        if (!read_unsigned_id(env, argv[1], &device) || !read_unsigned_id(env, argv[2], &inode) ||
            napi_get_value_uint32(env, argv[3], &owner) != napi_ok || owner != geteuid() ||
            !read_unsigned_id(env, argv[4], &git_device) || !read_unsigned_id(env, argv[5], &git_inode) ||
            napi_get_value_uint32(env, argv[6], &git_owner) != napi_ok || git_owner != owner) goto done;
        relative_length = strlen(".git/index");
    } else if (napi_get_value_string_utf8(env, argv[1], NULL, 0, &relative_length) != napi_ok ||
               relative_length == 0 || relative_length >= PATH_MAX ||
               !read_unsigned_id(env, argv[2], &device) || !read_unsigned_id(env, argv[3], &inode) ||
               napi_get_value_uint32(env, argv[4], &owner) != napi_ok || owner != geteuid()) goto done;
    file = calloc(1, sizeof(*file));
    if (!file) goto done;
    file->root_fd = file->parent_fd = file->file_fd = -1;
    file->lock = lock;
    file->workspace_path = malloc(workspace_length + 1);
    file->relative_path = malloc(relative_length + 1);
    if (!file->workspace_path || !file->relative_path ||
        napi_get_value_string_utf8(env, argv[0], file->workspace_path, workspace_length + 1, &workspace_length) != napi_ok ||
        strlen(file->workspace_path) != workspace_length) goto done;
    if (git_index) {
        memcpy(file->relative_path, ".git/index", relative_length + 1);
    } else if (napi_get_value_string_utf8(env, argv[1], file->relative_path, relative_length + 1, &relative_length) != napi_ok ||
               strlen(file->relative_path) != relative_length ||
               !valid_source_relative_path(file->relative_path)) goto done;
    error = "workspace source root or file is unsafe or changed";
    file->root_fd = open_literal_root(file->workspace_path);
    if (file->root_fd < 0 || fstat(file->root_fd, &file->root) < 0) goto done;
#ifdef __APPLE__
    /* Workspace identity exposes Darwin's unsigned 32-bit dev_t spelling. */
    const unsigned long long root_device = (uint32_t)file->root.st_dev;
#else
    const unsigned long long root_device = file->root.st_dev;
#endif
    if (!S_ISDIR(file->root.st_mode) || file->root.st_uid != owner || root_device != device ||
        (unsigned long long)file->root.st_ino != inode) goto done;
    file->parent_fd = open_source_parent(file->root_fd, file->relative_path, &file->root, &file->parent);
    if (file->parent_fd < 0) goto done;
    if (git_index) {
#ifdef __APPLE__
        const unsigned long long observed_git_device = (uint32_t)file->parent.st_dev;
#else
        const unsigned long long observed_git_device = file->parent.st_dev;
#endif
        if (observed_git_device != git_device || (unsigned long long)file->parent.st_ino != git_inode ||
            file->parent.st_uid != git_owner) goto done;
    }
    const char *leaf = strrchr(file->relative_path, '/');
    leaf = leaf ? leaf + 1 : file->relative_path;
    int literal_leaf = literal_child_present(file->parent_fd, leaf);
    if (git_index && literal_leaf == 0) {
        struct stat absent;
        if (fstatat(file->parent_fd, leaf, &absent, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT ||
            !source_parent_stable(file) || literal_child_present(file->parent_fd, leaf) != 0 ||
            fstatat(file->parent_fd, leaf, &absent, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT ||
            napi_get_null(env, &result) != napi_ok) goto done;
        error = NULL;
        goto done;
    }
    if (literal_leaf != 1) goto done;
    file->file_fd = openat(file->parent_fd, leaf, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (file->file_fd < 0 || fstat(file->file_fd, &file->file) < 0 || !S_ISREG(file->file.st_mode) ||
        file->file.st_uid != owner || file->file.st_dev != file->root.st_dev ||
        (git_index && file->file.st_nlink != 1) ||
        file->file.st_size < 0 || file->file.st_size > 9007199254740991LL ||
        !source_file_stable(file, 0)) goto done;
    if (napi_create_reference(env, self, 1, &file->lock_ref) != napi_ok) goto done;
    /* The reference keeps the native StateOwner allocation alive after this
     * call; every later source read independently checks the live lock. */
    if (napi_create_object(env, &result) != napi_ok ||
        napi_create_double(env, (double)file->file.st_size, &value) != napi_ok ||
        napi_set_named_property(env, result, "size", value) != napi_ok ||
        napi_create_uint32(env, file->file.st_mode & 07777, &value) != napi_ok ||
        napi_set_named_property(env, result, "mode", value) != napi_ok ||
        identity_member(env, result, "identity", &file->file) == 0) goto done;
    const napi_property_descriptor methods[] = {
        {"readChunk", NULL, source_file_read_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"assertStable", NULL, source_file_assert_stable, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, source_file_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_wrap(env, result, file, finalize_source_file, NULL, NULL) != napi_ok) goto done;
    if (napi_type_tag_object(env, result, &source_file_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_object_freeze(env, result) != napi_ok) return native_error(env, "workspace source handle initialization failed");
    return result;
done:
    if (file) finalize_source_file(env, file, NULL);
    return error ? native_error(env, error) : result;
}

static napi_value open_workspace_source_file(napi_env env, napi_callback_info info) {
    return open_workspace_file(env, info, 0);
}

static napi_value open_workspace_git_index(napi_env env, napi_callback_info info) {
    return open_workspace_file(env, info, 1);
}

static int open_source_directory(int root_fd, const char *relative_path, const struct stat *root,
                                 struct stat *directory_identity) {
    int directory = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (directory < 0) return -1;
    const char *part = relative_path;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t size = end ? (size_t)(end - part) : strlen(part);
        char component[NAME_MAX + 1];
        memcpy(component, part, size); component[size] = '\0';
        if (literal_child_present(directory, component) != 1) { close(directory); return -1; }
        int next = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat observed;
        if (next < 0 || fstat(next, &observed) < 0 || !S_ISDIR(observed.st_mode) ||
            observed.st_uid != root->st_uid || observed.st_dev != root->st_dev) {
            if (next >= 0) close(next);
            close(directory); return -1;
        }
        close(directory);
        directory = next;
        part = end ? end + 1 : part + size;
    }
    if (fstat(directory, directory_identity) < 0) { close(directory); return -1; }
    return directory;
}

/* N-API may replace malformed UTF-8. Only a byte-identical round trip can
 * become an authoritative canonical source path component. */
static int source_entry_name(napi_env env, const char *raw, napi_value *value) {
    size_t size = strlen(raw), roundtrip_size;
    char roundtrip[NAME_MAX + 1];
    if (size == 0 || size > NAME_MAX ||
        napi_create_string_utf8(env, raw, size, value) != napi_ok ||
        napi_get_value_string_utf8(env, *value, NULL, 0, &roundtrip_size) != napi_ok ||
        roundtrip_size != size ||
        napi_get_value_string_utf8(env, *value, roundtrip, sizeof(roundtrip), &roundtrip_size) != napi_ok ||
        roundtrip_size != size) return 0;
    return memcmp(raw, roundtrip, size) == 0;
}

static napi_value list_workspace_source_directory(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    napi_value argv[5], result = NULL;
    size_t argc = 5, workspace_length, relative_length;
    unsigned long long device, inode;
    uint32_t owner;
    int root_fd = -1, directory_fd = -1, scan_fd = -1, reopened = -1;
    DIR *stream = NULL;
    char *workspace_path = NULL, *relative_path = NULL;
    struct stat root, directory_before, directory_after, named;
    const char *error = "workspace source directory input is invalid";
    if (!lock_is_held(lock) || napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 5 ||
        napi_get_value_string_utf8(env, argv[0], NULL, 0, &workspace_length) != napi_ok ||
        workspace_length < 2 || workspace_length >= PATH_MAX ||
        napi_get_value_string_utf8(env, argv[1], NULL, 0, &relative_length) != napi_ok ||
        relative_length >= PATH_MAX || !read_unsigned_id(env, argv[2], &device) ||
        !read_unsigned_id(env, argv[3], &inode) ||
        napi_get_value_uint32(env, argv[4], &owner) != napi_ok || owner != geteuid()) goto done;
    workspace_path = malloc(workspace_length + 1);
    relative_path = malloc(relative_length + 1);
    if (!workspace_path || !relative_path ||
        napi_get_value_string_utf8(env, argv[0], workspace_path, workspace_length + 1, &workspace_length) != napi_ok ||
        napi_get_value_string_utf8(env, argv[1], relative_path, relative_length + 1, &relative_length) != napi_ok ||
        strlen(workspace_path) != workspace_length || strlen(relative_path) != relative_length ||
        (*relative_path && !valid_source_relative_path(relative_path))) goto done;
    error = "workspace source directory is unsafe or changed";
    root_fd = open_literal_root(workspace_path);
    if (root_fd < 0 || fstat(root_fd, &root) < 0) goto done;
#ifdef __APPLE__
    const unsigned long long root_device = (uint32_t)root.st_dev;
#else
    const unsigned long long root_device = root.st_dev;
#endif
    if (!S_ISDIR(root.st_mode) || root.st_uid != owner || root_device != device ||
        (unsigned long long)root.st_ino != inode) goto done;
    directory_fd = open_source_directory(root_fd, relative_path, &root, &directory_before);
    if (directory_fd < 0) goto done;
    scan_fd = openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scan_fd < 0 || !(stream = fdopendir(scan_fd))) goto done;
    scan_fd = -1;
    if (napi_create_array(env, &result) != napi_ok) goto done;
    uint32_t count = 0;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) { errno = 0; continue; }
        if (count >= 100000) goto done;
        napi_value name, item, kind, mode, size;
        if (!source_entry_name(env, entry->d_name, &name) ||
            fstatat(directory_fd, entry->d_name, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
            named.st_uid != root.st_uid || named.st_dev != root.st_dev ||
            !(S_ISDIR(named.st_mode) || S_ISREG(named.st_mode) || S_ISLNK(named.st_mode)) ||
            napi_create_object(env, &item) != napi_ok ||
            napi_set_named_property(env, item, "name", name) != napi_ok ||
            napi_create_string_utf8(env, S_ISDIR(named.st_mode) ? "directory" :
                S_ISREG(named.st_mode) ? "file" : "symlink", NAPI_AUTO_LENGTH, &kind) != napi_ok ||
            napi_set_named_property(env, item, "kind", kind) != napi_ok ||
            napi_create_uint32(env, named.st_mode & 07777, &mode) != napi_ok ||
            napi_set_named_property(env, item, "mode", mode) != napi_ok ||
            identity_member(env, item, "identity", &named) == 0) goto done;
        if (S_ISREG(named.st_mode)) {
            if (named.st_size < 0 || named.st_size > 9007199254740991LL ||
                napi_create_double(env, (double)named.st_size, &size) != napi_ok ||
                napi_set_named_property(env, item, "size", size) != napi_ok) goto done;
        }
        if (napi_object_freeze(env, item) != napi_ok ||
            napi_set_element(env, result, count++, item) != napi_ok) goto done;
        errno = 0;
    }
    if (errno != 0) goto done;
    closedir(stream); stream = NULL;
    if (fstat(directory_fd, &directory_after) < 0 ||
        !same_file_observation(&directory_before, &directory_after)) goto done;
    reopened = open_source_directory(root_fd, relative_path, &root, &named);
    if (reopened < 0 || !same_file_observation(&directory_before, &named)) goto done;
    close(reopened); reopened = -1;
    reopened = open_literal_root(workspace_path);
    if (reopened < 0 || fstat(reopened, &named) < 0 ||
        !same_file_observation(&root, &named) || !lock_is_held(lock) ||
        napi_object_freeze(env, result) != napi_ok) goto done;
    error = NULL;
done:
    if (stream) closedir(stream);
    if (scan_fd >= 0) close(scan_fd);
    if (reopened >= 0) close(reopened);
    if (directory_fd >= 0) close(directory_fd);
    if (root_fd >= 0) close(root_fd);
    free(workspace_path);
    free(relative_path);
    return error ? native_error(env, error) : result;
}

static napi_value read_workspace_source_symlink(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    napi_value argv[5], result = NULL, target_value, mode;
    size_t argc = 5, workspace_length, relative_length, roundtrip_length;
    unsigned long long device, inode;
    uint32_t owner;
    int root_fd = -1, parent_fd = -1, reopened = -1;
    char *workspace_path = NULL, *relative_path = NULL;
    char target[PATH_MAX + 1], roundtrip[PATH_MAX + 1];
    struct stat root, parent, link_before, link_after, named;
    const char *error = "workspace source symlink input is invalid";
    if (!lock_is_held(lock) || napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 5 ||
        napi_get_value_string_utf8(env, argv[0], NULL, 0, &workspace_length) != napi_ok ||
        workspace_length < 2 || workspace_length >= PATH_MAX ||
        napi_get_value_string_utf8(env, argv[1], NULL, 0, &relative_length) != napi_ok ||
        relative_length == 0 || relative_length >= PATH_MAX ||
        !read_unsigned_id(env, argv[2], &device) || !read_unsigned_id(env, argv[3], &inode) ||
        napi_get_value_uint32(env, argv[4], &owner) != napi_ok || owner != geteuid()) goto done;
    workspace_path = malloc(workspace_length + 1);
    relative_path = malloc(relative_length + 1);
    if (!workspace_path || !relative_path ||
        napi_get_value_string_utf8(env, argv[0], workspace_path, workspace_length + 1, &workspace_length) != napi_ok ||
        napi_get_value_string_utf8(env, argv[1], relative_path, relative_length + 1, &relative_length) != napi_ok ||
        strlen(workspace_path) != workspace_length || strlen(relative_path) != relative_length ||
        !valid_source_relative_path(relative_path)) goto done;
    error = "workspace source symlink is unsafe or changed";
    root_fd = open_literal_root(workspace_path);
    if (root_fd < 0 || fstat(root_fd, &root) < 0) goto done;
#ifdef __APPLE__
    const unsigned long long root_device = (uint32_t)root.st_dev;
#else
    const unsigned long long root_device = root.st_dev;
#endif
    if (!S_ISDIR(root.st_mode) || root.st_uid != owner || root_device != device ||
        (unsigned long long)root.st_ino != inode) goto done;
    parent_fd = open_source_parent(root_fd, relative_path, &root, &parent);
    if (parent_fd < 0) goto done;
    const char *leaf = strrchr(relative_path, '/');
    leaf = leaf ? leaf + 1 : relative_path;
    if (literal_child_present(parent_fd, leaf) != 1 ||
        fstatat(parent_fd, leaf, &link_before, AT_SYMLINK_NOFOLLOW) < 0 ||
        !S_ISLNK(link_before.st_mode) || link_before.st_uid != owner ||
        link_before.st_dev != root.st_dev || link_before.st_nlink != 1) goto done;
    ssize_t count = readlinkat(parent_fd, leaf, target, PATH_MAX);
    if (count <= 0 || count >= PATH_MAX) goto done;
    target[count] = '\0';
    if (strlen(target) != (size_t)count ||
        napi_create_string_utf8(env, target, (size_t)count, &target_value) != napi_ok ||
        napi_get_value_string_utf8(env, target_value, NULL, 0, &roundtrip_length) != napi_ok ||
        roundtrip_length != (size_t)count ||
        napi_get_value_string_utf8(env, target_value, roundtrip, sizeof(roundtrip), &roundtrip_length) != napi_ok ||
        roundtrip_length != (size_t)count || memcmp(target, roundtrip, (size_t)count) != 0 ||
        fstatat(parent_fd, leaf, &link_after, AT_SYMLINK_NOFOLLOW) < 0 ||
        !same_file_observation(&link_before, &link_after) ||
        fstat(parent_fd, &named) < 0 || !same_file_observation(&parent, &named)) goto done;
    reopened = open_source_parent(root_fd, relative_path, &root, &named);
    if (reopened < 0 || !same_file_observation(&parent, &named)) goto done;
    close(reopened); reopened = -1;
    reopened = open_literal_root(workspace_path);
    if (reopened < 0 || fstat(reopened, &named) < 0 ||
        !same_file_observation(&root, &named) || !lock_is_held(lock) ||
        napi_create_object(env, &result) != napi_ok ||
        napi_set_named_property(env, result, "target", target_value) != napi_ok ||
        napi_create_uint32(env, link_before.st_mode & 07777, &mode) != napi_ok ||
        napi_set_named_property(env, result, "mode", mode) != napi_ok ||
        !identity_member(env, result, "identity", &link_before) ||
        napi_object_freeze(env, result) != napi_ok) goto done;
    error = NULL;
done:
    if (reopened >= 0) close(reopened);
    if (parent_fd >= 0) close(parent_fd);
    if (root_fd >= 0) close(root_fd);
    free(workspace_path);
    free(relative_path);
    return error ? native_error(env, error) : result;
}

/* 1 = observed identity, 0 = positively absent, -1 = unavailable/invalid.
 * Permission failures and hidden procfs entries are never death evidence. */
static int observe_process(pid_t pid, char token[128]) {
#ifdef __APPLE__
    struct proc_bsdinfo process;
    memset(&process, 0, sizeof(process));
    errno = 0;
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &process, sizeof(process));
    if (size == 0 && errno == ESRCH) return 0;
    if (size != sizeof(process) || process.pbi_pid != (uint32_t)pid ||
        process.pbi_start_tvsec == 0 || process.pbi_start_tvusec >= 1000000) {
        return -1;
    }
    snprintf(token, 128, "darwin-proc-start-time:%llu:%06llu",
             (unsigned long long)process.pbi_start_tvsec, (unsigned long long)process.pbi_start_tvusec);
#elif defined(__linux__)
    char stat[4096], path[64];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        /* hidepid can also produce ENOENT. Require a separate kernel PID
         * absence observation; no signal is sent and EPERM is indeterminate. */
        return (errno == ENOENT || errno == ESRCH) && kill(pid, 0) < 0 && errno == ESRCH ? 0 : -1;
    }
    struct statfs filesystem;
    if (fstatfs(fd, &filesystem) < 0 || filesystem.f_type != PROC_SUPER_MAGIC) { close(fd); return -1; }
    FILE *file = fdopen(fd, "r");
    if (file == NULL) { close(fd); return -1; }
    size_t size = fread(stat, 1, sizeof(stat) - 1, file);
    int failed = ferror(file);
    fclose(file);
    if (failed || size == 0 || size == sizeof(stat) - 1) return -1;
    stat[size] = '\0';
    char *pid_end;
    errno = 0;
    long observed_pid = strtol(stat, &pid_end, 10);
    if (errno != 0 || observed_pid != pid || pid_end[0] != ' ' || pid_end[1] != '(') return -1;
    char *field = strrchr(stat, ')');
    if (field == NULL || field[1] != ' ') return -1;
    field += 2;
    for (int index = 3; index < 22; index++) {
        field = strchr(field, ' ');
        if (field == NULL) return -1;
        field++;
    }
    if (*field < '0' || *field > '9') return -1;
    char *end;
    errno = 0;
    unsigned long long ticks = strtoull(field, &end, 10);
    if (errno != 0 || *end != ' ' || ticks == 0) return -1;
    snprintf(token, 128, "linux-proc-start-ticks:%llu", ticks);
#else
#error StateOwner supports only macOS and Linux
#endif
    return 1;
}

static napi_value process_start_token(napi_env env, napi_callback_info info) {
    (void)info;
    char token[128];
    if (observe_process(getpid(), token) != 1) return native_error(env, "cannot observe the current process start token");
    napi_value result;
    if (napi_create_string_utf8(env, token, NAPI_AUTO_LENGTH, &result) != napi_ok) return NULL;
    return result;
}

static napi_value assert_prior_process_dead(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    if (!lock_is_held(lock)) return native_error(env, "StateOwner root/runtime/lock descriptor identity changed or closed");
    size_t argc = 2, length;
    napi_value argv[2];
    double number;
    char prior[128], observed[128];
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 2 ||
        napi_get_value_double(env, argv[0], &number) != napi_ok || !(number >= 1 && number <= INT_MAX) || number != (pid_t)number ||
        napi_get_value_string_utf8(env, argv[1], NULL, 0, &length) != napi_ok || length == 0 || length >= sizeof(prior) ||
        napi_get_value_string_utf8(env, argv[1], prior, sizeof(prior), &length) != napi_ok || strlen(prior) != length) {
        return native_error(env, "invalid prior StateOwner process identity");
    }
    /* Only the helper's exact canonical token syntax is comparable. Unknown
     * versions or arbitrary strings cannot be treated as a positive mismatch. */
    unsigned long long first, second;
    int end = 0;
#ifdef __APPLE__
    if (sscanf(prior, "darwin-proc-start-time:%llu:%llu%n", &first, &second, &end) != 2 ||
        first == 0 || second >= 1000000 || (size_t)end != length) return native_error(env, "invalid prior StateOwner process start token");
    snprintf(observed, sizeof(observed), "darwin-proc-start-time:%llu:%06llu", first, second);
#else
    (void)second;
    if (sscanf(prior, "linux-proc-start-ticks:%llu%n", &first, &end) != 1 ||
        first == 0 || (size_t)end != length) return native_error(env, "invalid prior StateOwner process start token");
    snprintf(observed, sizeof(observed), "linux-proc-start-ticks:%llu", first);
#endif
    if (strcmp(prior, observed) != 0) return native_error(env, "invalid prior StateOwner process start token");
    int status = observe_process((pid_t)number, observed);
    if (status < 0) return native_error(env, "prior StateOwner process observation is unavailable");
    if (status == 1 && strcmp(prior, observed) == 0) return native_error(env, "prior StateOwner process is still present");
    if (!lock_is_held(lock)) return native_error(env, "StateOwner root/runtime/lock descriptor identity changed or closed");
    napi_value result;
    if (napi_get_undefined(env, &result) != napi_ok) return NULL;
    return result;
}

static napi_value initialize(napi_env env, napi_value exports) {
    const napi_property_descriptor methods[] = {
        {"acquireLock", NULL, acquire_lock, NULL, NULL, NULL, napi_default, NULL},
        {"processStartToken", NULL, process_start_token, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok) return NULL;
    return exports;
}

NAPI_MODULE(cliq_state_owner, initialize)
